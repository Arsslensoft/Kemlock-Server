//! `POST /api/accounts/kdf`, which Bitwarden clients from 2026.10 call at sign-in to move a weak
//! PBKDF2 account to 600,000 rounds, in the shapes and messages of Vaultwarden.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";
const NEW_HASH: &str = "n3wAuthenticationHashOfTheSamePasswordUnder600k=";
const NEW_KEY: &str = "2.bmV3|d3JhcHBlZA==|bWFj";

fn change(password: &str, auth_salt: &str, auth_rounds: i32, unlock_rounds: i32) -> Value {
    json!({
        "masterPasswordHash": password,
        "authenticationData": {
            "salt": auth_salt,
            "kdf": { "kdfType": 0, "iterations": auth_rounds },
            "masterPasswordAuthenticationHash": NEW_HASH,
        },
        "unlockData": {
            "salt": EMAIL,
            "kdf": { "kdfType": 0, "iterations": unlock_rounds },
            "masterKeyWrappedUserKey": NEW_KEY,
        },
    })
}

async fn refresh(h: &Harness, token: &str) -> StatusCode {
    h.token(&[
        ("grant_type", "refresh_token"),
        ("client_id", "mobile"),
        ("refresh_token", token),
    ])
    .await
    .0
}

#[tokio::test]
async fn the_kdf_moves_to_the_new_settings_and_only_the_calling_device_stays_signed_in() {
    let h = Harness::new().await;
    let (cli, _) = h.signed_in(EMAIL).await;
    let cli_refresh = h.login(EMAIL, HASH).await["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();
    let mut phone = Harness::password_fields(EMAIL, HASH);
    phone.retain(|(k, _)| *k != "deviceIdentifier");
    phone.push(("deviceIdentifier", "1f0e2d3c-4b5a-4968-8776-655443322110"));
    let (status, body) = h.token(&phone).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let phone_refresh = body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/kdf",
            Some(&cli),
            Some(change(HASH, EMAIL, 600_000, 600_000)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The new settings, key and password hash.
    let (_, prelogin) = h
        .json(
            "POST",
            "/identity/accounts/prelogin",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(prelogin["kdf"], 0);
    assert_eq!(prelogin["kdfIterations"], 600_000);
    let (status, synced) = h.json("GET", "/api/sync", Some(&cli), None).await;
    assert_eq!(status, StatusCode::OK, "the calling app keeps its session");
    assert_eq!(synced["profile"]["key"], NEW_KEY);
    let (status, _) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the old hash no longer signs in"
    );
    h.login(EMAIL, NEW_HASH).await;

    // The calling device refreshes; every other one signs in again.
    assert_eq!(refresh(&h, &cli_refresh).await, StatusCode::OK);
    assert_eq!(refresh(&h, &phone_refresh).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_wrong_password_salt_or_mismatched_kdf_is_refused_with_vaultwardens_messages() {
    let h = Harness::new().await;
    let (cli, _) = h.signed_in(EMAIL).await;
    for (body, message) in [
        (
            change("not the hash", EMAIL, 600_000, 600_000),
            "Invalid password",
        ),
        (
            change(HASH, EMAIL, 600_000, 700_000),
            "KDF settings must be equal for authentication and unlock",
        ),
        (
            change(HASH, "someone@example.com", 600_000, 600_000),
            "Invalid master password salt",
        ),
        (
            change(HASH, EMAIL, 50_000, 50_000),
            "PBKDF2 KDF iterations must be at least 100000.",
        ),
    ] {
        let (status, answer) = h
            .json("POST", "/api/accounts/kdf", Some(&cli), Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert!(answer.to_string().contains(message), "{message}: {answer}");
    }
    // Nothing changed.
    h.login(EMAIL, HASH).await;
}

#[tokio::test]
async fn an_unlock_for_another_user_key_is_refused() {
    let h = Harness::new().await;
    let (cli, _) = h.signed_in(EMAIL).await;
    let (status, _) = h
        .json(
            "POST",
            "/api/accounts/key-management/user-key-id",
            Some(&cli),
            Some(json!({ "userKeyId": "0123456789abcdef0123456789abcdef" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let mut body = change(HASH, EMAIL, 600_000, 600_000);
    body["unlockData"]["containedKeyId"] = json!("fedcba9876543210fedcba9876543210");
    let (status, answer) = h
        .json("POST", "/api/accounts/kdf", Some(&cli), Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(
        answer
            .to_string()
            .contains("Invalid user key sent in master-password unlock data."),
        "{answer}"
    );
}
