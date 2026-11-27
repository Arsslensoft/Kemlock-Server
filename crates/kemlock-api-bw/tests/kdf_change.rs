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

/// The CLI that changes the KDF and a phone signed in beside it, each with its tokens.
struct Devices {
    cli: String,
    cli_refresh: String,
    phone: String,
    phone_refresh: String,
}

async fn two_devices(h: &Harness) -> Devices {
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
    let text = |key: &str| body[key].as_str().expect(key).to_owned();
    Devices {
        cli,
        cli_refresh,
        phone: text("access_token"),
        phone_refresh: text("refresh_token"),
    }
}

/// Changes the KDF from the CLI to PBKDF2 at `rounds`, then checks what holds either way: the new
/// settings, key and password hash, and the calling device's session and security stamp.
async fn change_from_cli(h: &Harness, d: &Devices, rounds: i32) {
    let (_, before) = h.json("GET", "/api/sync", Some(&d.cli), None).await;
    h.events.take();
    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/kdf",
            Some(&d.cli),
            Some(change(HASH, EMAIL, rounds, rounds)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, prelogin) = h
        .json(
            "POST",
            "/identity/accounts/prelogin",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(prelogin["kdf"], 0);
    assert_eq!(prelogin["kdfIterations"], rounds);
    // The calling app keeps its session, and the security stamp stays: a Bitwarden client signs
    // itself out when the stamp of a sync is not the one it had.
    let (status, synced) = h.json("GET", "/api/sync", Some(&d.cli), None).await;
    assert_eq!(status, StatusCode::OK, "the calling app keeps its session");
    assert_eq!(synced["profile"]["key"], NEW_KEY);
    assert_eq!(
        synced["profile"]["securityStamp"],
        before["profile"]["securityStamp"]
    );
    let (status, _) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the old hash no longer signs in"
    );
    assert_eq!(refresh(h, &d.cli_refresh).await, StatusCode::OK);
}

fn told_to_sign_out(h: &Harness) -> bool {
    h.events
        .take()
        .iter()
        .any(|e| matches!(e, kemlock_app::bw_events::BwEvent::LogOut { .. }))
}

#[tokio::test]
async fn a_kdf_change_ends_every_other_devices_session_at_once() {
    let h = Harness::new().await;
    let d = two_devices(&h).await;
    change_from_cli(&h, &d, 700_000).await;

    // The phone's access token is refused at once, its live connections are told to sign out,
    // and it can't refresh: it signs in again with the password.
    assert!(told_to_sign_out(&h));
    let (status, _) = h.json("GET", "/api/sync", Some(&d.phone), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refresh(&h, &d.phone_refresh).await, StatusCode::BAD_REQUEST);
    h.login(EMAIL, NEW_HASH).await;
}

#[tokio::test]
async fn the_clients_migration_to_600k_rounds_ends_no_session() {
    // The harness's account is PBKDF2 at 1,000 rounds: the CLI moves it to the minimum at sign-in.
    let h = Harness::new().await;
    let d = two_devices(&h).await;
    change_from_cli(&h, &d, 600_000).await;

    // A Kemlock app beside the CLI goes on working, and takes the new key at its next sync.
    assert!(!told_to_sign_out(&h));
    let (status, synced) = h.json("GET", "/api/sync", Some(&d.phone), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(synced["profile"]["key"], NEW_KEY);
    assert_eq!(refresh(&h, &d.phone_refresh).await, StatusCode::OK);
    h.login(EMAIL, NEW_HASH).await;
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

#[tokio::test]
async fn a_kdf_change_leaves_the_account_and_its_stamp_as_they_were() {
    use kemlock_app::ports::UserRepo;
    let h = Harness::new().await;
    let (cli, user) = h.signed_in(EMAIL).await;
    let before = UserRepo::by_id(&h.store, user)
        .await
        .expect("reads")
        .expect("the account");
    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/kdf",
            Some(&cli),
            Some(change(HASH, EMAIL, 600_000, 600_000)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = UserRepo::by_id(&h.store, user)
        .await
        .expect("reads")
        .expect("the account");
    // The stamp stays: a Bitwarden client signs itself out when its sync shows a new one.
    assert_eq!(after, before);
}
