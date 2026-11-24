//! The user key id that Bitwarden clients from 2026.10 report once (their key id backfill), in the
//! shapes of Vaultwarden: `POST /api/accounts/key-management/user-key-id` and `userKeyId` in
//! `/api/sync`.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::json;

const ID: &str = "0123456789abcdef0123456789abcdef";
const PATH: &str = "/api/accounts/key-management/user-key-id";

#[tokio::test]
async fn a_client_reports_the_user_key_id_once_and_sync_gives_it_back() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;

    // None yet: sync leaves it out, which is what makes a client report it.
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    let decryption = &synced["userDecryption"];
    assert!(decryption.get("masterPasswordUnlock").is_some(), "{decryption}");
    assert!(decryption.get("userKeyId").is_none(), "{decryption}");
    let (_, before) = h
        .json("GET", "/api/accounts/revision-date", Some(&ada), None)
        .await;

    h.env.advance(time::Duration::minutes(1));
    let (status, body) = h
        .json("POST", PATH, Some(&ada), Some(json!({ "userKeyId": ID })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    assert_eq!(synced["userDecryption"]["userKeyId"], ID);
    let (_, after) = h
        .json("GET", "/api/accounts/revision-date", Some(&ada), None)
        .await;
    assert_ne!(before, after, "the change moves the revision date");

    // Only a rotation would change it afterwards: a second report is refused.
    let (status, body) = h
        .json(
            "POST",
            PATH,
            Some(&ada),
            Some(json!({ "userKeyId": "fedcba9876543210fedcba9876543210" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("User key id is already set."), "{body}");
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    assert_eq!(synced["userDecryption"]["userKeyId"], ID);
}

#[tokio::test]
async fn a_malformed_id_or_no_token_is_refused() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    for bad in [
        json!({ "userKeyId": "0123456789ABCDEF0123456789ABCDEF" }),
        json!({ "userKeyId": "0123456789abcdef" }),
        json!({ "userKeyId": 7 }),
        json!({}),
    ] {
        let (status, body) = h.json("POST", PATH, Some(&ada), Some(bad.clone())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
    }
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    assert!(synced["userDecryption"].get("userKeyId").is_none());

    let (status, _) = h
        .json("POST", PATH, None, Some(json!({ "userKeyId": ID })))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
