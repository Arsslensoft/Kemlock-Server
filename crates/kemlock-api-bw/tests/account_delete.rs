//! `DELETE /api/accounts` and `POST /api/accounts/delete`, as Vaultwarden's `delete_account` answers
//! them: the master password hash (or a one-time code) in, the account and what hangs on it gone, a
//! refusal for the last owner of an organization that still has members.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_app::ports::UserRepo;
use kemlock_domain::UserId;
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";

async fn gone(h: &Harness, user: UserId) -> bool {
    UserRepo::by_id(&h.store, user)
        .await
        .expect("the store")
        .is_none()
}

#[tokio::test]
async fn the_password_deletes_the_account_and_its_token_stops_working() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in(EMAIL).await;

    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(gone(&h, user).await, "the account is erased");
    let (status, _) = h
        .json("GET", "/api/accounts/profile", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the token is dead");
}

#[tokio::test]
async fn the_post_form_works_and_a_wrong_or_missing_proof_deletes_nothing() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in(EMAIL).await;

    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/delete",
            Some(&token),
            Some(json!({"masterPasswordHash": "not the hash"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");

    let (status, body) = h
        .json("POST", "/api/accounts/delete", Some(&token), Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "No validation provided");
    assert!(!gone(&h, user).await, "nothing was deleted");

    let (status, body) = h
        .json(
            "POST",
            "/api/accounts/delete",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(gone(&h, user).await);
}

#[tokio::test]
async fn the_personal_api_key_dies_with_the_account() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in(EMAIL).await;
    let (status, key) = h
        .json(
            "POST",
            "/api/accounts/api-key",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    let secret = key["apiKey"].as_str().expect("a key").to_owned();
    let client_id = format!("user.{user}");
    let fields = [
        ("grant_type", "client_credentials"),
        ("scope", "api"),
        ("client_id", client_id.as_str()),
        ("client_secret", secret.as_str()),
        ("deviceType", "8"),
        ("deviceIdentifier", "00000000-0000-4000-8000-000000000002"),
        ("deviceName", "cli"),
    ];
    let (status, _) = h.token(&fields).await;
    assert_eq!(status, StatusCode::OK, "the key signs in first");

    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = h.token(&fields).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "Invalid client_id");
}

/// The owner of an organization with a confirmed member, and that member.
async fn shared_organization(h: &Harness) -> ((String, UserId), (String, UserId), String) {
    let (ada, ada_id) = h.signed_in(EMAIL).await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(&ada),
            Some(json!({
                "name": "Shared",
                "billingEmail": EMAIL,
                "key": "4.orgkeywrappedbythemember",
                "collectionName": "2.collection",
                "keys": {"publicKey": "pub", "encryptedPrivateKey": "2.priv"},
                "planType": 0,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let org = org["id"].as_str().expect("an id").to_owned();
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(json!({"emails": ["bob@example.com"], "type": 2, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    ((ada, ada_id), (bob, bob_id), org)
}

#[tokio::test]
async fn the_last_owner_of_an_organization_with_members_is_refused() {
    let h = Harness::new().await;
    let ((ada, ada_id), (bob, bob_id), _org) = shared_organization(&h).await;

    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&ada),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Can't delete last owner");
    assert!(!gone(&h, ada_id).await, "nothing was touched");

    // A member may leave the world; the organization and the owner stay.
    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&bob),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(gone(&h, bob_id).await);
    let (status, sync): (_, Value) = h.json("GET", "/api/sync", Some(&ada), None).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(
        sync["profile"]["organizations"].as_array().map(Vec::len),
        Some(1),
        "the owner still has the organization"
    );
}

#[tokio::test]
async fn the_deletion_is_at_once_whatever_grace_period_the_settings_give() {
    use kemlock_app::privacy::PrivacySettings;
    let h = Harness::new().await;
    let mut retention = PrivacySettings::retention(&h.store).await.expect("the settings");
    retention.deleted_account_grace_days = 7;
    PrivacySettings::save_retention(&h.store, &retention)
        .await
        .expect("saved");
    let (token, user) = h.signed_in(EMAIL).await;

    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(gone(&h, user).await, "erased now, not scheduled");
}

#[tokio::test]
async fn the_last_owner_is_refused_even_when_no_one_else_is_in_the_organization() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in(EMAIL).await;
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(&ada),
            Some(json!({
                "name": "Alone",
                "billingEmail": EMAIL,
                "key": "4.orgkeywrappedbythemember",
                "collectionName": "2.collection",
                "keys": {"publicKey": "pub", "encryptedPrivateKey": "2.priv"},
                "planType": 0,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");

    let (status, body) = h
        .json(
            "DELETE",
            "/api/accounts",
            Some(&ada),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Can't delete last owner");
    assert!(!gone(&h, ada_id).await, "nothing was touched");
}
