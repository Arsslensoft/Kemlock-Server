//! `KEMLOCK_BW_INVITES_AUTO_ACCEPT`: the operator's opt-in to Vaultwarden's mail-off behaviour, an
//! invitation to an existing account with a password counting as accepted at once.

mod common;

use axum::http::StatusCode;
use common::{Harness, USER_KEY};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use serde_json::{Value, json};
use std::sync::Arc;

struct Silent;

impl Outbox for Silent {
    fn deliver(&self, _notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

async fn organization(h: &Harness, owner: &str) -> String {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(json!({
                "name": "Org",
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": "4.orgkey",
                "keys": {"publicKey": "MIIBIjANorganizationpublickey", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    org["id"].as_str().expect("an id").to_owned()
}

async fn member_status(h: &Harness, owner: &str, org: &str, email: &str) -> Value {
    let (_, list) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users"),
            Some(owner),
            None,
        )
        .await;
    list["data"]
        .as_array()
        .and_then(|rows| rows.iter().find(|m| m["email"] == email))
        .map(|m| m["status"].clone())
        .unwrap_or(Value::Null)
}

async fn invite(h: &Harness, owner: &str, org: &str, email: &str) {
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(owner),
            Some(json!({"emails": [email], "type": 2, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn with_the_setting_on_and_no_mail_an_invited_account_is_accepted_at_once() {
    let h = Harness::with(|s| s.bw_invites_auto_accept = true).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com").await;
    assert_eq!(
        member_status(&h, &ada, &org, "bob@example.com").await,
        json!(1)
    );

    // An emergency contact too.
    let (status, body) = h
        .json(
            "POST",
            "/api/emergency-access/invite",
            Some(&ada),
            Some(json!({"email": "bob@example.com", "type": 0, "waitTimeDays": 7})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, trusted) = h
        .json("GET", "/api/emergency-access/trusted", Some(&ada), None)
        .await;
    assert_eq!(trusted["data"][0]["status"], 1);
}

#[tokio::test]
async fn with_the_setting_on_a_server_that_mails_still_waits_for_the_invitee() {
    let h = Harness::with_mail_set(Arc::new(Silent), |s| s.bw_invites_auto_accept = true).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com").await;
    assert_eq!(
        member_status(&h, &ada, &org, "bob@example.com").await,
        json!(0)
    );
}

#[tokio::test]
async fn an_invitation_waiting_for_a_registration_is_adopted_accepted_only_on_request() {
    for (on, expected) in [(false, 0), (true, 1)] {
        let h = Harness::with(|s| s.bw_invites_auto_accept = on).await;
        let (ada, _) = h.signed_in("ada@example.com").await;
        let org = organization(&h, &ada).await;
        invite(&h, &ada, &org, "new@example.com").await;
        let (status, bytes) = {
            let (status, _, bytes) = h
                .send(
                    "POST",
                    "/identity/accounts/register/send-verification-email",
                    &[("content-type", "application/json")],
                    axum::body::Body::from(json!({"email": "new@example.com"}).to_string()),
                )
                .await;
            (status, bytes)
        };
        assert_eq!(status, StatusCode::OK);
        let token = String::from_utf8(bytes).expect("a token");
        let (status, body) = h
            .json(
                "POST",
                "/identity/accounts/register/finish",
                None,
                Some(json!({
                    "email": "new@example.com", "masterPasswordHash": common::HASH,
                    "kdf": 0, "kdfIterations": 600_000, "userSymmetricKey": USER_KEY,
                    "keys": {"encryptedPrivateKey": "2.priv|key|mac", "publicKey": "MIIBIjAN"},
                    "emailVerificationToken": token
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            member_status(&h, &ada, &org, "new@example.com").await,
            json!(expected),
            "setting {on}"
        );
    }
}
