//! An invitation to an organization needs the invitee's consent: an account that exists stays
//! invited until it accepts, policies bind only confirmed members, and Require SSO has the
//! prerequisites Bitwarden gives it.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";
const ORG_NAME: &str = "Evil organization";

/// Keeps what it is asked to mail.
#[derive(Default)]
struct Mailbox(Mutex<Vec<Notice>>);

impl Mailbox {
    fn notices(&self) -> Vec<Notice> {
        self.0.lock().expect("lock").clone()
    }
}

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("lock").push(notice);
        })
    }
}

async fn organization(h: &Harness, owner: &str) -> String {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(json!({
                "name": ORG_NAME,
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": ORG_KEY,
                "keys": {"publicKey": "MIIBIjANorganizationpublickey", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    org["id"].as_str().expect("an id").to_owned()
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

async fn put_policy(
    h: &Harness,
    owner: &str,
    org: &str,
    ptype: i32,
    enabled: bool,
) -> (StatusCode, Value) {
    h.json(
        "PUT",
        &format!("/api/organizations/{org}/policies/{ptype}"),
        Some(owner),
        Some(json!({"policy": {"enabled": enabled, "data": null}})),
    )
    .await
}

async fn confirm(h: &Harness, owner: &str, org: &str, member: UserId) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/organizations/{org}/users/{member}/confirm"),
        Some(owner),
        Some(json!({"key": "junk"})),
    )
    .await
}

async fn status_of(h: &Harness, owner: &str, org: &str, email: &str) -> Option<i64> {
    let (_, list) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users"),
            Some(owner),
            None,
        )
        .await;
    list["data"]
        .as_array()?
        .iter()
        .find(|m| m["email"] == email)
        .and_then(|m| m["status"].as_i64())
}

#[tokio::test]
async fn an_organization_can_not_lock_out_an_account_it_invited() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (_victim, victim_id) = h.signed_in("victim@example.com").await;
    let org = organization(&h, &eve).await;
    h.configure_sso().await;
    assert_eq!(put_policy(&h, &eve, &org, 3, true).await.0, StatusCode::OK);
    assert_eq!(put_policy(&h, &eve, &org, 4, true).await.0, StatusCode::OK);

    invite(&h, &eve, &org, "victim@example.com").await;
    assert_eq!(
        status_of(&h, &eve, &org, "victim@example.com").await,
        Some(0)
    );
    // The invitation is not a membership, so no policy of the organization binds the account.
    let (status, body) = h
        .token(&Harness::password_fields("victim@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // And nobody confirms what the account has not accepted.
    let (status, body) = confirm(&h, &eve, &org, victim_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "User in invalid state");

    // Accepting is the account's own act, from the web vault's spaces.
    h.accept_in_space(&org, victim_id).await;
    assert_eq!(
        status_of(&h, &eve, &org, "victim@example.com").await,
        Some(1)
    );
    let (status, body) = h
        .token(&Harness::password_fields("victim@example.com", HASH))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an accepted member is not bound yet: {body}"
    );

    // Only once confirmed is the member bound by the policy.
    let (status, body) = confirm(&h, &eve, &org, victim_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .token(&Harness::password_fields("victim@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Single sign-on is required for your organization. Sign in with SSO."
    );
}

#[tokio::test]
async fn require_sso_needs_a_provider_and_single_organization() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let org = organization(&h, &ada).await;

    let (status, body) = put_policy(&h, &ada, &org, 4, true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Set up single sign-on on this server before turning on the Require single sign-on authentication policy."
    );

    h.configure_sso().await;
    let (status, body) = put_policy(&h, &ada, &org, 4, true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Turn on the Single organization policy because it is required for the Require single sign-on authentication policy."
    );

    assert_eq!(put_policy(&h, &ada, &org, 3, true).await.0, StatusCode::OK);
    assert_eq!(put_policy(&h, &ada, &org, 4, true).await.0, StatusCode::OK);
    let (status, body) = put_policy(&h, &ada, &org, 3, false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Turn off the Require single sign-on authentication policy because it requires the Single organization policy."
    );
    // Turning Require SSO off, then Single organization, is allowed.
    assert_eq!(put_policy(&h, &ada, &org, 4, false).await.0, StatusCode::OK);
    assert_eq!(put_policy(&h, &ada, &org, 3, false).await.0, StatusCode::OK);
}

#[tokio::test]
async fn an_invitation_is_mailed_again_and_still_waits_for_the_account() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), false).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;

    invite(&h, &ada, &org, "bob@example.com").await;
    let sent = mailbox.notices();
    assert_eq!(sent.len(), 1, "{sent:?}");
    match &sent[0] {
        Notice::Invitation(notice) => {
            assert_eq!(notice.to.as_str(), "bob@example.com");
            assert_eq!(notice.space.as_deref(), Some(ORG_NAME));
            assert_eq!(notice.inviter.as_deref(), Some("ada@example.com"));
            assert_eq!(notice.space_id.map(|s| s.to_string()), Some(org.clone()));
        }
        other => panic!("an invitation was expected, not {other:?}"),
    }

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/reinvite"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(mailbox.notices().len(), 2);
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, Some(0));

    // Once accepted, there is nothing to send again.
    h.accept_in_space(&org, bob_id).await;
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/reinvite"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(mailbox.notices().len(), 2);
}

#[tokio::test]
async fn an_invited_or_accepted_member_may_turn_the_organization_down() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let (cat, cat_id) = h.signed_in("cat@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com").await;
    invite(&h, &ada, &org, "cat@example.com").await;
    h.accept_in_space(&org, cat_id).await;

    for token in [&bob, &cat] {
        let (status, body) = h
            .json(
                "POST",
                &format!("/api/organizations/{org}/leave"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, None);
    assert_eq!(status_of(&h, &ada, &org, "cat@example.com").await, None);
}
