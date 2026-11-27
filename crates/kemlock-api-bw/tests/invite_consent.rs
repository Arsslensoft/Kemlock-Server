//! An invitation to an organization needs the invitee's consent: an account that exists stays
//! invited until it accepts, policies bind only confirmed members, and Require SSO has the
//! prerequisites Bitwarden gives it.

mod common;

use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness};
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
    /// What was mailed, leaving out the new-device notices of the sign-ins: they are not what
    /// these tests are about.
    fn notices(&self) -> Vec<Notice> {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .filter(|n| !matches!(n, Notice::NewDevice(_)))
            .cloned()
            .collect()
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
    // An account made through the Bitwarden API can't sign in to the web vault, so its mail
    // carries the link that accepts by itself.
    let link = match &sent[0] {
        Notice::BwOrgInvite(notice) => {
            assert_eq!(notice.to.as_str(), "bob@example.com");
            assert_eq!(notice.organization, ORG_NAME);
            assert_eq!(notice.inviter.as_deref(), Some("ada@example.com"));
            notice.link.clone()
        }
        other => panic!("an invitation was expected, not {other:?}"),
    };
    assert!(
        link.starts_with(&format!(
            "{DOMAIN}/#/accept-organization/?organizationId={org}&organizationUserId={bob_id}&email=bob%40example.com&organizationName=Evil+organization&token="
        )),
        "{link}"
    );

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

/// The token a link carries.
fn token_of(link: &str) -> String {
    link.rsplit_once("token=")
        .map(|(_, token)| token.to_owned())
        .expect("a link with a token")
}

/// Posts the accept of `member`: with `bearer` signed in as that caller, or with none. The body
/// carries a key for account recovery, as a client does when the organization asks for one.
async fn accept_as(
    h: &Harness,
    bearer: Option<&str>,
    org: &str,
    member: UserId,
    token: &str,
) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/organizations/{org}/users/{member}/accept"),
        bearer,
        Some(json!({"token": token, "resetPasswordKey": "4.thekeyofwhoeversent"})),
    )
    .await
}

/// The accept of `member` with the master password hash in the body: with `bearer` signed in, or
/// with no session. The body also carries a key for account recovery.
async fn accept_hashed(
    h: &Harness,
    bearer: Option<&str>,
    org: &str,
    member: UserId,
    token: &str,
    hash: &str,
) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/organizations/{org}/users/{member}/accept"),
        bearer,
        Some(json!({
            "token": token,
            "resetPasswordKey": "4.thekeyofwhoeversent",
            "masterPasswordHash": hash
        })),
    )
    .await
}

/// Turns the account recovery policy on, with enrolment by itself.
async fn auto_enrol(h: &Harness, owner: &str, org: &str) {
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/8"),
            Some(owner),
            Some(json!({"policy": {"enabled": true, "data": {"autoEnrollEnabled": true}}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The id the organization's member list gives `email`.
async fn member_of(h: &Harness, owner: &str, org: &str, email: &str) -> String {
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
        .and_then(|all| all.iter().find(|m| m["email"] == email))
        .and_then(|m| m["id"].as_str())
        .expect("a member")
        .to_owned()
}

#[tokio::test]
async fn the_mailed_link_accepts_for_the_account_that_signs_in_with_it() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), false).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (cat, cat_id) = h.signed_in("cat@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com").await;
    invite(&h, &ada, &org, "cat@example.com").await;
    let links: Vec<String> = mailbox
        .notices()
        .into_iter()
        .filter_map(|n| match n {
            Notice::BwOrgInvite(n) => Some(n.link),
            _ => None,
        })
        .collect();
    assert_eq!(links.len(), 2);
    let (bob_token, cat_token) = (token_of(&links[0]), token_of(&links[1]));

    // The token alone accepts nothing.
    let (status, _) = accept_as(&h, None, &org, bob_id, &bob_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, Some(0));
    // Nor does another account's session, the inviter's included.
    for other in [&ada, &cat] {
        let (status, body) = accept_as(&h, Some(other), &org, bob_id, &bob_token).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["message"],
            "Invitation was issued to a different account"
        );
    }
    // A token made for someone else does not accept this member.
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &cat_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Invitation was issued to a different account"
    );
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, Some(0));
    // Nor does something that isn't a token.
    let (status, _) = accept_as(&h, Some(&bob), &org, bob_id, "junk").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &bob_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, Some(1));
    // Accepted already: a second call (a client that retries, or sends its recovery key after) is a
    // success and changes nothing.
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &bob_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(status_of(&h, &ada, &org, "bob@example.com").await, Some(1));
    assert_eq!(status_of(&h, &ada, &org, "cat@example.com").await, Some(0));

    // A link runs out in five days.
    h.env.advance(time::Duration::days(6));
    let fresh = h.login("cat@example.com", HASH).await;
    let fresh = fresh["access_token"].as_str().expect("a token").to_owned();
    let (status, _) = accept_as(&h, Some(&fresh), &org, cat_id, &cat_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn with_no_mail_the_inviting_administrator_can_copy_the_link_to_hand_over() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    invite(&h, &ada, &org, "bob@example.com").await;

    let uri = format!("/api/organizations/{org}/users/{bob_id}/invite-link");
    // The invitee is not an administrator and gets nothing.
    let (status, _) = h.json("GET", &uri, Some(&bob), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h.json("GET", &uri, Some(&ada), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "inviteLink");
    let link = body["link"].as_str().expect("a link").to_owned();
    assert!(
        link.starts_with(&format!("{DOMAIN}/#/accept-organization/?")),
        "{link}"
    );
    assert_eq!(body["token"], token_of(&link));

    // The administrator who holds the link can't accept with it; the invitee signs in and does.
    let (status, _) = accept_as(&h, None, &org, bob_id, &token_of(&link)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = accept_as(&h, Some(&ada), &org, bob_id, &token_of(&link)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &token_of(&link)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Once accepted there is no link to hand over.
    let (status, _) = h.json("GET", &uri, Some(&ada), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The audit's N1: an organization owner turns on auto-enrolment, invites the victim, reads the
/// invitation's link and tries to accept for them with no session, confirm them and reset their
/// password. It fails at the accept, and nothing after it works.
#[tokio::test]
async fn an_owner_cannot_accept_for_the_invitee_and_reset_their_password() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (_victim, victim_id) = h.signed_in("victim@example.com").await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "victim@example.com").await;
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{victim_id}/invite-link"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token").to_owned();

    // No Authorization header: refused. With the owner's own session: refused.
    let (status, _) = accept_as(&h, None, &org, victim_id, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = accept_as(&h, Some(&eve), &org, victim_id, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        status_of(&h, &eve, &org, "victim@example.com").await,
        Some(0)
    );

    // So the victim can't be confirmed, and can't be reset, with a key the owner made up.
    let (status, body) = confirm(&h, &eve, &org, victim_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "User in invalid state");
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{victim_id}/recover-account"),
            Some(&eve),
            Some(json!({"resetMasterPassword": true, "resetTwoFactor": true,
                "newMasterPasswordHash": "ATTACKERHASH", "key": "2.attacker|key|mac"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Password reset not or not correctly enrolled"
    );
    // The victim's password still works.
    let (status, body) = h
        .token(&Harness::password_fields("victim@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A session alone stores no key for account recovery, whatever the body sends: only the password
/// proof (below) does, so a session that was stolen or borrowed can not enrol the account.
#[tokio::test]
async fn a_session_alone_stores_no_recovery_key() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    let token = h.invite_token(&org, bob_id, "bob@example.com");
    // A session alone stores no key: it needs the password proof.
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let details = format!("/api/organizations/{org}/users/{bob_id}/reset-password-details");
    let (status, body) = h.json("GET", &details, Some(&eve), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["resetPasswordKey"].is_null(), "{body}");
}

/// With the session and the password proof together the key is stored.
#[tokio::test]
async fn a_signed_in_invitee_with_the_password_proof_stores_the_recovery_key() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    let token = h.invite_token(&org, bob_id, "bob@example.com");
    let (status, body) = accept_hashed(&h, Some(&bob), &org, bob_id, &token, "wrong").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(status_of(&h, &eve, &org, "bob@example.com").await, Some(0));
    let (status, body) = accept_hashed(&h, Some(&bob), &org, bob_id, &token, HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/reset-password-details"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["resetPasswordKey"], "4.thekeyofwhoeversent");
}

/// The verification token of a registration of `email`.
async fn verification_of(h: &Harness, email: &str) -> String {
    let (status, _, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            axum::body::Body::from(json!({"email": email}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_slice::<String>(&bytes).expect("a verification token")
}

async fn register_with(
    h: &Harness,
    email: &str,
    org_invite_token: &str,
) -> (StatusCode, Value) {
    let verification = verification_of(h, email).await;
    h.json(
        "POST",
        "/identity/accounts/register/finish",
        None,
        Some(json!({
            "email": email,
            "masterPasswordHash": HASH,
            "kdf": 0, "kdfIterations": 600_000,
            "userSymmetricKey": common::USER_KEY,
            "emailVerificationToken": verification,
            "orgInviteToken": org_invite_token
        })),
    )
    .await
}

/// An address with no account yet registers with the token of its invitation and is accepted in
/// the same request: the one acceptance that has no session.
#[tokio::test]
async fn an_address_that_registers_with_the_invitation_token_is_accepted_with_it() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "new@example.com").await;
    let pending = member_of(&h, &eve, &org, "new@example.com").await;
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{pending}/invite-link"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token").to_owned();

    // The token of another address does nothing for an address that registers with it.
    let (status, body) = register_with(&h, "other@example.com", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, list) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users"),
            Some(&eve),
            None,
        )
        .await;
    assert!(
        !list["data"]
            .as_array()
            .expect("a list")
            .iter()
            .any(|m| m["email"] == "other@example.com"),
        "{list}"
    );

    let (status, body) = register_with(&h, "new@example.com", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        status_of(&h, &eve, &org, "new@example.com").await,
        Some(1),
        "accepted by the registration that made the account"
    );
    // No recovery key was taken with no session.
    let member = member_of(&h, &eve, &org, "new@example.com").await;
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{member}/reset-password-details"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["resetPasswordKey"].is_null(), "{body}");

    // The client then accepts with the id the invitation had (the pending one, which the account
    // replaced) and the password: success, and now the key is kept.
    let pending_id: UserId = pending.parse().expect("an id");
    let (status, body) = accept_hashed(&h, None, &org, pending_id, &token, HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{member}/reset-password-details"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(body["resetPasswordKey"], "4.thekeyofwhoeversent");
}

/// Require SSO is kept in `space_policy_settings`: the Bitwarden route writes it there, what the
/// Kemlock side writes shows in the Bitwarden policy, and the Bitwarden sign-in follows the table.
#[tokio::test]
async fn require_sso_is_one_setting_for_both_apis() {
    use kemlock_app::spaces::SpaceRepo;

    /// Whether the table says the space requires SSO.
    async fn required(h: &Harness, space: kemlock_domain::SpaceId) -> bool {
        SpaceRepo::require_sso_of(&h.store, &[space])
            .await
            .expect("a read")
            .contains(&space)
    }

    /// The `enabled` the Bitwarden policy of type 4 shows `token`.
    async fn shown(h: &Harness, token: &str, org: &str) -> Value {
        h.json(
            "GET",
            &format!("/api/organizations/{org}/policies/4"),
            Some(token),
            None,
        )
        .await
        .1["enabled"]
            .clone()
    }

    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    let space = kemlock_domain::SpaceId(org.parse().expect("an organization id"));
    h.configure_sso().await;
    invite(&h, &eve, &org, "bob@example.com").await;
    h.accept_in_space(&org, bob_id).await;
    let (status, body) = confirm(&h, &eve, &org, bob_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The Bitwarden route writes the table.
    assert!(!required(&h, space).await);
    assert_eq!(put_policy(&h, &eve, &org, 3, true).await.0, StatusCode::OK);
    assert_eq!(put_policy(&h, &eve, &org, 4, true).await.0, StatusCode::OK);
    assert!(required(&h, space).await);
    let (status, _) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "bound by the Bitwarden route's write"
    );

    // The Kemlock side turns it off: the Bitwarden policy says so, and the member signs in.
    SpaceRepo::set_require_sso(&h.store, space, false)
        .await
        .expect("a write");
    assert_eq!(shown(&h, &eve, &org).await, json!(false));
    let (status, body) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // And on again: bound, and shown, though the Bitwarden policy was never written again.
    SpaceRepo::set_require_sso(&h.store, space, true)
        .await
        .expect("a write");
    assert_eq!(shown(&h, &eve, &org).await, json!(true));
    let (status, _) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A member only the Kemlock side confirmed has not accepted on the Bitwarden side: they stay
/// invited there, an administrator can't confirm them as accepted, and their own acceptance moves
/// them to accepted without taking away what the Kemlock side confirmed.
#[tokio::test]
async fn a_member_the_space_row_confirmed_stays_invited_until_they_accept_here() {
    use kemlock_domain::spaces::MemberState;
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    h.change_row(&org, bob_id, |row| row.state = MemberState::Confirmed)
        .await;

    assert_eq!(
        status_of(&h, &eve, &org, "bob@example.com").await,
        Some(0),
        "invited, not accepted"
    );
    let (status, body) = confirm(&h, &eve, &org, bob_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "User in invalid state");

    // Bob accepts for himself; the Kemlock side's confirmation is still there.
    let token = h.invite_token(&org, bob_id, "bob@example.com");
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(status_of(&h, &eve, &org, "bob@example.com").await, Some(1));
    let space = kemlock_domain::SpaceId(org.parse().expect("an organization id"));
    let state = kemlock_app::spaces::SpaceRepo::load(&h.store, space)
        .await
        .expect("a read")
        .expect("the space");
    let row = state
        .members
        .iter()
        .find(|m| m.user == bob_id)
        .expect("bob's row");
    assert_eq!(row.state, MemberState::Confirmed);
}

/// A space with a chain is confirmed only by a signed `confirm` record, which a Bitwarden client
/// can't make: the Bitwarden confirm route is refused there, so no row is made Confirmed (and
/// Require SSO binds no one) without the chain.
#[tokio::test]
async fn a_bitwarden_confirm_on_a_chained_space_is_refused() {
    use kemlock_app::spaces::{
        AppendOutcome, ChainAppend, ChainHead, SpaceChainRepo, SpaceChanges, StoredRecord,
    };
    let h = Harness::new().await;
    let (eve, eve_id) = h.signed_in("eve@example.com").await;
    let (_bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    h.accept_in_space(&org, bob_id).await;

    // The space has a chain from here (one record is enough to make it one; these tests don't
    // verify it).
    let space = kemlock_domain::SpaceId(org.parse().expect("an organization id"));
    let first = StoredRecord {
        seq: 0,
        link: [1; 32],
        epoch: 1,
        by: eve_id,
        at: 1_780_000_000,
        entry: vec![1; 300],
        signature: vec![1; 3373],
        cosignature: None,
    };
    let outcome = SpaceChainRepo::chain_append(
        &h.store,
        space,
        ChainAppend {
            expected: None,
            records: vec![first.clone()],
            seals: Vec::new(),
            names: Vec::new(),
            changes: SpaceChanges::new(space),
            creating: false,
            held: Vec::new(),
            writes: Vec::new(),
            answers: None,
            state: None,
        },
    )
    .await
    .expect("the append");
    assert_eq!(
        outcome,
        AppendOutcome::Appended(ChainHead {
            seq: 0,
            link: first.link,
            epoch: first.epoch,
        })
    );

    let (status, body) = confirm(&h, &eve, &org, bob_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "This organization's members are confirmed in the Kemlock app, where the confirmation is signed"
    );
    assert_eq!(status_of(&h, &eve, &org, "bob@example.com").await, Some(1));
}

/// The count of wrong passwords an account holds, as the password grant keeps it (the count is
/// read by counting one more try).
async fn password_tries(h: &Harness, user: UserId) -> u32 {
    use kemlock_app::bitwarden::BwTryRepo;
    BwTryRepo::count_try(&h.store, user, "password", h.env.time().unix_timestamp(), 900)
        .await
        .expect("a count")
}

/// An account made through the Bitwarden API has no way into the web vault and the apps have no
/// accept screen, so the link's page asks for the master password: with no session, the hash in
/// the body is the proof. It issues no session, and the key for recovery goes with the proof.
#[tokio::test]
async fn an_invitee_with_no_session_accepts_with_the_master_password() {
    use kemlock_app::ports::DeviceRepo;
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let bob_id = h.account("bob@example.com", HASH).await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    let token = h.invite_token(&org, bob_id, "bob@example.com");

    // No proof at all: refused as unauthenticated.
    let (status, _) = accept_as(&h, None, &org, bob_id, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A wrong hash is a wrong password, the answer of a sign-in.
    let (status, body) = accept_hashed(&h, None, &org, bob_id, &token, "not-the-hash").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "Username or password is incorrect. Try again");
    assert_eq!(status_of(&h, &eve, &org, "bob@example.com").await, Some(0));

    // The right hash accepts, stores the key and issues nothing.
    let (status, body) = accept_hashed(&h, None, &org, bob_id, &token, HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.is_null() || body == json!({}) || body == json!(""),
        "no tokens or session in the answer: {body}"
    );
    assert_eq!(status_of(&h, &eve, &org, "bob@example.com").await, Some(1));
    assert!(DeviceRepo::list(&h.store, bob_id).await.expect("devices").is_empty());
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/reset-password-details"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["resetPasswordKey"], "4.thekeyofwhoeversent");
}

/// Wrong hashes sent to the accept routes count in the account's one password counter, the
/// password grant's, so they add up with its wrong passwords; a token that is junk, or for another
/// member, is refused before any hash is computed or counted; and an unknown address answers as a
/// wrong password does.
#[tokio::test]
async fn a_wrong_hash_at_accept_counts_with_the_password_grant_and_a_junk_token_counts_nothing() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let bob_id = h.account("bob@example.com", HASH).await;
    let org = organization(&h, &eve).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    let token = h.invite_token(&org, bob_id, "bob@example.com");

    // A junk token, and one made for another member: no hash, and no count (see below).
    let (status, _) = accept_hashed(&h, None, &org, bob_id, "junk", "wrong").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let other = h.invite_token(&org, UserId::random(), "bob@example.com");
    let (status, body) = accept_hashed(&h, None, &org, bob_id, &other, "wrong").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "Error accepting the invitation");

    // Two wrong hashes here and one wrong password at the grant: one counter, three tries.
    for _ in 0..2 {
        let (status, _) = accept_hashed(&h, None, &org, bob_id, &token, "wrong").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = h
        .token(&Harness::password_fields("bob@example.com", "wrong"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Counted: the two wrong hashes, the wrong password and this read; the junk tokens add nothing.
    assert_eq!(password_tries(&h, bob_id).await, 4);

    // An address with no account answers as a wrong password does.
    let member = UserId::random();
    let ghost = h.invite_token(&org, member, "ghost@example.com");
    let (status, body) = accept_hashed(&h, None, &org, member, &ghost, "wrong").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "Username or password is incorrect. Try again");
}

/// On a server that verifies sign-ups by mail, the token of an invitation to an organization that
/// names the address was mailed to it, so it proves the address as the verification link does: the
/// registration finishes with it alone, and any other token does not.
#[tokio::test]
async fn on_a_verifying_server_the_organization_invitation_proves_the_address() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail_set(mailbox.clone(), |s| s.signups_verify = true).await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let org = organization(&h, &eve).await;
    invite(&h, &eve, &org, "new@example.com").await;
    let pending = member_of(&h, &eve, &org, "new@example.com").await;
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{pending}/invite-link"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token").to_owned();
    let finish = |email: &'static str, org_token: String| {
        let h = &h;
        async move {
            h.json(
                "POST",
                "/identity/accounts/register/finish",
                None,
                Some(json!({
                    "email": email,
                    "masterPasswordHash": HASH,
                    "kdf": 0, "kdfIterations": 600_000,
                    "userSymmetricKey": common::USER_KEY,
                    "orgInviteToken": org_token
                })),
            )
            .await
        }
    };
    // A token for another address proves nothing for this one.
    let (status, body) = finish("other@example.com", token.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // The one that names the address does.
    let (status, body) = finish("new@example.com", token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(status_of(&h, &eve, &org, "new@example.com").await, Some(1));
}
