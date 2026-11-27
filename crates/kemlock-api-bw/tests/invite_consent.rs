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
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &bob_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "User already accepted the invitation");
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

/// What the invitee sends at accept is theirs to send: with their session, an auto-enrolling
/// organization stores the key, and recovery needs that enrolment.
#[tokio::test]
async fn the_invitee_who_signs_in_to_accept_is_enrolled_for_recovery() {
    let h = Harness::new().await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &eve).await;
    auto_enrol(&h, &eve, &org).await;
    invite(&h, &eve, &org, "bob@example.com").await;
    let token = h.invite_token(&org, bob_id, "bob@example.com");
    let (status, body) = accept_as(&h, Some(&bob), &org, bob_id, &token).await;
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
