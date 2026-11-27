//! The admin API through its router, in-process: authorisation (a non-admin, an admin without a
//! two-step method and an admin without a step-up token are all refused), step-up, and every
//! screen's routes over fakes.

#[path = "../../kemlock-api-kem/tests/common/mod.rs"]
mod common;
mod fake_admin;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;
mod rig;
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;
#[path = "../../kemlock-app/tests/sso_fakes/mod.rs"]
mod sso_fakes;

use axum::http::StatusCode;
use common::{Req, b64};
use kemlock_app::bitwarden::{Asker, InviteLinkError};
use kemlock_app::ports::Clock;
use kemlock_app::ports::{TwoFactorMethod, TwoFactorRepo};
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{CustomPermissions, Member, MemberState, Space, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use rig::{FakeInviteLinks, Rig, slug};
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

const ADMIN: &str = "root@kemlock.test";

// ---------------------------------------------------------------------------------------------
// Who may call

/// Every route with a body that could change something, as `(method, path, body)`.
fn writes(target: &str) -> Vec<(&'static str, String, Option<Value>)> {
    vec![
        (
            "POST",
            "/admin/v1/invitations".into(),
            Some(json!({"email": "new@example.org"})),
        ),
        (
            "POST",
            format!("/admin/v1/invitations/{}/resend", Uuid::new_v4()),
            None,
        ),
        (
            "DELETE",
            format!("/admin/v1/invitations/{}", Uuid::new_v4()),
            None,
        ),
        ("POST", format!("/admin/v1/users/{target}/sign-out"), None),
        ("POST", format!("/admin/v1/users/{target}/disable"), None),
        ("POST", format!("/admin/v1/users/{target}/enable"), None),
        (
            "POST",
            format!("/admin/v1/users/{target}/cancel-erasure"),
            None,
        ),
        (
            "POST",
            format!("/admin/v1/users/{target}/reset-two-step"),
            None,
        ),
        ("DELETE", format!("/admin/v1/users/{target}"), None),
        (
            "PUT",
            format!("/admin/v1/spaces/{}/owner", Uuid::new_v4()),
            Some(json!({"newOwner": Uuid::new_v4()})),
        ),
        (
            "GET",
            format!(
                "/admin/v1/spaces/{}/members/{target}/invite-link",
                Uuid::new_v4()
            ),
            None,
        ),
        ("GET", "/admin/v1/events.csv".into(), None),
        (
            "PUT",
            "/admin/v1/settings".into(),
            Some(json!({"changes": {"trash_days": "10"}})),
        ),
        (
            "PUT",
            "/admin/v1/sso".into(),
            Some(
                json!({"enabled": false, "displayName": "SSO", "issuer": "https://idp.example.org", "clientId": "kemlock"}),
            ),
        ),
        (
            "POST",
            "/admin/v1/sso/domains".into(),
            Some(json!({"domain": "example.org"})),
        ),
        (
            "POST",
            "/admin/v1/sso/domains/example.org/verify".into(),
            None,
        ),
        ("DELETE", "/admin/v1/sso/domains/example.org".into(), None),
        (
            "POST",
            "/admin/v1/migration/start".into(),
            Some(json!({"from": "/nowhere"})),
        ),
        (
            "POST",
            "/admin/v1/custom-fields".into(),
            Some(json!({"name": "Employee ID", "type": "text", "kinds": "all"})),
        ),
        (
            "PUT",
            format!("/admin/v1/custom-fields/{}", Uuid::new_v4()),
            Some(json!({"name": "Employee ID", "type": "text", "kinds": "all"})),
        ),
        (
            "DELETE",
            format!("/admin/v1/custom-fields/{}", Uuid::new_v4()),
            None,
        ),
        (
            "PUT",
            "/admin/v1/custom-fields/allow-own".into(),
            Some(json!({"allow": false})),
        ),
        ("POST", "/admin/v1/push-relay/enable".into(), None),
        ("POST", "/admin/v1/push-relay/disable".into(), None),
        (
            "POST",
            "/admin/v1/compliance/requests".into(),
            Some(json!({"kind": "access", "requester": "someone@example.org"})),
        ),
        (
            "PATCH",
            format!("/admin/v1/compliance/requests/{}", Uuid::new_v4()),
            Some(json!({"status": "done"})),
        ),
    ]
}

/// Every read.
const READS: &[&str] = &[
    "/admin/v1/me",
    "/admin/v1/overview",
    "/admin/v1/users",
    "/admin/v1/invitations",
    "/admin/v1/spaces",
    "/admin/v1/custom-fields",
    "/admin/v1/events",
    "/admin/v1/settings",
    "/admin/v1/sso",
    "/admin/v1/sso/domains",
    "/admin/v1/migration",
    "/admin/v1/push-relay",
    "/admin/v1/server-address",
    "/admin/v1/compliance/requests",
];

#[tokio::test]
async fn nobody_signed_in_is_asked_to_sign_in() {
    let rig = Rig::new();
    let client = rig.client();
    for uri in READS {
        let reply = client.get(uri).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(reply.content_type(), "application/problem+json", "{uri}");
    }
}

#[tokio::test]
async fn a_non_admin_is_refused_everywhere() {
    let rig = Rig::new();
    let _root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    for uri in READS {
        let reply = sam.get(uri).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(slug(&reply), "forbidden", "{uri}");
    }
    // A write is refused as forbidden too, with or without a step-up token: being an admin is
    // checked first, so a non-admin learns nothing about step-up.
    for (method, path, body) in writes(&sam.id.to_string()) {
        let reply = sam.send(method, &path, body.clone(), None).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(slug(&reply), "forbidden", "{method} {path}");
        let reply = sam.send(method, &path, body, Some("made-up")).await;
        assert_eq!(slug(&reply), "forbidden", "{method} {path}");
    }
    // The step-up routes are for admins too.
    let reply = sam
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": "123456"})),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        rig.admin.actions(),
        Vec::<String>::new(),
        "nothing was recorded"
    );
}

#[tokio::test]
async fn an_admin_without_a_two_step_method_is_an_ordinary_user() {
    let rig = Rig::new();
    let sam = rig.user("sam@kemlock.test").await;
    rig.promote(sam.id);
    for uri in READS {
        let reply = sam.get(uri).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}");
    }
    // Once a method is confirmed, the same token works.
    rig.enrol_totp(sam.id).await;
    assert_eq!(sam.get("/admin/v1/me").await.status, StatusCode::OK);
    // And removing it takes the role away again.
    TwoFactorRepo::remove(&rig.app.store, sam.id, TwoFactorMethod::Totp)
        .await
        .expect("remove");
    assert_eq!(sam.get("/admin/v1/me").await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_admin_without_a_step_up_token_can_read_but_not_write() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let other = rig.user("other@kemlock.test").await;
    for uri in READS {
        let reply = root.get(uri).await;
        assert_eq!(reply.status, StatusCode::OK, "{uri}: {:?}", reply.body);
    }
    for (method, path, body) in writes(&other.id.to_string()) {
        let reply = root.send(method, &path, body.clone(), None).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(slug(&reply), "step-up-required", "{method} {path}");
        assert_eq!(reply.json()["stepUp"], true);
        let reply = root.send(method, &path, body, Some("not-a-token")).await;
        assert_eq!(slug(&reply), "step-up-required", "{method} {path}");
    }
    assert!(
        rig.admin.actions().is_empty(),
        "no refused write was recorded"
    );
}

#[tokio::test]
async fn a_step_up_token_is_for_one_account_one_device_and_a_few_minutes() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let second = rig.admin("second@kemlock.test").await;
    let target = rig.user("target@kemlock.test").await;
    let uri = format!("/admin/v1/users/{}/enable", target.id);

    let token = root.step_up(&rig).await;
    assert_eq!(
        root.write("POST", &uri, None, &token).await.status,
        StatusCode::NO_CONTENT
    );
    // The token works again inside its window.
    assert_eq!(
        root.write("POST", &uri, None, &token).await.status,
        StatusCode::NO_CONTENT
    );

    // Another admin can't use it.
    let reply = second.write("POST", &uri, None, &token).await;
    assert_eq!(slug(&reply), "step-up-required");
    // The same admin on another device can't either.
    let elsewhere = rig.second_device(&root).await;
    let reply = elsewhere.write("POST", &uri, None, &token).await;
    assert_eq!(slug(&reply), "step-up-required");

    // And it ends.
    rig.app.clock.advance(Duration::minutes(6));
    let reply = root.write("POST", &uri, None, &token).await;
    assert_eq!(slug(&reply), "step-up-required");
    let fresh = root.step_up(&rig).await;
    assert_eq!(
        root.write("POST", &uri, None, &fresh).await.status,
        StatusCode::NO_CONTENT
    );
}

// ---------------------------------------------------------------------------------------------
// Step-up

#[tokio::test]
async fn a_totp_code_makes_a_step_up_token_once() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let me = root.get("/admin/v1/me").await;
    assert_eq!(me.json()["userId"], root.id.to_string());
    assert_eq!(me.json()["stepUpTtlSeconds"], 300);

    rig.next_step();
    let code = rig.totp_code();
    let ok = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": code})),
            None,
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert!(ok.json()["token"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(ok.json()["expiresAt"].as_i64().expect("expiry") > rig.app.now());

    // The same step can't be used twice.
    let replay = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": code})),
            None,
        )
        .await;
    assert_eq!(replay.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&replay), "step-up-failed");
}

#[tokio::test]
async fn wrong_totp_codes_are_refused_and_then_slowed_down() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    for _ in 0..4 {
        let reply = root
            .send(
                "POST",
                "/admin/v1/step-up/totp",
                Some(json!({"code": "000000"})),
                None,
            )
            .await;
        assert_eq!(slug(&reply), "step-up-failed");
    }
    // The fifth failure raises the delay; the next try is told to wait, even with a right code.
    let fifth = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": "000000"})),
            None,
        )
        .await;
    assert_eq!(slug(&fifth), "step-up-failed");
    let waiting = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": rig.totp_code()})),
            None,
        )
        .await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(waiting.header("retry-after").is_some());
}

#[tokio::test]
async fn step_up_codes_and_the_second_step_at_sign_in_keep_separate_counts() {
    use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    // Five attempts at the second step of a sign-in, counted in the store as the Kemlock API
    // counts them: the sign-in count is at its limit and waits.
    for _ in 0..5 {
        let reserved =
            SecondStepGuard::reserve_second_step(&rig.app.store, root.id, rig.app.now(), 5, 900)
                .await;
        assert_eq!(reserved, Ok(Reservation::Granted));
    }
    assert!(matches!(
        SecondStepGuard::reserve_second_step(&rig.app.store, root.id, rig.app.now(), 5, 900).await,
        Ok(Reservation::Wait(_))
    ));
    // The step-up has a count of its own: a wrong code is looked at and refused as wrong, not
    // as too many tries.
    let wrong = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": "000000"})),
            None,
        )
        .await;
    assert_eq!(slug(&wrong), "step-up-failed");
    // Four more wrong step-up codes reach its own limit, and the next waits...
    for _ in 0..4 {
        let again = root
            .send(
                "POST",
                "/admin/v1/step-up/totp",
                Some(json!({"code": "000000"})),
                None,
            )
            .await;
        assert_eq!(slug(&again), "step-up-failed");
    }
    let waiting = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": rig.totp_code()})),
            None,
        )
        .await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    // ...while the sign-in count is where it was: a right step-up clears only its own.
    rig.app.clock.advance(Duration::seconds(1));
    rig.next_step();
    let ok = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": rig.totp_code()})),
            None,
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    let step_up =
        SecondStepGuard::reserve_step_up(&rig.app.store, root.id, rig.app.now(), 5, 900).await;
    assert_eq!(step_up, Ok(Reservation::Granted));
    let sign_in =
        SecondStepGuard::reserve_second_step(&rig.app.store, root.id, rig.app.now(), 5, 900).await;
    assert!(matches!(sign_in, Ok(Reservation::Wait(_))), "{sign_in:?}");
}

async fn the_password_check_makes_a_step_up_token() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let issued = root.step_up_with_password(&common::PASSWORD).await;
    assert_eq!(issued.status, StatusCode::OK, "{:?}", issued.json());
    let token = issued.json()["token"].as_str().expect("a token").to_owned();
    let target = rig.user("target@kemlock.test").await;
    let uri = format!("/admin/v1/users/{}/sign-out", target.id);
    assert_eq!(
        root.write("POST", &uri, None, &token).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn a_wrong_password_makes_no_token() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let reply = root.step_up_with_password(&[6u8; 32]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&reply), "step-up-failed");
}

/// What the browser sends after `navigator.credentials.get` for `options`.
fn assertion(options: &Value, credential: &[u8], user: UserId, counter: u32, uv: bool) -> Value {
    let bytes =
        passkey_fakes::assertion_answer(options, credential, Some(user.as_bytes()), counter, uv);
    serde_json::from_slice(&bytes).expect("JSON")
}

/// Asks for the options of a passkey step-up and returns them with the challenge.
async fn passkey_options(person: &rig::Person) -> (Value, Value) {
    let reply = person
        .send("POST", "/admin/v1/step-up/passkey/options", None, None)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let body = reply.json();
    (body["options"].clone(), body["challenge"].clone())
}

#[tokio::test]
async fn a_passkey_assertion_makes_a_step_up_token_the_writes_take() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    rig.passkeys.insert_for_test(root.id, "Work key", b"cred-1");

    let (options, challenge) = passkey_options(&root).await;
    assert_eq!(
        options["kind"], "Passkey",
        "a passkey, so user verification"
    );
    let credential = assertion(&options, b"cred-1", root.id, 1, true);
    let issued = root
        .send(
            "POST",
            "/admin/v1/step-up/passkey/finish",
            Some(json!({"challenge": challenge, "credential": credential})),
            None,
        )
        .await;
    assert_eq!(issued.status, StatusCode::OK, "{:?}", issued.json());
    let token = issued.json()["token"].as_str().expect("a token").to_owned();
    assert!(issued.json()["expiresAt"].as_i64().expect("expiry") > rig.app.now());

    // The token is the same one the other checks make: a write takes it.
    let target = rig.user("target@kemlock.test").await;
    let uri = format!("/admin/v1/users/{}/sign-out", target.id);
    assert_eq!(
        root.write("POST", &uri, None, &token).await.status,
        StatusCode::NO_CONTENT
    );
    // The passkey's use was kept, so the same counter can't be played again.
    assert!(rig.passkeys.of(root.id)[0].last_used_at.is_some());
}

#[tokio::test]
async fn a_passkey_step_up_is_refused_without_a_passkey_or_for_a_non_admin() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let none = root
        .send("POST", "/admin/v1/step-up/passkey/options", None, None)
        .await;
    assert_eq!(none.status, StatusCode::CONFLICT);

    let sam = rig.user("sam@kemlock.test").await;
    rig.passkeys
        .insert_for_test(sam.id, "Sam's key", b"cred-sam");
    let refused = sam
        .send("POST", "/admin/v1/step-up/passkey/options", None, None)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let refused = sam
        .send(
            "POST",
            "/admin/v1/step-up/passkey/finish",
            Some(json!({"challenge": "AAAA", "credential": {}})),
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unverified_or_foreign_assertion_makes_no_token_and_a_challenge_is_good_once() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let other = rig.user("other@kemlock.test").await;
    rig.passkeys.insert_for_test(root.id, "Work key", b"cred-1");
    rig.passkeys.insert_for_test(other.id, "Theirs", b"cred-2");
    let finish = |challenge: &Value, credential: Value| {
        root.send(
            "POST",
            "/admin/v1/step-up/passkey/finish",
            Some(json!({"challenge": challenge, "credential": credential})),
            None,
        )
    };

    // The per-address limit on these routes is per minute: each step below starts a new one.
    let new_minute = || rig.app.clock.advance(Duration::seconds(61));
    new_minute();

    // No user verification.
    let (options, challenge) = passkey_options(&root).await;
    let unverified = finish(
        &challenge,
        assertion(&options, b"cred-1", root.id, 1, false),
    )
    .await;
    assert_eq!(unverified.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&unverified), "step-up-failed");
    // A challenge is spent by a wrong answer too.
    let again = finish(&challenge, assertion(&options, b"cred-1", root.id, 1, true)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);

    new_minute();
    // Another account's passkey.
    let (options, challenge) = passkey_options(&root).await;
    let foreign = finish(&challenge, assertion(&options, b"cred-2", root.id, 1, true)).await;
    assert_eq!(slug(&foreign), "step-up-failed");

    new_minute();
    // A challenge made on one device isn't answered from another device of the same admin.
    let (options, challenge) = passkey_options(&root).await;
    let elsewhere = rig.second_device(&root).await;
    let stolen = elsewhere
        .send(
            "POST",
            "/admin/v1/step-up/passkey/finish",
            Some(json!({
                "challenge": challenge,
                "credential": assertion(&options, b"cred-1", root.id, 1, true)
            })),
            None,
        )
        .await;
    assert_eq!(slug(&stolen), "step-up-failed");

    new_minute();
    // Made-up challenges are bad requests and take no room.
    let junk = finish(&json!("not-a-challenge"), json!({})).await;
    assert_eq!(junk.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_passkey_answers_are_slowed_down_with_the_codes() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    rig.passkeys.insert_for_test(root.id, "Work key", b"cred-1");
    for _ in 0..5 {
        // The per-address limit is per minute; the account's failures are counted for 15.
        rig.app.clock.advance(Duration::seconds(61));
        let (options, challenge) = passkey_options(&root).await;
        let wrong = root
            .send(
                "POST",
                "/admin/v1/step-up/passkey/finish",
                Some(json!({
                    "challenge": challenge,
                    "credential": assertion(&options, b"cred-1", root.id, 1, false)
                })),
                None,
            )
            .await;
        assert_eq!(slug(&wrong), "step-up-failed");
    }
    // The fifth failure raises the delay, which the authenticator-code check shares.
    let waiting = root
        .send(
            "POST",
            "/admin/v1/step-up/totp",
            Some(json!({"code": rig.totp_code()})),
            None,
        )
        .await;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_step_up_login_state_finishes_once_and_only_for_its_admin() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let second = rig.admin("second@kemlock.test").await;
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(&common::PASSWORD).expect("start");
    let started = root
        .send(
            "POST",
            "/admin/v1/step-up/password/start",
            Some(json!({"request": b64(&request)})),
            None,
        )
        .await
        .json();
    let response = common::unb64(started["response"].as_str().expect("response"));
    let (finalization, _, _) =
        kemlock_crypto::opaque::client_login_finish(state, &common::PASSWORD, &response)
            .expect("finish");
    let body = json!({"loginState": started["loginState"], "finalization": b64(&finalization)});

    // Another admin can't finish it.
    let stolen = second
        .send(
            "POST",
            "/admin/v1/step-up/password/finish",
            Some(body.clone()),
            None,
        )
        .await;
    assert_eq!(slug(&stolen), "step-up-failed");
    // The right admin can, once.
    let first = root
        .send(
            "POST",
            "/admin/v1/step-up/password/finish",
            Some(body.clone()),
            None,
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
    let again = root
        .send(
            "POST",
            "/admin/v1/step-up/password/finish",
            Some(body),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------------------------
// Users and invitations

#[tokio::test]
async fn users_are_listed_searched_and_paged() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    rig.user("ada@kemlock.test").await;
    rig.user("bob@kemlock.test").await;

    let all = root.get("/admin/v1/users").await.json();
    assert_eq!(all["total"], 3);
    assert_eq!(all["users"][0]["email"], "ada@kemlock.test");
    let admin_row = all["users"]
        .as_array()
        .expect("users")
        .iter()
        .find(|u| u["email"] == ADMIN)
        .expect("the admin is listed");
    assert_eq!(admin_row["role"], "admin");
    assert_eq!(admin_row["twoStep"], true);
    assert_eq!(admin_row["devices"], 1);

    let found = root.get("/admin/v1/users?search=BOB").await.json();
    assert_eq!(found["total"], 1);
    let page = root.get("/admin/v1/users?limit=1&offset=1").await.json();
    assert_eq!(page["total"], 3);
    assert_eq!(page["users"].as_array().expect("users").len(), 1);
    assert_eq!(page["users"][0]["email"], "bob@kemlock.test");
    assert_eq!(
        root.get("/admin/v1/users?limit=nope").await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_invitation_is_made_mailed_resent_and_revoked() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let made = root
        .write(
            "POST",
            "/admin/v1/invitations",
            Some(json!({"email": " New@Example.org "})),
            &token,
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    let made = made.json();
    assert_eq!(made["invite"]["email"], "new@example.org");
    assert_eq!(made["invite"]["pending"], true);
    assert_eq!(made["mailed"], true);
    let link = made["link"].as_str().expect("a link").to_owned();
    assert!(
        link.starts_with("https://kemlock.test/invite?token="),
        "{link}"
    );
    let mails = rig.mail.sent();
    assert_eq!(
        mails.len(),
        1,
        "the invitation went to the invitee (no other admin exists)"
    );
    assert_eq!(mails[0].to.as_str(), "new@example.org");
    assert!(mails[0].body.contains(&link));
    // The server keeps only a hash of the token.
    let stored = &rig.admin.invites_now()[0];
    let token_text = link.split("token=").nth(1).expect("a token");
    assert!(
        !stored
            .token_hash
            .iter()
            .eq(token_text.as_bytes().iter().take(32))
    );

    // The same address can't be invited twice; an existing account can't be invited at all.
    let again = root
        .write(
            "POST",
            "/admin/v1/invitations",
            Some(json!({"email": "new@example.org"})),
            &token,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(slug(&again), "wrong-state");
    let existing = root
        .write(
            "POST",
            "/admin/v1/invitations",
            Some(json!({"email": ADMIN})),
            &token,
        )
        .await;
    assert_eq!(existing.status, StatusCode::CONFLICT);
    let bad = root
        .write(
            "POST",
            "/admin/v1/invitations",
            Some(json!({"email": "not an email"})),
            &token,
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // Listed, resent with a new link, revoked.
    let listed = root.get("/admin/v1/invitations").await.json();
    assert_eq!(listed.as_array().expect("list").len(), 1);
    let id = made["invite"]["id"].as_str().expect("id").to_owned();
    let resent = root
        .write(
            "POST",
            &format!("/admin/v1/invitations/{id}/resend"),
            None,
            &token,
        )
        .await;
    assert_eq!(resent.status, StatusCode::OK);
    assert_eq!(resent.json()["invite"]["sent"], 2);
    assert_ne!(resent.json()["link"], made["link"], "a new token");
    let revoked = root
        .write(
            "DELETE",
            &format!("/admin/v1/invitations/{id}"),
            None,
            &token,
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert!(
        root.get("/admin/v1/invitations")
            .await
            .json()
            .as_array()
            .expect("list")
            .is_empty()
    );
    let gone = root
        .write(
            "DELETE",
            &format!("/admin/v1/invitations/{id}"),
            None,
            &token,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn without_mail_an_invitation_still_gives_the_link() {
    let rig = Rig::with(false, &[]);
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let made = root
        .write(
            "POST",
            "/admin/v1/invitations",
            Some(json!({"email": "new@example.org"})),
            &token,
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED);
    assert_eq!(made.json()["mailed"], false);
    assert!(
        made.json()["link"]
            .as_str()
            .is_some_and(|l| l.contains("/invite?token="))
    );
    assert!(rig.mail.sent().is_empty());
}

#[tokio::test]
async fn signing_an_account_out_ends_its_session() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    assert_eq!(sam.get("/kem/v1/sync").await.status, StatusCode::OK);
    let token = root.step_up(&rig).await;
    let reply = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/sign-out", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let after = sam.get("/kem/v1/sync").await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "{:?}", after.json());
    // No device keeps the key it could sign back in with (a replica's device-key sign-in).
    let devices = kemlock_app::ports::DeviceRepo::list(&rig.app.store, sam.id)
        .await
        .expect("devices");
    assert!(!devices.is_empty());
    assert!(devices.iter().all(|d| d.dpop_jkt.is_none()));
    assert_eq!(
        root.write(
            "POST",
            &format!("/admin/v1/users/{}/sign-out", Uuid::new_v4()),
            None,
            &token
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn disabling_signs_the_account_out_and_enabling_clears_the_flag() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    let token = root.step_up(&rig).await;

    let disabled = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/disable", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(disabled.status, StatusCode::NO_CONTENT);
    assert_eq!(
        sam.get("/kem/v1/sync").await.status,
        StatusCode::UNAUTHORIZED
    );
    // Every test account is named "Sam", so the search is by the address: one row.
    let listed = root
        .get("/admin/v1/users?search=sam@kemlock.test")
        .await
        .json();
    assert_eq!(listed["total"], 1);
    assert!(listed["users"][0]["disabledAt"].as_i64().is_some());

    // With the right password, a disabled account still gets no session.
    let refused = common::sign_in_reply(&rig.client(), &sam.email, common::test_device()).await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        refused.json()
    );
    assert_eq!(slug(&refused), "account-disabled");

    let enabled = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/enable", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(enabled.status, StatusCode::NO_CONTENT);
    let listed = root
        .get("/admin/v1/users?search=sam@kemlock.test")
        .await
        .json();
    assert_eq!(listed["total"], 1);
    assert!(listed["users"][0]["disabledAt"].is_null());
    let signed = common::sign_in_reply(&rig.client(), &sam.email, common::test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());

    // Not your own account.
    let own = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/disable", root.id),
            None,
            &token,
        )
        .await;
    assert_eq!(own.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn resetting_two_step_removes_the_methods_and_not_your_own() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    rig.enrol_totp(sam.id).await;
    assert_eq!(rig.app.store.two_factor_of(sam.id).len(), 1);
    let token = root.step_up(&rig).await;

    let reply = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/reset-two-step", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(rig.app.store.two_factor_of(sam.id).is_empty());
    let own = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/reset-two-step", root.id),
            None,
            &token,
        )
        .await;
    assert_eq!(own.status, StatusCode::CONFLICT);
    assert_eq!(rig.app.store.two_factor_of(root.id).len(), 1);
}

fn space_with(id: SpaceId, members: &[(UserId, SpaceRole, MemberState)]) -> SpaceChanges {
    let now = time::macros::datetime!(2026-03-01 12:00 UTC);
    SpaceChanges {
        space: Some(Space {
            id,
            name: vec![1; 40],
            key_version: 1,
            keys_pending_since: None,
            created_at: now,
            updated_at: now,
        }),
        members: members
            .iter()
            .map(|(user, role, state)| Member {
                state: *state,
                ..Member::invited(id, *user, *role, CustomPermissions::NONE, *user, now)
            })
            .collect(),
        ..SpaceChanges::new(id)
    }
}

#[tokio::test]
async fn deleting_an_account_has_guards() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let second = rig.admin("second@kemlock.test").await;
    let sam = rig.user("sam@kemlock.test").await;
    let owner = rig.user("owner@kemlock.test").await;
    let space = SpaceId::random();
    SpaceRepo::create(
        &rig.spaces,
        space_with(
            space,
            &[(owner.id, SpaceRole::Owner, MemberState::Confirmed)],
        ),
    )
    .await
    .expect("space");
    rig.admin.track_space(space);
    let token = root.step_up(&rig).await;

    // Not yourself, and not the only owner of a space.
    let own = root
        .write(
            "DELETE",
            &format!("/admin/v1/users/{}", root.id),
            None,
            &token,
        )
        .await;
    assert_eq!(own.status, StatusCode::CONFLICT);
    let sole = root
        .write(
            "DELETE",
            &format!("/admin/v1/users/{}", owner.id),
            None,
            &token,
        )
        .await;
    assert_eq!(sole.status, StatusCode::CONFLICT);
    assert!(rig.admin.erasures().is_empty());

    // An ordinary account goes; so does an admin while another remains.
    let gone = root
        .write(
            "DELETE",
            &format!("/admin/v1/users/{}", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    let admin_gone = root
        .write(
            "DELETE",
            &format!("/admin/v1/users/{}", second.id),
            None,
            &token,
        )
        .await;
    assert_eq!(admin_gone.status, StatusCode::NO_CONTENT);
    // Through privacy's erasure, as the admin who asked: never the narrower repository erase, which
    // leaves Sends, files, the sign-in log and federated copies behind.
    assert_eq!(
        rig.admin.erasures(),
        [(sam.id, root.id), (second.id, root.id)]
    );
    assert!(rig.admin.erased().is_empty());
    let missing = root
        .write(
            "DELETE",
            &format!("/admin/v1/users/{}", Uuid::new_v4()),
            None,
            &token,
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn writes_are_recorded_with_the_admin_and_a_cut_address_and_mailed_to_the_others() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let second = rig.admin("second@kemlock.test").await;
    let sam = rig.user("sam@kemlock.test").await;
    let token = root.step_up(&rig).await;

    let reply = root
        .client
        .send(
            "POST",
            &format!("/admin/v1/users/{}/disable", sam.id),
            Req {
                access_token: Some(root.session.access_token.as_str()),
                headers: vec![("step-up-token", token)],
                peer: Some(std::net::SocketAddr::from(([203, 0, 113, 77], 40_000))),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);

    let events = rig.admin.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "admin.user.disable");
    assert_eq!(events[0].actor, Some(root.id));
    assert_eq!(events[0].actor_email.as_deref(), Some(ADMIN));
    assert_eq!(events[0].target, Some(sam.id.to_string()));
    assert_eq!(
        events[0].ip.as_deref(),
        Some("203.0.113.0/24"),
        "the address is cut when written"
    );

    // The other admin is told; the one who acted is not.
    let mails = rig.mail.sent();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to.as_str(), "second@kemlock.test");
    assert!(mails[0].subject.contains("disabled an account"));
    assert!(mails[0].body.contains(ADMIN));
    assert!(mails[0].body.contains("203.0.113.0/24"));
    assert!(!mails[0].body.contains("203.0.113.77"));
    let _ = second;
}

// ---------------------------------------------------------------------------------------------
// Spaces

#[tokio::test]
async fn spaces_are_listed_with_their_owners() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let ada = rig.user("ada@kemlock.test").await;
    let bob = rig.user("bob@kemlock.test").await;
    let space = SpaceId::random();
    SpaceRepo::create(
        &rig.spaces,
        space_with(
            space,
            &[
                (ada.id, SpaceRole::Owner, MemberState::Confirmed),
                (bob.id, SpaceRole::Member, MemberState::Accepted),
            ],
        ),
    )
    .await
    .expect("space");
    rig.admin.track_space(space);

    let list = root.get("/admin/v1/spaces").await.json();
    assert_eq!(list["total"], 1);
    assert_eq!(list["spaces"][0]["id"], space.to_string());
    assert_eq!(list["spaces"][0]["members"], 2);
    assert_eq!(list["spaces"][0]["confirmed"], 1);
    assert_eq!(list["spaces"][0]["owners"][0]["email"], "ada@kemlock.test");
    let one = root.get(&format!("/admin/v1/spaces/{space}")).await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(
        root.get(&format!("/admin/v1/spaces/{}", Uuid::new_v4()))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        root.get("/admin/v1/spaces/not-a-uuid").await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_space_changes_owner_only_to_a_confirmed_member() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let ada = rig.user("ada@kemlock.test").await;
    let bob = rig.user("bob@kemlock.test").await;
    let cy = rig.user("cy@kemlock.test").await;
    let stranger = rig.user("stranger@kemlock.test").await;
    let space = SpaceId::random();
    SpaceRepo::create(
        &rig.spaces,
        space_with(
            space,
            &[
                (ada.id, SpaceRole::Owner, MemberState::Confirmed),
                (bob.id, SpaceRole::Member, MemberState::Confirmed),
                (cy.id, SpaceRole::Member, MemberState::Accepted),
            ],
        ),
    )
    .await
    .expect("space");
    rig.admin.track_space(space);
    let token = root.step_up(&rig).await;
    let uri = format!("/admin/v1/spaces/{space}/owner");

    // Someone who only accepted can't be made owner: the server can't hand them the space key.
    let unconfirmed = root
        .write(
            "PUT",
            &uri,
            Some(json!({"newOwner": cy.id.to_string()})),
            &token,
        )
        .await;
    assert_eq!(unconfirmed.status, StatusCode::CONFLICT);
    assert!(
        unconfirmed.json()["detail"]
            .as_str()
            .expect("detail")
            .contains("confirmed")
    );
    // Nor someone outside the space.
    let outside = root
        .write(
            "PUT",
            &uri,
            Some(json!({"newOwner": stranger.id.to_string()})),
            &token,
        )
        .await;
    assert_eq!(outside.status, StatusCode::CONFLICT);
    assert!(rig.admin.actions().is_empty());

    // A confirmed member becomes the owner and the previous owner an admin.
    let done = root
        .write(
            "PUT",
            &uri,
            Some(json!({"newOwner": bob.id.to_string()})),
            &token,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.json());
    assert_eq!(done.json()["owners"].as_array().expect("owners").len(), 1);
    assert_eq!(done.json()["owners"][0]["email"], "bob@kemlock.test");
    assert_eq!(
        rig.spaces.member(space, ada.id).expect("member").role,
        SpaceRole::Admin
    );
    assert_eq!(
        rig.spaces.member(space, bob.id).expect("member").role,
        SpaceRole::Owner
    );
    assert_eq!(rig.admin.actions(), ["admin.space.change_owner"]);

    // Already the owner: nothing to do.
    let again = root
        .write(
            "PUT",
            &uri,
            Some(json!({"newOwner": bob.id.to_string()})),
            &token,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    // Adding an owner without demoting the other.
    let added = root
        .write(
            "PUT",
            &uri,
            Some(json!({"newOwner": ada.id.to_string(), "demotePrevious": false})),
            &token,
        )
        .await;
    assert_eq!(added.status, StatusCode::OK);
    assert_eq!(added.json()["owners"].as_array().expect("owners").len(), 2);
}

// ---------------------------------------------------------------------------------------------
// Events

#[tokio::test]
async fn the_event_log_filters_pages_and_exports_csv() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    let token = root.step_up(&rig).await;
    for _ in 0..3 {
        rig.app.clock.advance(Duration::minutes(1));
        let reply = root
            .write(
                "POST",
                &format!("/admin/v1/users/{}/sign-out", sam.id),
                None,
                &token,
            )
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
    }
    rig.app.clock.advance(Duration::minutes(1));
    root.write(
        "POST",
        &format!("/admin/v1/users/{}/enable", sam.id),
        None,
        &token,
    )
    .await;

    let all = root.get("/admin/v1/events").await.json();
    assert_eq!(all["events"].as_array().expect("events").len(), 4);
    assert_eq!(
        all["events"][0]["action"], "admin.user.enable",
        "newest first"
    );
    assert_eq!(all["events"][0]["actorEmail"], ADMIN);
    assert!(all["next"].is_null());

    let signed_out = root
        .get("/admin/v1/events?action=admin.user.sign_out")
        .await
        .json();
    assert_eq!(signed_out["events"].as_array().expect("events").len(), 3);
    let prefix = root
        .get("/admin/v1/events?action=admin.user.*")
        .await
        .json();
    assert_eq!(prefix["events"].as_array().expect("events").len(), 4);
    let by_actor = root
        .get(&format!("/admin/v1/events?actor={}", sam.id))
        .await
        .json();
    assert!(by_actor["events"].as_array().expect("events").is_empty());
    let by_target = root
        .get(&format!("/admin/v1/events?target={}", sam.id))
        .await
        .json();
    assert_eq!(by_target["events"].as_array().expect("events").len(), 4);
    let from = rig.app.now() - 90;
    let recent = root
        .get(&format!("/admin/v1/events?from={from}"))
        .await
        .json();
    assert_eq!(recent["events"].as_array().expect("events").len(), 2);

    // Pages follow the cursor.
    let first = root.get("/admin/v1/events?limit=3").await.json();
    assert_eq!(first["events"].as_array().expect("events").len(), 3);
    let cursor = first["next"].as_str().expect("a next page").to_owned();
    let second = root
        .get(&format!("/admin/v1/events?limit=3&cursor={cursor}"))
        .await
        .json();
    assert_eq!(second["events"].as_array().expect("events").len(), 1);
    assert!(second["next"].is_null());
    assert_eq!(
        root.get("/admin/v1/events?cursor=junk").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        root.get("/admin/v1/events?action=a%25").await.status,
        StatusCode::BAD_REQUEST
    );

    // CSV needs a step-up token, comes as an attachment, and is itself recorded.
    let refused = root.get("/admin/v1/events.csv").await;
    assert_eq!(slug(&refused), "step-up-required");
    let csv = root
        .write(
            "GET",
            "/admin/v1/events.csv?action=admin.user.*",
            None,
            &token,
        )
        .await;
    assert_eq!(csv.status, StatusCode::OK);
    assert!(csv.content_type().starts_with("text/csv"));
    assert!(
        csv.header("content-disposition")
            .expect("a disposition")
            .contains("attachment")
    );
    let text = String::from_utf8(csv.body.clone()).expect("UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "time,actor,actor_email,action,target,device,ip");
    assert_eq!(lines.len(), 5, "a header and four events: {text}");
    assert!(lines[1].contains("admin.user.enable"));
    assert!(
        rig.admin
            .actions()
            .contains(&"admin.events.export".to_owned())
    );
}

#[tokio::test]
async fn addresses_in_the_log_are_cut_even_when_stored_in_full() {
    use kemlock_app::admin::{AdminEvent, AdminEventRepo};
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    rig.admin
        .record_admin_event(AdminEvent {
            actor: Some(root.id),
            device: None,
            action: "imported.sign_in".to_owned(),
            target: None,
            ip: Some("198.51.100.200".to_owned()),
            at: rig.app.clock.now(),
        })
        .await
        .expect("record");
    let listed = root
        .get("/admin/v1/events?action=imported.sign_in")
        .await
        .json();
    assert_eq!(listed["events"][0]["ip"], "198.51.100.0/24");
    let token = root.step_up(&rig).await;
    let csv = root
        .write(
            "GET",
            "/admin/v1/events.csv?action=imported.sign_in",
            None,
            &token,
        )
        .await;
    let text = String::from_utf8(csv.body).expect("UTF-8");
    assert!(text.contains("198.51.100.0/24"));
    assert!(!text.contains("198.51.100.200"));
}

// ---------------------------------------------------------------------------------------------
// Settings

fn setting<'a>(list: &'a Value, key: &str) -> &'a Value {
    list["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|s| s["key"] == key)
        .unwrap_or_else(|| panic!("{key} is a setting"))
}

#[tokio::test]
async fn settings_are_typed_saved_and_reset() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let before = root.get("/admin/v1/settings").await.json();
    let trash = setting(&before, "trash_days");
    assert_eq!(trash["value"], "30");
    assert_eq!(trash["source"], "default");
    assert_eq!(trash["kind"], "int");
    assert_eq!(trash["min"], 1);
    assert_eq!(trash["max"], 365);
    assert_eq!(trash["readOnly"], false);
    assert_eq!(
        setting(&before, "smtp_security")["choices"],
        json!(["starttls", "force_tls", "off"])
    );

    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {
                "trash_days": "45",
                "signups_allowed": "Yes",
                "smtp_host": "mail.example.org",
                "rate_sign_in_per_minute": "20",
                "event_log_days": "400",
                "signups_domains_whitelist": "Example.org, corp.example.com"
            }})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    let after = saved.json();
    assert_eq!(setting(&after, "trash_days")["value"], "45");
    assert_eq!(setting(&after, "trash_days")["source"], "saved");
    assert_eq!(setting(&after, "signups_allowed")["value"], "true");
    assert_eq!(
        setting(&after, "signups_domains_whitelist")["value"],
        "example.org,corp.example.com"
    );
    assert_eq!(
        rig.admin.saved_setting("setting.trash_days").as_deref(),
        Some("45")
    );

    // `null` forgets the saved value.
    let reset = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"trash_days": null}})),
            &token,
        )
        .await
        .json();
    assert_eq!(setting(&reset, "trash_days")["value"], "30");
    assert_eq!(setting(&reset, "trash_days")["source"], "default");
    assert_eq!(rig.admin.saved_setting("setting.trash_days"), None);
    assert_eq!(
        rig.admin.actions(),
        ["admin.settings.update", "admin.settings.update"]
    );
}

#[tokio::test]
async fn the_server_is_told_when_settings_are_saved_and_only_then() {
    use std::sync::atomic::Ordering;
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    assert_eq!(rig.settings_saves.load(Ordering::SeqCst), 0);

    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"trash_days": "45"}})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    assert_eq!(rig.settings_saves.load(Ordering::SeqCst), 1);

    // A refused save, and a read, don't tell it anything.
    let refused = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"trash_days": "0"}})),
            &token,
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    root.get("/admin/v1/settings").await;
    assert_eq!(rig.settings_saves.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn verifying_new_accounts_can_only_be_turned_on_where_mail_can_be_sent() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let refused = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"signups_verify": "true"}})),
            &token,
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );
    assert_eq!(rig.admin.saved_setting("setting.signups_verify"), None);

    // A host alone is not a mail server: the server needs a sender too, and a user name with its
    // password or neither.
    for changes in [
        json!({"signups_verify": "true", "smtp_host": "mail.example.org"}),
        json!({
            "signups_verify": "true", "smtp_host": "mail.example.org",
            "smtp_from": "vault@example.org", "smtp_username": "vault"
        }),
    ] {
        let refused = root
            .write(
                "PUT",
                "/admin/v1/settings",
                Some(json!({"changes": changes})),
                &token,
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.json()
        );
    }
    assert_eq!(rig.admin.saved_setting("setting.signups_verify"), None);

    // With the whole mail server in the same save it is taken, and then it can be changed on its
    // own.
    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {
                "signups_verify": "true",
                "smtp_host": "mail.example.org",
                "smtp_from": "vault@example.org"
            }})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    assert_eq!(
        rig.admin.saved_setting("setting.signups_verify").as_deref(),
        Some("true")
    );
    let off = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"signups_verify": "false"}})),
            &token,
        )
        .await;
    assert_eq!(off.status, StatusCode::OK, "{:?}", off.json());
}


#[tokio::test]
async fn verifying_signups_from_the_environment_shows_as_off_while_no_mail_can_be_sent() {
    let env = [("SIGNUPS_VERIFY", "true")];
    // No mail server: the server holds nobody back, so the console says off.
    let rig = Rig::with(false, &env);
    let root = rig.admin(ADMIN).await;
    let list = root.get("/admin/v1/settings").await.json();
    let verify = setting(&list, "signups_verify");
    assert_eq!(verify["source"], "env");
    assert_eq!(verify["value"], "false");
    // With mail it is as asked.
    let rig = Rig::with(true, &env);
    let root = rig.admin(ADMIN).await;
    let list = root.get("/admin/v1/settings").await.json();
    assert_eq!(setting(&list, "signups_verify")["value"], "true");
}
#[tokio::test]
async fn settings_refuse_what_is_out_of_bounds_all_or_none() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    for (key, value) in [
        ("trash_days", "0"),
        ("trash_days", "366"),
        ("trash_days", "soon"),
        ("event_log_days", "30"),
        ("smtp_port", "70000"),
        ("smtp_security", "ssl3"),
        ("smtp_from", "no at sign"),
        ("signups_allowed", "maybe"),
        ("rate_sign_in_per_minute", "0"),
    ] {
        let reply = root
            .write(
                "PUT",
                "/admin/v1/settings",
                Some(json!({"changes": {key: value}})),
                &token,
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{key}={value}");
    }
    let unknown = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"admin_token": "x"}})),
            &token,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    let empty = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {}})),
            &token,
        )
        .await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    // One bad value stops the whole request.
    let mixed = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"trash_days": "12", "smtp_port": "0"}})),
            &token,
        )
        .await;
    assert_eq!(mixed.status, StatusCode::BAD_REQUEST);
    assert_eq!(rig.admin.saved_setting("setting.trash_days"), None);
    assert!(rig.admin.actions().is_empty());
}

#[tokio::test]
async fn a_setting_the_environment_sets_is_read_only() {
    let rig = Rig::with(
        true,
        &[
            ("SIGNUPS_ALLOWED", "true"),
            ("SMTP_HOST", "smtp.env.example"),
        ],
    );
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let list = root.get("/admin/v1/settings").await.json();
    let signups = setting(&list, "signups_allowed");
    assert_eq!(signups["source"], "env");
    assert_eq!(signups["readOnly"], true);
    assert_eq!(signups["value"], "true");
    assert_eq!(signups["env"], "SIGNUPS_ALLOWED");
    assert_eq!(setting(&list, "smtp_host")["value"], "smtp.env.example");
    assert_eq!(setting(&list, "trash_days")["readOnly"], false);

    let refused = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"signups_allowed": "false", "trash_days": "10"}})),
            &token,
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(slug(&refused), "setting-read-only");
    assert_eq!(refused.json()["setting"], "signups_allowed");
    assert_eq!(
        rig.admin.saved_setting("setting.trash_days"),
        None,
        "nothing was applied"
    );
}

#[tokio::test]
async fn secrets_are_sealed_and_never_shown() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let before = root.get("/admin/v1/settings").await.json();
    assert_eq!(setting(&before, "smtp_password")["secretSet"], false);

    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"smtp_password": "hunter2-hunter2"}})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let text = String::from_utf8(saved.body.clone()).expect("UTF-8");
    assert!(
        !text.contains("hunter2"),
        "the response doesn't echo the secret"
    );
    let shown = setting(&saved.json(), "smtp_password").clone();
    assert_eq!(shown["secretSet"], true);
    assert!(shown["value"].is_null());
    assert_eq!(shown["kind"], "secret");

    let stored = rig
        .admin
        .saved_setting("setting.smtp_password")
        .expect("stored");
    assert!(!stored.contains("hunter2"), "the stored value is sealed");
    let again = root.get("/admin/v1/settings").await;
    assert!(
        !String::from_utf8(again.body)
            .expect("UTF-8")
            .contains("hunter2")
    );
    // The audit trail names the setting, not its value.
    let events = rig.admin.events();
    assert_eq!(events[0].target.as_deref(), Some("smtp_password"));
}

#[tokio::test]
async fn rate_limit_settings_have_sane_caps() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    for (key, ok, too_many) in [
        ("rate_sign_in_per_minute", "100", "101"),
        ("rate_password_failures_per_15_minutes", "30", "31"),
        ("rate_second_step_failures_per_15_minutes", "20", "21"),
        ("rate_second_step_challenges_per_5_minutes", "30", "31"),
        ("rate_register_per_hour", "50", "51"),
    ] {
        for (value, status) in [(ok, StatusCode::OK), (too_many, StatusCode::BAD_REQUEST)] {
            let reply = root
                .write(
                    "PUT",
                    "/admin/v1/settings",
                    Some(json!({"changes": {key: value}})),
                    &token,
                )
                .await;
            assert_eq!(reply.status, status, "{key}={value}: {:?}", reply.json());
        }
    }
}

#[tokio::test]
async fn the_audit_trail_records_what_a_setting_was_and_became_but_never_a_secret() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {
                "trash_days": "45",
                "smtp_password": "hunter2-hunter2",
            }})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    let target = rig.admin.events()[0].target.clone().expect("a target");
    assert!(target.contains("trash_days: 30 -> 45"), "{target}");
    assert!(target.contains("smtp_password"), "{target}");
    assert!(!target.contains("hunter2"), "{target}");

    let reset = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {"trash_days": null}})),
            &token,
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK);
    let target = rig.admin.events().last().and_then(|e| e.target.clone()).expect("a target");
    assert_eq!(target, "trash_days: 45 -> 30");
}

#[tokio::test]
async fn a_new_smtp_host_starts_without_the_saved_smtp_password() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let put = |changes: Value| {
        root.write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({ "changes": changes })),
            &token,
        )
    };
    assert_eq!(
        put(json!({"smtp_host": "mail.example.org", "smtp_password": "hunter2-hunter2"}))
            .await
            .status,
        StatusCode::OK
    );
    assert!(rig.admin.saved_setting("setting.smtp_password").is_some());
    // Another setting of the mail server, or the same host again: the password stays.
    assert_eq!(
        put(json!({"smtp_host": "mail.example.org", "smtp_port": "465"}))
            .await
            .status,
        StatusCode::OK
    );
    assert!(rig.admin.saved_setting("setting.smtp_password").is_some());
    // A new host with a new password keeps the new one.
    assert_eq!(
        put(json!({"smtp_host": "smtp.other.example", "smtp_password": "another-secret-1"}))
            .await
            .status,
        StatusCode::OK
    );
    assert!(rig.admin.saved_setting("setting.smtp_password").is_some());
    // A new host alone drops the password the old one was given.
    assert_eq!(
        put(json!({"smtp_host": "evil.example"})).await.status,
        StatusCode::OK
    );
    assert_eq!(rig.admin.saved_setting("setting.smtp_password"), None);
}

#[tokio::test]
async fn a_new_sso_issuer_starts_without_the_stored_client_secret() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let saved = root
        .write("PUT", "/admin/v1/sso", Some(sso_body()), &token)
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    // The same issuer, the secret left out: kept.
    let mut keep = sso_body();
    keep.as_object_mut().expect("object").remove("clientSecret");
    let kept = root
        .write("PUT", "/admin/v1/sso", Some(keep.clone()), &token)
        .await
        .json();
    assert_eq!(kept["clientSecretSet"], true);
    // Another issuer with the secret left out: the secret does not follow it.
    keep["issuer"] = json!("https://idp.attacker.example/realms/kemlock");
    let moved = root
        .write("PUT", "/admin/v1/sso", Some(keep), &token)
        .await
        .json();
    assert_eq!(moved["clientSecretSet"], false);
}

// ---------------------------------------------------------------------------------------------
// SSO

fn sso_body() -> Value {
    json!({
        "enabled": true,
        "displayName": "Example SSO",
        "issuer": "https://idp.example.org/realms/kemlock",
        "clientId": "kemlock",
        "clientSecret": "s3cret-s3cret",
        "scopes": ["email", "profile", "groups", "openid"],
        "groupRules": [{"group": "eng", "space": Uuid::new_v4(), "role": "admin"}]
    })
}

#[tokio::test]
async fn sso_settings_are_saved_and_the_secret_is_never_returned() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let empty = root.get("/admin/v1/sso").await.json();
    assert_eq!(empty["configured"], false);
    assert_eq!(
        empty["callbackUrl"],
        "https://kemlock.test/kem/v1/auth/sso/callback"
    );

    let saved = root
        .write("PUT", "/admin/v1/sso", Some(sso_body()), &token)
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    let text = String::from_utf8(saved.body.clone()).expect("UTF-8");
    assert!(!text.contains("s3cret"));
    let shown = saved.json();
    assert_eq!(shown["configured"], true);
    assert_eq!(shown["clientSecretSet"], true);
    assert_eq!(
        shown["scopes"],
        json!(["email", "profile", "groups"]),
        "openid is implied"
    );
    assert_eq!(shown["groupRules"][0]["role"], "admin");
    assert_eq!(shown["linkByEmail"], true);

    // The stored secret is sealed: the SSO area can open it, the table doesn't hold it in clear.
    let stored = rig.sso.settings().expect("stored");
    let sealed = stored.sealed_client_secret.clone().expect("a secret");
    assert!(!sealed.windows(6).any(|w| w == b"s3cret"));
    let client = stored.client_config(&rig.app.crypto).expect("opens");
    assert_eq!(client.client_secret.as_deref(), Some("s3cret-s3cret"));

    // Leaving the secret out keeps it; `clearClientSecret` removes it.
    let mut keep = sso_body();
    keep.as_object_mut().expect("object").remove("clientSecret");
    keep["displayName"] = json!("Renamed");
    let kept = root
        .write("PUT", "/admin/v1/sso", Some(keep.clone()), &token)
        .await
        .json();
    assert_eq!(kept["displayName"], "Renamed");
    assert_eq!(kept["clientSecretSet"], true);
    keep["clearClientSecret"] = json!(true);
    let cleared = root
        .write("PUT", "/admin/v1/sso", Some(keep), &token)
        .await
        .json();
    assert_eq!(cleared["clientSecretSet"], false);
    assert_eq!(rig.admin.actions(), ["admin.sso.update"; 3]);
}

#[tokio::test]
async fn sso_settings_are_checked() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    for (field, value) in [
        ("issuer", json!("http://idp.example.org")),
        ("issuer", json!("not a url")),
        ("displayName", json!("")),
        ("clientId", json!("has space")),
        ("scopes", json!(["two words"])),
        (
            "groupRules",
            json!([{"group": "eng", "space": Uuid::new_v4(), "role": "root"}]),
        ),
    ] {
        let mut body = sso_body();
        body[field] = value.clone();
        let reply = root.write("PUT", "/admin/v1/sso", Some(body), &token).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{field}={value}");
    }
    assert!(rig.sso.settings().is_none(), "nothing was stored");
    // A provider on this machine may use http.
    let mut local = sso_body();
    local["issuer"] = json!("http://localhost:8081/realms/dev");
    assert_eq!(
        root.write("PUT", "/admin/v1/sso", Some(local), &token)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sso_domains_are_claimed_proven_by_dns_and_removed() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    let claimed = root
        .write(
            "POST",
            "/admin/v1/sso/domains",
            Some(json!({"domain": "Example.ORG."})),
            &token,
        )
        .await;
    assert_eq!(claimed.status, StatusCode::CREATED, "{:?}", claimed.json());
    let claim = claimed.json();
    assert_eq!(claim["domain"], "example.org");
    assert_eq!(claim["verified"], false);
    let txt = claim["txtValue"].as_str().expect("a record").to_owned();
    assert!(txt.starts_with("kemlock-verification="));
    // Claiming again shows the same record.
    let again = root
        .write(
            "POST",
            "/admin/v1/sso/domains",
            Some(json!({"domain": "example.org"})),
            &token,
        )
        .await;
    assert_eq!(again.json()["txtValue"], txt);

    // Until the record is published the check says so.
    let early = root
        .write(
            "POST",
            "/admin/v1/sso/domains/example.org/verify",
            None,
            &token,
        )
        .await;
    assert_eq!(early.status, StatusCode::CONFLICT);
    rig.dns.publish("example.org", &txt);
    let proven = root
        .write(
            "POST",
            "/admin/v1/sso/domains/example.org/verify",
            None,
            &token,
        )
        .await;
    assert_eq!(proven.status, StatusCode::OK, "{:?}", proven.json());
    assert_eq!(proven.json()["verified"], true);
    let listed = root.get("/admin/v1/sso/domains").await.json();
    assert_eq!(listed[0]["verified"], true);

    assert_eq!(
        root.write(
            "POST",
            "/admin/v1/sso/domains",
            Some(json!({"domain": "nodots"})),
            &token
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let removed = root
        .write("DELETE", "/admin/v1/sso/domains/example.org", None, &token)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert!(
        root.get("/admin/v1/sso/domains")
            .await
            .json()
            .as_array()
            .expect("list")
            .is_empty()
    );
    let gone = root
        .write("DELETE", "/admin/v1/sso/domains/example.org", None, &token)
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Migration

/// Starts a move as an admin with a fresh step-up token.
async fn start_move(root: &rig::Person, token: &str, body: Value) -> common::Reply {
    root.write("POST", "/admin/v1/migration/start", Some(body), token)
        .await
}

#[tokio::test]
async fn a_move_starts_in_the_background_and_its_progress_and_result_are_shown() {
    use kemlock_app::admin::MigrationRequest;

    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let idle = root.get("/admin/v1/migration").await.json();
    assert_eq!(idle["state"], "idle");
    assert_eq!(idle["applies"], true, "a move writes to this server");

    // The start answers at once: 202, with the move running.
    let started = start_move(
        &root,
        &token,
        json!({"from": " /vw/data ", "files": "/vw/files"}),
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{:?}", started.json());
    let started = started.json();
    assert_eq!(started["state"], "running");
    assert_eq!(started["source"], "/vw/data");
    assert_eq!(started["stage"], "starting");
    assert_eq!(started["startedBy"], root.id.to_string());
    assert_eq!(
        rig.migration.requests(),
        [MigrationRequest {
            from: "/vw/data".to_owned(),
            files: Some("/vw/files".to_owned()),
            by: root.id,
        }]
    );

    // While it runs, a GET shows it and a second start is refused.
    assert_eq!(
        root.get("/admin/v1/migration").await.json()["state"],
        "running"
    );
    let again = start_move(&root, &token, json!({"from": "/vw/other"})).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(slug(&again), "wrong-state");
    assert_eq!(rig.migration.requests().len(), 1);

    // The background job reports its stages and then its result.
    let job = rig.migration.record();
    job.progress("writing", Some("12 accounts, 340 items".to_owned()))
        .await
        .expect("progress");
    let shown = root.get("/admin/v1/migration").await.json();
    assert_eq!(shown["state"], "running");
    assert_eq!(shown["stage"], "writing");
    assert_eq!(shown["plan"], "12 accounts, 340 items");
    assert_eq!(shown["finishedAt"], Value::Null);

    job.finished("wrote 12 accounts and 340 items".to_owned())
        .await
        .expect("finished");
    let done = root.get("/admin/v1/migration").await.json();
    assert_eq!(done["state"], "done");
    assert_eq!(done["report"], "wrote 12 accounts and 340 items");
    assert_eq!(done["stage"], Value::Null);
    assert_eq!(done["plan"], "12 accounts, 340 items");
    assert!(done["finishedAt"].as_i64().is_some());
    assert_eq!(done["startedBy"], root.id.to_string());

    // A finished move doesn't stop the next one, and a late stage doesn't revive the old one.
    job.progress("reading", None).await.expect("stale");
    assert_eq!(
        root.get("/admin/v1/migration").await.json()["state"],
        "done"
    );
    let next = start_move(&root, &token, json!({"from": "/vw/other"})).await;
    assert_eq!(next.status, StatusCode::ACCEPTED);
    assert_eq!(rig.migration.requests().len(), 2);
    assert_eq!(
        rig.admin.actions(),
        ["admin.migration.start", "admin.migration.start"],
        "only the starts that were accepted are recorded"
    );
}

#[tokio::test]
async fn a_move_that_fails_shows_why_and_keeps_who_started_it() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let started = start_move(&root, &token, json!({"from": "/definitely/not/there"})).await;
    assert_eq!(started.status, StatusCode::ACCEPTED);

    // The source couldn't be read: that is the background job's failure, not the request's.
    let job = rig.migration.record();
    job.progress("reading", None).await.expect("progress");
    job.failed(
        root.id,
        "/definitely/not/there".to_owned(),
        "can't read /definitely/not/there".to_owned(),
    )
    .await
    .expect("failed");
    let status = root.get("/admin/v1/migration").await.json();
    assert_eq!(status["state"], "failed");
    assert_eq!(status["source"], "/definitely/not/there");
    assert_eq!(status["error"], "can't read /definitely/not/there");
    assert_eq!(status["startedBy"], root.id.to_string());
    assert!(status["finishedAt"].as_i64().is_some());

    // A failed move can be started again.
    let retry = start_move(&root, &token, json!({"from": "/vw/data"})).await;
    assert_eq!(retry.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn a_source_that_cannot_be_one_is_refused_before_anything_starts() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    for body in [
        json!({"from": "a\nb"}),
        json!({"from": "   "}),
        json!({"from": "/vw", "files": "x\ty"}),
        json!({"from": "bad:source"}),
    ] {
        let reply = start_move(&root, &token, body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert!(rig.migration.requests().is_empty());
    assert_eq!(
        root.get("/admin/v1/migration").await.json()["state"],
        "idle"
    );
    assert!(rig.admin.actions().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Compliance and overview

#[tokio::test]
async fn requests_are_queued_with_due_dates_and_extended_once() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let now = rig.app.now();

    let access = root
        .write(
            "POST",
            "/admin/v1/compliance/requests",
            Some(json!({"kind": "access", "requester": "ada@example.org", "note": "by email"})),
            &token,
        )
        .await;
    assert_eq!(access.status, StatusCode::CREATED, "{:?}", access.json());
    let access = access.json();
    assert_eq!(access["dueAt"], now + 45 * 86_400);
    assert_eq!(access["status"], "open");
    assert_eq!(access["overdue"], false);
    let opt_out = root
        .write(
            "POST",
            "/admin/v1/compliance/requests",
            Some(json!({"kind": "opt-out", "requester": "bob@example.org"})),
            &token,
        )
        .await
        .json();
    // 2026-03-01 is a Sunday: 15 business days later is Friday 2026-03-20, 19 days on.
    assert_eq!(opt_out["dueAt"], now + 19 * 86_400);
    // A request that arrived 50 days ago is already past its 45 days.
    let old = root
        .write(
            "POST",
            "/admin/v1/compliance/requests",
            Some(json!({"kind": "erasure", "requester": "cy@example.org", "receivedAt": now - 50 * 86_400})),
            &token,
        )
        .await
        .json();
    assert_eq!(old["dueAt"], now - 5 * 86_400);
    assert_eq!(old["overdue"], true);

    let queue = root.get("/admin/v1/compliance/requests").await.json();
    assert_eq!(queue["requests"][0]["id"], old["id"], "soonest due first");
    assert_eq!(queue["requests"][1]["id"], opt_out["id"]);
    assert_eq!(queue["requests"].as_array().expect("list").len(), 3);
    let overview = root.get("/admin/v1/overview").await.json();
    assert_eq!(overview["openRequests"], 3);
    assert_eq!(overview["overdueRequests"], 1);

    let id = access["id"].as_str().expect("id");
    let uri = format!("/admin/v1/compliance/requests/{id}");
    let extended = root
        .write("PATCH", &uri, Some(json!({"extend": true})), &token)
        .await;
    assert_eq!(extended.status, StatusCode::OK, "{:?}", extended.json());
    assert_eq!(extended.json()["dueAt"], now + 90 * 86_400);
    assert_eq!(extended.json()["extended"], true);
    let twice = root
        .write("PATCH", &uri, Some(json!({"extend": true})), &token)
        .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
    let no_extension = root
        .write(
            "PATCH",
            &format!(
                "/admin/v1/compliance/requests/{}",
                opt_out["id"].as_str().expect("id")
            ),
            Some(json!({"extend": true})),
            &token,
        )
        .await;
    assert_eq!(
        no_extension.status,
        StatusCode::CONFLICT,
        "an opt-out can't be extended"
    );

    // Closing records who and when, and the open queue drops it.
    let closed = root
        .write(
            "PATCH",
            &uri,
            Some(json!({"status": "done", "note": "sent the export"})),
            &token,
        )
        .await
        .json();
    assert_eq!(closed["status"], "done");
    assert_eq!(closed["handledBy"], root.id.to_string());
    assert!(closed["closedAt"].as_i64().is_some());
    assert_eq!(
        root.get("/admin/v1/compliance/requests").await.json()["requests"]
            .as_array()
            .expect("list")
            .len(),
        2
    );
    assert_eq!(
        root.get("/admin/v1/compliance/requests?open=false")
            .await
            .json()["requests"]
            .as_array()
            .expect("list")
            .len(),
        3
    );
    assert_eq!(
        root.write("PATCH", &uri, Some(json!({"status": "stuck"})), &token)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let bad_kind = root
        .write(
            "POST",
            "/admin/v1/compliance/requests",
            Some(json!({"kind": "gossip", "requester": "x"})),
            &token,
        )
        .await;
    assert_eq!(bad_kind.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_overview_counts_what_the_server_holds() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let ada = rig.user("ada@kemlock.test").await;
    rig.user("bob@kemlock.test").await;
    let space = SpaceId::random();
    SpaceRepo::create(
        &rig.spaces,
        space_with(space, &[(ada.id, SpaceRole::Owner, MemberState::Confirmed)]),
    )
    .await
    .expect("space");
    rig.admin.track_space(space);
    let token = root.step_up(&rig).await;
    root.write(
        "POST",
        "/admin/v1/invitations",
        Some(json!({"email": "new@example.org"})),
        &token,
    )
    .await;
    root.write(
        "POST",
        &format!("/admin/v1/users/{}/disable", ada.id),
        None,
        &token,
    )
    .await;

    let overview = root.get("/admin/v1/overview").await.json();
    assert_eq!(overview["users"], 3);
    assert_eq!(overview["admins"], 1);
    assert_eq!(overview["disabledUsers"], 1);
    assert_eq!(overview["spaces"], 1);
    assert_eq!(overview["pendingInvites"], 1);
    assert_eq!(overview["events24h"], 2);
    assert_eq!(overview["mailConfigured"], true);
    assert!(overview["devices"].as_u64().expect("devices") >= 3);
}

#[tokio::test]
async fn old_events_are_dropped_by_the_retention_setting() {
    use kemlock_app::admin::{AdminEvent, AdminEventRepo, EventRetention, Settings};
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let now = rig.app.clock.now();
    for days in [10, 200, 400, 800] {
        rig.admin
            .record_admin_event(AdminEvent {
                actor: Some(root.id),
                device: None,
                action: format!("old.{days}"),
                target: None,
                ip: None,
                at: now - Duration::days(days),
            })
            .await
            .expect("record");
    }
    let retention = EventRetention {
        events: rig.admin.clone(),
        settings: Settings {
            repo: rig.admin.clone(),
            seal: rig.app.crypto.clone(),
            env: kemlock_app::admin::NoEnv,
        },
        clock: rig.app.clock.clone(),
    };
    // A year by default.
    assert_eq!(retention.execute().await.expect("purge"), 2);
    let mut left = rig.admin.actions();
    left.sort();
    assert_eq!(left, ["old.10", "old.200"]);
}

// ---------------------------------------------------------------------------------------------
// The document

#[tokio::test]
async fn the_openapi_document_names_routes_the_router_answers() {
    let rig = Rig::new();
    let client = rig.client();
    let served = client.get("/admin/v1/openapi.json").await;
    assert_eq!(served.status, StatusCode::OK);
    let doc = served.json();
    assert_eq!(
        doc,
        serde_json::to_value(kemlock_api_admin::admin_openapi()).expect("a document")
    );

    let mut operations = 0;
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, _) in item.as_object().expect("operations") {
            operations += 1;
            let uri = path
                .replace("{id}", &Uuid::new_v4().to_string())
                .replace("{user}", &Uuid::new_v4().to_string())
                .replace("{domain}", "example.org");
            let reply = client
                .send(&method.to_uppercase(), &uri, Req::default())
                .await;
            if path == "/admin/v1/openapi.json" {
                assert_eq!(reply.status, StatusCode::OK);
            } else {
                // Not signed in: refused, but the route is there (not 404, not 405).
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
            }
        }
    }
    assert_eq!(operations, 47, "every operation is documented once");
    assert_eq!(
        doc["components"]["securitySchemes"]["dpop"]["type"],
        "apiKey"
    );
}

#[tokio::test]
async fn every_write_in_the_document_asks_for_a_step_up_token() {
    let doc = serde_json::to_value(kemlock_api_admin::admin_openapi()).expect("a document");
    let mut writes_seen = 0;
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("operations") {
            let names: Vec<&str> = operation["parameters"]
                .as_array()
                .map(|p| p.iter().filter_map(|p| p["name"].as_str()).collect())
                .unwrap_or_default();
            let has_step_up = names.contains(&"Step-Up-Token");
            // The invitation link is a read that hands out a secret, so it asks like a write.
            let is_write =
                method != "get" || path.ends_with(".csv") || path.ends_with("/invite-link");
            let is_step_up_route = path.starts_with("/admin/v1/step-up/");
            if is_write && !is_step_up_route {
                writes_seen += 1;
                assert!(has_step_up, "{method} {path} should name Step-Up-Token");
            } else {
                assert!(!has_step_up, "{method} {path} should not");
            }
        }
    }
    assert!(writes_seen >= 19, "{writes_seen}");
}

#[tokio::test]
async fn an_admin_cancels_the_pending_deletion_of_an_account() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    let kim = rig.user("kim@kemlock.test").await;
    rig.admin.schedule_erasure(sam.id);
    let token = root.step_up(&rig).await;

    let listed = root.get("/admin/v1/users").await.json();
    let flag_of = |email: &str| {
        listed["users"]
            .as_array()
            .expect("users")
            .iter()
            .find(|u| u["email"] == email)
            .map(|u| u["erasurePending"].clone())
    };
    assert_eq!(flag_of("sam@kemlock.test"), Some(true.into()));
    assert_eq!(flag_of("kim@kemlock.test"), Some(false.into()));

    let cancelled = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/cancel-erasure", sam.id),
            None,
            &token,
        )
        .await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    assert!(rig.admin.pending_erasures().is_empty());
    assert!(
        rig.admin
            .actions()
            .contains(&"admin.user.cancel_erasure".to_owned()),
        "the cancellation is in the event log"
    );

    // Nothing pending for kim, and no such account: refused, not silently fine.
    let nothing = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/cancel-erasure", kim.id),
            None,
            &token,
        )
        .await;
    assert_eq!(nothing.status, StatusCode::CONFLICT);
    let missing = root
        .write(
            "POST",
            &format!("/admin/v1/users/{}/cancel-erasure", Uuid::new_v4()),
            None,
            &token,
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Kemlock's push relay

/// A relay the console turns on and off, with no network. `unreachable` makes turning it on fail
/// the way an unreachable relay does.
#[derive(Default)]
struct FakeRelay {
    installation: std::sync::Mutex<Option<String>>,
    unreachable: bool,
}

impl FakeRelay {
    fn status(&self) -> kemlock_app::admin::RelayStatus {
        let installation = self.installation.lock().expect("lock").clone();
        kemlock_app::admin::RelayStatus {
            enabled: installation.is_some(),
            installation_id: installation,
            relay_url: "https://push.kemlock.test".to_owned(),
            apns_configured: true,
            apns_sandbox: false,
        }
    }
}

impl kemlock_app::admin::PushRelayControl for FakeRelay {
    fn status(
        &self,
    ) -> kemlock_app::notices::BoxFuture<
        '_,
        Result<kemlock_app::admin::RelayStatus, kemlock_app::admin::AdminError>,
    > {
        Box::pin(async move { Ok(FakeRelay::status(self)) })
    }

    fn enable(
        &self,
    ) -> kemlock_app::notices::BoxFuture<
        '_,
        Result<kemlock_app::admin::RelayStatus, kemlock_app::admin::AdminError>,
    > {
        Box::pin(async move {
            if self.unreachable {
                return Err(kemlock_app::admin::AdminError::State(
                    "the push relay could not be reached; try again later",
                ));
            }
            self.installation
                .lock()
                .expect("lock")
                .get_or_insert_with(|| "inst-1".to_owned());
            Ok(FakeRelay::status(self))
        })
    }

    fn disable(
        &self,
    ) -> kemlock_app::notices::BoxFuture<
        '_,
        Result<kemlock_app::admin::RelayStatus, kemlock_app::admin::AdminError>,
    > {
        Box::pin(async move {
            *self.installation.lock().expect("lock") = None;
            Ok(FakeRelay::status(self))
        })
    }
}

#[tokio::test]
async fn the_push_relay_is_turned_on_and_off_with_a_step_up_and_each_is_logged() {
    let rig = Rig::with_push_relay(std::sync::Arc::new(FakeRelay::default()));
    let root = rig.admin(ADMIN).await;

    let off = root.get("/admin/v1/push-relay").await;
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(off.json()["enabled"], false);
    assert_eq!(off.json()["installationId"], Value::Null);
    assert_eq!(off.json()["relayUrl"], "https://push.kemlock.test");
    // The server's own pushes show beside the relay.
    assert_eq!(off.json()["apnsConfigured"], true);
    assert_eq!(off.json()["apnsSandbox"], false);
    assert_eq!(off.json()["unifiedPush"], true);

    // A write without a step-up token is refused.
    let refused = root
        .send("POST", "/admin/v1/push-relay/enable", None, None)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&refused), "step-up-required");
    assert_eq!(
        root.get("/admin/v1/push-relay").await.json()["enabled"],
        false
    );

    let token = root.step_up(&rig).await;
    let on = root
        .write("POST", "/admin/v1/push-relay/enable", None, &token)
        .await;
    assert_eq!(on.status, StatusCode::OK, "{:?}", on.json());
    assert_eq!(on.json()["enabled"], true);
    assert_eq!(on.json()["installationId"], "inst-1");
    // The key is never in an answer.
    assert!(!on.json().to_string().to_lowercase().contains("key"));
    assert_eq!(
        root.get("/admin/v1/push-relay").await.json()["enabled"],
        true
    );

    let off = root
        .write("POST", "/admin/v1/push-relay/disable", None, &token)
        .await;
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(off.json()["enabled"], false);

    let events = rig.admin.events();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        ["admin.push-relay.enable", "admin.push-relay.disable"]
    );
    assert_eq!(events[0].actor, Some(root.id));
    assert_eq!(events[0].target.as_deref(), Some("inst-1"));
}

#[tokio::test]
async fn a_relay_that_cannot_be_reached_stays_off_and_logs_nothing() {
    let rig = Rig::with_push_relay(std::sync::Arc::new(FakeRelay {
        unreachable: true,
        ..FakeRelay::default()
    }));
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let failed = root
        .write("POST", "/admin/v1/push-relay/enable", None, &token)
        .await;
    assert_eq!(failed.status, StatusCode::CONFLICT);
    assert_eq!(slug(&failed), "wrong-state");
    assert_eq!(
        root.get("/admin/v1/push-relay").await.json()["enabled"],
        false
    );
    assert!(rig.admin.events().is_empty());
}

#[tokio::test]
async fn a_server_with_no_relay_to_control_says_so() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    // Reading answers with the relay off; only turning it on or off needs one to control.
    let read = root.get("/admin/v1/push-relay").await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["enabled"], false);
    assert_eq!(read.json()["apnsConfigured"], false);
    assert_eq!(read.json()["unifiedPush"], true);
    for action in ["enable", "disable"] {
        let reply = root
            .write(
                "POST",
                &format!("/admin/v1/push-relay/{action}"),
                None,
                &token,
            )
            .await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{action}");
    }
}

#[tokio::test]
async fn an_ordinary_account_cannot_see_or_change_the_push_relay() {
    let rig = Rig::with_push_relay(std::sync::Arc::new(FakeRelay::default()));
    let sam = rig.user("sam@example.org").await;
    assert_eq!(
        sam.get("/admin/v1/push-relay").await.status,
        StatusCode::FORBIDDEN
    );
    let reply = sam
        .send(
            "POST",
            "/admin/v1/push-relay/enable",
            None,
            Some("anything"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn turning_the_push_relay_off_clears_the_saved_switch_and_tells_the_server() {
    use kemlock_app::admin::SettingsRepo;
    use std::sync::atomic::Ordering;
    let rig = Rig::with_push_relay(std::sync::Arc::new(FakeRelay::default()));
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    rig.admin
        .put_setting("setting.kemlock_push_relay", "true")
        .await
        .expect("saved");
    let before = root.get("/admin/v1/settings").await.json();
    assert_eq!(setting(&before, "kemlock_push_relay")["value"], "true");
    let saves = rig.settings_saves.load(Ordering::SeqCst);

    let off = root
        .write("POST", "/admin/v1/push-relay/disable", None, &token)
        .await;
    assert_eq!(off.status, StatusCode::OK);
    let after = root.get("/admin/v1/settings").await.json();
    assert_eq!(setting(&after, "kemlock_push_relay")["value"], "false");
    assert_eq!(setting(&after, "kemlock_push_relay")["source"], "default");
    assert_eq!(rig.settings_saves.load(Ordering::SeqCst), saves + 1);
}

#[tokio::test]
async fn the_address_is_shown_with_the_one_recorded_at_setup_and_a_difference_is_flagged() {
    use kemlock_app::admin::SettingsRepo;
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let none = root.get("/admin/v1/server-address").await;
    assert_eq!(none.status, StatusCode::OK);
    assert_eq!(none.json()["recordedDomain"], Value::Null);
    assert_eq!(none.json()["differs"], false);
    let domain = none.json()["domain"].as_str().expect("domain").to_owned();

    // The same address, with a slash and another case, isn't a difference.
    rig.admin
        .put_setting("setup.domain", &format!("{}/", domain.to_uppercase()))
        .await
        .expect("saved");
    assert_eq!(
        root.get("/admin/v1/server-address").await.json()["differs"],
        false
    );

    rig.admin
        .put_setting("setup.domain", "https://old.example.org")
        .await
        .expect("saved");
    let differs = root.get("/admin/v1/server-address").await.json();
    assert_eq!(differs["recordedDomain"], "https://old.example.org");
    assert_eq!(differs["differs"], true);
    assert_eq!(differs["domain"], domain);
}

#[tokio::test]
async fn an_ordinary_account_cannot_read_the_address() {
    let rig = Rig::new();
    let sam = rig.user("sam@example.org").await;
    assert_eq!(
        sam.get("/admin/v1/server-address").await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn the_push_installation_id_and_key_are_never_returned() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let saved = root
        .write(
            "PUT",
            "/admin/v1/settings",
            Some(json!({"changes": {
                "push_installation_id": "id-sekret-1",
                "push_installation_key": "key-sekret-2",
                "push_enabled": "true"
            }})),
            &token,
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.json());
    for body in [saved.json(), root.get("/admin/v1/settings").await.json()] {
        for key in ["push_installation_id", "push_installation_key"] {
            let s = setting(&body, key);
            assert_eq!(s["kind"], "secret");
            assert_eq!(s["secretSet"], true);
            assert_eq!(s["value"], Value::Null);
        }
        let text = body.to_string();
        assert!(!text.contains("sekret"), "{text}");
    }
}

// ---------------------------------------------------------------------------------------------
// Custom fields

fn field_body(name: &str, field_type: &str, kinds: Value) -> Value {
    json!({"name": name, "type": field_type, "kinds": kinds})
}

#[tokio::test]
async fn an_admin_adds_changes_and_removes_custom_fields() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    // Nothing yet, and people may add their own until an admin says no.
    let empty = root.get("/admin/v1/custom-fields").await;
    assert_eq!(empty.status, StatusCode::OK, "{:?}", empty.json());
    assert_eq!(empty.json(), json!({"fields": [], "allowOwn": true}));

    // The answer has the shape clients read: id, name, type, and kinds as "all" or a list.
    let all = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("  Employee   ID ", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(all.status, StatusCode::CREATED, "{:?}", all.json());
    let all_id = all.json()["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        all.json(),
        json!({"id": all_id, "name": "Employee ID", "type": "text", "kinds": "all"})
    );
    let some = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body(
                "Cost center",
                "hidden",
                json!(["card", "login", "card"]),
            )),
            &token,
        )
        .await;
    assert_eq!(some.status, StatusCode::CREATED, "{:?}", some.json());
    let some_id = some.json()["id"].as_str().expect("an id").to_owned();
    assert_eq!(some.json()["kinds"], json!(["login", "card"]));
    assert_eq!(rig.admin.custom_fields_now().len(), 2);

    let listed = root.get("/admin/v1/custom-fields").await.json();
    assert_eq!(listed["allowOwn"], true);
    let names: Vec<&str> = listed["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|f| f["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["Employee ID", "Cost center"]);

    // A change keeps the id.
    let changed = root
        .write(
            "PUT",
            &format!("/admin/v1/custom-fields/{some_id}"),
            Some(field_body("Cost centre", "checkbox", json!(["card"]))),
            &token,
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.json());
    assert_eq!(
        changed.json(),
        json!({"id": some_id, "name": "Cost centre", "type": "checkbox", "kinds": ["card"]})
    );

    // A removed field is gone, and removing it twice is a 404.
    let uri = format!("/admin/v1/custom-fields/{all_id}");
    let removed = root.write("DELETE", &uri, None, &token).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let again = root.write("DELETE", &uri, None, &token).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(rig.admin.custom_fields_now().len(), 1);

    // Every change is in the event log; the refused one is not.
    assert_eq!(
        rig.admin.actions(),
        [
            "admin.custom_field.create",
            "admin.custom_field.create",
            "admin.custom_field.update",
            "admin.custom_field.delete",
        ]
    );
}

#[tokio::test]
async fn a_custom_field_typed_wrongly_is_refused_and_not_recorded() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;

    for (why, body) in [
        ("an empty name", field_body("   ", "text", json!("all"))),
        (
            "a name of 65 characters",
            field_body(&"x".repeat(65), "text", json!("all")),
        ),
        (
            "a control character in the name",
            field_body("a\u{7}b", "text", json!("all")),
        ),
        (
            "a type that isn't one",
            field_body("Pin", "password", json!("all")),
        ),
        ("no kinds", field_body("Pin", "text", json!([]))),
        (
            "a word that isn't all",
            field_body("Pin", "text", json!("everything")),
        ),
        ("a passkey", field_body("Pin", "text", json!(["passkey"]))),
        ("a file", field_body("Pin", "text", json!(["file"]))),
        (
            "a required flag: nothing is ever required",
            json!({"name": "Pin", "type": "text", "kinds": "all", "required": true}),
        ),
    ] {
        let reply = root
            .write("POST", "/admin/v1/custom-fields", Some(body), &token)
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{why}: {:?}",
            reply.json()
        );
    }
    assert!(rig.admin.custom_fields_now().is_empty());
    assert!(rig.admin.actions().is_empty());
}

#[tokio::test]
async fn two_custom_fields_can_not_share_a_name_whatever_the_case() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let first = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("Employee ID", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let second = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("EMPLOYEE id", "hidden", json!(["login"]))),
            &token,
        )
        .await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert!(
        second.json()["detail"]
            .as_str()
            .expect("detail")
            .contains("name")
    );
    let other = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("Cost center", "text", json!("all"))),
            &token,
        )
        .await;
    let other_id = other.json()["id"].as_str().expect("an id").to_owned();
    let uri = format!("/admin/v1/custom-fields/{other_id}");

    // Taking the other's name in a change is the same refusal; keeping one's own is fine.
    let clash = root
        .write(
            "PUT",
            &uri,
            Some(field_body("employee id", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(clash.status, StatusCode::CONFLICT);
    let same = root
        .write(
            "PUT",
            &uri,
            Some(field_body("COST CENTER", "hidden", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(same.status, StatusCode::OK, "{:?}", same.json());
    assert_eq!(rig.admin.custom_fields_now().len(), 2);

    // A field that isn't there can't be changed, and an id that isn't one is a 400.
    let ghost = root
        .write(
            "PUT",
            &format!("/admin/v1/custom-fields/{}", Uuid::new_v4()),
            Some(field_body("Ghost", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(ghost.status, StatusCode::NOT_FOUND);
    let bad_id = root
        .write("DELETE", "/admin/v1/custom-fields/not-a-uuid", None, &token)
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_server_holds_at_most_a_hundred_custom_fields() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    for n in 0..100 {
        let reply = root
            .write(
                "POST",
                "/admin/v1/custom-fields",
                Some(field_body(&format!("Field {n}"), "text", json!("all"))),
                &token,
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{n}: {:?}", reply.json());
    }
    let over = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("One too many", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(over.status, StatusCode::CONFLICT);
    assert_eq!(rig.admin.custom_fields_now().len(), 100);
}

#[tokio::test]
async fn an_admin_turns_people_adding_their_own_fields_off_and_on() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let uri = "/admin/v1/custom-fields/allow-own";

    let off = root
        .write("PUT", uri, Some(json!({"allow": false})), &token)
        .await;
    assert_eq!(off.status, StatusCode::OK, "{:?}", off.json());
    assert_eq!(off.json(), json!({"allowOwn": false}));
    assert_eq!(
        rig.admin.saved_setting("custom_fields.allow_own"),
        Some("false".to_owned())
    );
    assert_eq!(
        root.get("/admin/v1/custom-fields").await.json()["allowOwn"],
        false
    );

    let on = root
        .write("PUT", uri, Some(json!({"allow": true})), &token)
        .await;
    assert_eq!(on.json(), json!({"allowOwn": true}));
    assert_eq!(
        root.get("/admin/v1/custom-fields").await.json()["allowOwn"],
        true
    );

    // Not a flag: refused, and not recorded.
    let bad = root
        .write("PUT", uri, Some(json!({"allow": "no"})), &token)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        rig.admin.actions(),
        [
            "admin.custom_field.allow_own",
            "admin.custom_field.allow_own"
        ]
    );
}

#[tokio::test]
async fn a_custom_field_change_asks_for_a_step_up_and_tells_the_other_admins() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let _second = rig.admin("second@kemlock.test").await;

    let without = root
        .send(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("Employee ID", "text", json!("all"))),
            None,
        )
        .await;
    assert_eq!(without.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&without), "step-up-required");
    assert!(rig.admin.custom_fields_now().is_empty());

    let token = root.step_up(&rig).await;
    let made = root
        .write(
            "POST",
            "/admin/v1/custom-fields",
            Some(field_body("Employee ID", "text", json!("all"))),
            &token,
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED);
    let events = rig.admin.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "admin.custom_field.create");
    assert_eq!(
        events[0].target.as_deref(),
        made.json()["id"].as_str(),
        "the log names the field by its id"
    );
    let mails = rig.mail.sent();
    assert_eq!(mails.len(), 1, "the other admin is told");
    assert_eq!(mails[0].to.as_str(), "second@kemlock.test");
    assert!(mails[0].subject.contains("added a custom field"));
}

#[tokio::test]
async fn the_document_describes_the_custom_fields_routes() {
    let doc = serde_json::to_value(kemlock_api_admin::admin_openapi()).expect("a document");
    for (path, method) in [
        ("/admin/v1/custom-fields", "get"),
        ("/admin/v1/custom-fields", "post"),
        ("/admin/v1/custom-fields/{id}", "put"),
        ("/admin/v1/custom-fields/{id}", "delete"),
        ("/admin/v1/custom-fields/allow-own", "put"),
    ] {
        assert!(
            doc["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
    for schema in [
        "CustomFieldRequest",
        "CustomFieldDto",
        "CustomFieldsDto",
        "KindsDto",
        "AllowOwnRequest",
        "AllowOwnDto",
    ] {
        assert!(
            doc["components"]["schemas"][schema].is_object(),
            "{schema} is in the components"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The accept link of a Bitwarden invitation

fn invite_link_uri(space: SpaceId, member: UserId) -> String {
    format!("/admin/v1/spaces/{space}/members/{member}/invite-link")
}

#[tokio::test]
async fn an_admin_with_a_step_up_copies_an_invitation_link_and_it_is_logged() {
    let links = FakeInviteLinks::working();
    let rig = Rig::new().with_invite_links(links.shared());
    let root = rig.admin(ADMIN).await;
    let invited = rig.user("invited@kemlock.test").await;
    let space = SpaceId::random();
    let uri = invite_link_uri(space, invited.id);

    // The link accepts for the account, so a read without a step-up is refused.
    let bare = root.get(&uri).await;
    assert_eq!(bare.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&bare), "step-up-required");
    assert!(links.asked().is_empty());
    assert!(rig.admin.actions().is_empty());

    let token = root.step_up(&rig).await;
    let reply = root.write("GET", &uri, None, &token).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(
        reply.json()["link"],
        "https://vault.test/#/accept-organization/?token=secret"
    );
    assert_eq!(reply.json()["expiresAt"], 1_800_000_000);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(links.asked(), [(space, invited.id, Asker::Server)]);
    assert_eq!(rig.admin.actions(), ["admin.space.invite_link"]);
    let events = rig.admin.events();
    assert_eq!(
        events[0].target.as_deref(),
        Some(format!("{space}/{}", invited.id).as_str())
    );
}

#[tokio::test]
async fn the_invitation_link_is_refused_for_what_isnt_an_invitation() {
    let space = SpaceId::random();
    let member = UserId::random();
    let uri = invite_link_uri(space, member);
    for (answer, status, kind) in [
        (
            InviteLinkError::NotOrganization,
            StatusCode::CONFLICT,
            "wrong-state",
        ),
        (
            InviteLinkError::NotInvited,
            StatusCode::CONFLICT,
            "wrong-state",
        ),
        (InviteLinkError::NotFound, StatusCode::NOT_FOUND, ""),
    ] {
        let links = FakeInviteLinks::answering(Err(answer.clone()));
        let rig = Rig::new().with_invite_links(links.shared());
        let root = rig.admin(ADMIN).await;
        let token = root.step_up(&rig).await;
        let reply = root.write("GET", &uri, None, &token).await;
        assert_eq!(reply.status, status, "{answer:?}: {:?}", reply.json());
        if !kind.is_empty() {
            assert_eq!(slug(&reply), kind, "{answer:?}");
        }
        assert!(
            rig.admin.actions().is_empty(),
            "a refused read isn't logged"
        );
    }
}

#[tokio::test]
async fn a_server_without_the_bitwarden_api_has_no_invitation_link_to_give() {
    let rig = Rig::new();
    let root = rig.admin(ADMIN).await;
    let token = root.step_up(&rig).await;
    let reply = root
        .write(
            "GET",
            &invite_link_uri(SpaceId::random(), UserId::random()),
            None,
            &token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(slug(&reply), "not-configured");
    assert!(rig.admin.actions().is_empty());
}

#[tokio::test]
async fn a_non_admin_is_refused_the_invitation_link() {
    let links = FakeInviteLinks::working();
    let rig = Rig::new().with_invite_links(links.shared());
    let _root = rig.admin(ADMIN).await;
    let sam = rig.user("sam@kemlock.test").await;
    let uri = invite_link_uri(SpaceId::random(), sam.id);
    let reply = sam.send("GET", &uri, None, Some("made-up")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(slug(&reply), "forbidden");
    assert!(links.asked().is_empty());
}

#[tokio::test]
async fn the_console_says_which_spaces_are_organizations_and_who_has_an_invitation() {
    for (links, organization) in [(true, true), (true, false), (false, false)] {
        let fake = FakeInviteLinks::working();
        let rig = if links {
            Rig::new().with_invite_links(fake.shared())
        } else {
            Rig::new()
        };
        let root = rig.admin(ADMIN).await;
        let ada = rig.user("ada@kemlock.test").await;
        let ivy = rig.user("ivy@kemlock.test").await;
        let space = SpaceId::random();
        SpaceRepo::create(
            &rig.spaces,
            space_with(
                space,
                &[
                    (ada.id, SpaceRole::Owner, MemberState::Confirmed),
                    (ivy.id, SpaceRole::Member, MemberState::Invited),
                ],
            ),
        )
        .await
        .expect("space");
        rig.admin.track_space(space);
        // An organization where Ivy has a Bitwarden invitation, or a space the Bitwarden API
        // doesn't know (the links have no pending list for it).
        if organization {
            fake.set_pending(vec![ivy.id]);
        }

        let listed = root.get("/admin/v1/spaces").await;
        assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.json());
        let one = root.get(&format!("/admin/v1/spaces/{space}")).await;
        assert_eq!(one.status, StatusCode::OK, "{:?}", one.json());
        for seen in [listed.json()["spaces"][0].clone(), one.json()] {
            assert_eq!(seen["bitwardenOrganization"], organization);
            let expected = if organization {
                json!([{"userId": ivy.id.to_string(), "email": "ivy@kemlock.test"}])
            } else {
                json!([])
            };
            assert_eq!(seen["bitwardenInvitations"], expected);
        }
    }
}

#[tokio::test]
async fn the_invitation_link_is_not_given_when_the_copy_cannot_be_recorded() {
    let links = FakeInviteLinks::working();
    let rig = Rig::new().with_invite_links(links.shared());
    let root = rig.admin(ADMIN).await;
    let invited = rig.user("invited@kemlock.test").await;
    let token = root.step_up(&rig).await;
    rig.admin.fail_events();

    let reply = root
        .write(
            "GET",
            &invite_link_uri(SpaceId::random(), invited.id),
            None,
            &token,
        )
        .await;
    assert!(reply.status.is_server_error(), "{:?}", reply.status);
    // Whatever it says, it doesn't carry the link.
    assert!(
        !String::from_utf8_lossy(&reply.body).contains("accept-organization"),
        "a copy nobody recorded was handed over"
    );
    assert!(rig.admin.actions().is_empty());
}
