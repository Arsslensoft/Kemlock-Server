//! Account recovery through the router: the policy, a member's enrolment with the key their client
//! encrypted, and an admin setting a new password (and clearing the second step) from what the
//! admin's client made. The server stores and hands on what the clients encrypt.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use time::Duration;

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";
const RANGE: &str = "start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z";

async fn organization(h: &Harness, owner: &str) -> String {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(json!({
                "name": "Recovery organization",
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": ORG_KEY,
                "keys": {"publicKey": "MIIBIjANorg", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    org["id"].as_str().expect("an id").to_owned()
}

/// Invites `email` with `atype` and confirms them.
async fn add_member(h: &Harness, owner: &str, org: &str, member: UserId, email: &str, atype: i32) {
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(owner),
            Some(json!({"emails": [email], "type": atype, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.env.advance(Duration::seconds(1));
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{member}/confirm"),
            Some(owner),
            Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn set_policy(h: &Harness, token: &str, org: &str, enabled: bool, data: Value) {
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/8"),
            Some(token),
            Some(json!({"policy": {"enabled": enabled, "data": data}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn enroll(
    h: &Harness,
    token: &str,
    org: &str,
    user: UserId,
    key: &str,
) -> (StatusCode, Value) {
    h.json(
        "PUT",
        &format!("/api/organizations/{org}/users/{user}/reset-password-enrollment"),
        Some(token),
        Some(json!({"resetPasswordKey": key, "masterPasswordHash": HASH})),
    )
    .await
}

async fn recover(
    h: &Harness,
    token: &str,
    org: &str,
    user: UserId,
    body: Value,
) -> (StatusCode, Value) {
    h.json(
        "PUT",
        &format!("/api/organizations/{org}/users/{user}/recover-account"),
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn a_member_enrols_and_an_admin_reads_what_the_clients_need() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com", 2).await;

    // Without the policy there is nothing to enrol in.
    let (status, body) = enroll(&h, &bob, &org, bob_id, "4.bobresetkey").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Policy not found");

    set_policy(&h, &ada, &org, true, json!({"autoEnrollEnabled": false})).await;
    let (_, org_json) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(org_json["useResetPassword"], true);
    let (_, status_json) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/auto-enroll-status"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status_json["resetPasswordEnabled"], false);

    // Enrolling needs the member's password and is for the member alone.
    let uri = format!("/api/organizations/{org}/users/{bob_id}/reset-password-enrollment");
    let (status, body) = h
        .json(
            "PUT",
            &uri,
            Some(&bob),
            Some(json!({"resetPasswordKey": "4.bobresetkey", "masterPasswordHash": "wrong"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = enroll(&h, &ada, &org, bob_id, "4.bobresetkey").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "User to enroll isn't member of required organization"
    );
    let (status, body) = enroll(&h, &bob, &org, bob_id, "4.bobresetkey").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, synced) = h.json("GET", "/api/sync", Some(&bob), None).await;
    assert_eq!(
        synced["profile"]["organizations"][0]["resetPasswordEnrolled"],
        true
    );

    // The admin's client gets the member's key, the organization's encrypted private key and
    // the KDF it needs for the new password.
    let (status, details) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/reset-password-details"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{details}");
    assert_eq!(details["object"], "organizationUserResetPasswordDetails");
    assert_eq!(details["organizationUserId"], bob_id.to_string());
    assert_eq!(details["resetPasswordKey"], "4.bobresetkey");
    assert_eq!(details["encryptedPrivateKey"], "2.orgprivate|key|mac");
    assert_eq!(details["masterPasswordSalt"], "bob@example.com");
    assert_eq!(details["kdf"], 0);
    assert_eq!(details["kdfIterations"], 1_000);
    assert!(details["kdfMemory"].is_null());

    // A member isn't an admin.
    let (status, _) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users/{bob_id}/reset-password-details"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Withdrawing sends no key.
    let (status, body) = enroll(&h, &bob, &org, bob_id, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, synced) = h.json("GET", "/api/sync", Some(&bob), None).await;
    assert_eq!(
        synced["profile"]["organizations"][0]["resetPasswordEnrolled"],
        false
    );

    // With auto-enrolment on, enrolment can't be withdrawn.
    set_policy(&h, &ada, &org, true, json!({"autoEnrollEnabled": true})).await;
    let (status, body) = enroll(&h, &bob, &org, bob_id, "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Reset password can't be withdrawn due to an enterprise policy"
    );
    let (_, status_json) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/auto-enroll-status"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status_json["resetPasswordEnabled"], true);
}

#[tokio::test]
async fn an_admin_sets_a_new_password_and_the_member_signs_in_with_it() {
    let h = Harness::with(|settings| settings.org_events_enabled = true).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com", 2).await;
    set_policy(&h, &ada, &org, true, json!({"autoEnrollEnabled": false})).await;

    // Not enrolled yet.
    let (status, body) = recover(
        &h,
        &ada,
        &org,
        bob_id,
        json!({"resetMasterPassword": true, "resetTwoFactor": false,
            "newMasterPasswordHash": "NEWHASH", "key": "2.newkey|x|y"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Password reset not or not correctly enrolled"
    );

    let (status, body) = enroll(&h, &bob, &org, bob_id, "4.bobresetkey").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A request with nothing to set is refused as unprocessable.
    let (status, body) = recover(
        &h,
        &ada,
        &org,
        bob_id,
        json!({"resetMasterPassword": true, "resetTwoFactor": false}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["message"], "Missing fields to reset password");

    h.env.advance(Duration::minutes(1));
    let (status, body) = recover(
        &h,
        &ada,
        &org,
        bob_id,
        json!({"resetMasterPassword": true, "resetTwoFactor": true,
            "newMasterPasswordHash": "NEWHASH", "key": "2.newkey|x|y"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob's session is over, the old password is refused and the new one works, with the new key.
    let (status, _) = h.json("GET", "/api/sync", Some(&bob), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let signed = h.login("bob@example.com", "NEWHASH").await;
    assert_eq!(signed["Key"], "2.newkey|x|y");

    // Both resets are events of the organization.
    let (_, page) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/events?{RANGE}"),
            Some(&ada),
            None,
        )
        .await;
    let mut types: Vec<i64> = page["data"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|e| e["type"].as_i64().expect("a type"))
        .collect();
    types.sort_unstable();
    assert!(types.contains(&1506), "the enrolment");
    assert!(types.contains(&1508), "the password reset");
    assert!(types.contains(&1519), "the two-step reset");

    // The older route sets a password alone, and the enrolment is still there.
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/reset-password"),
            Some(&ada),
            Some(json!({"newMasterPasswordHash": "NEWER", "key": "2.newerkey|x|y"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signed = h.login("bob@example.com", "NEWER").await;
    assert_eq!(signed["Key"], "2.newerkey|x|y");
}

#[tokio::test]
async fn who_may_reset_whom_and_when() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (dan, dan_id) = h.signed_in("dan@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    add_member(&h, &ada, &org, dan_id, "dan@example.com", 1).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com", 2).await;
    let body = json!({"resetMasterPassword": true, "resetTwoFactor": false,
        "newMasterPasswordHash": "NEWHASH", "key": "2.newkey|x|y"});

    // The policy must exist and be on.
    let (status, got) = recover(&h, &ada, &org, bob_id, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(got["message"], "Policy not found");
    set_policy(&h, &ada, &org, false, Value::Null).await;
    let (_, got) = recover(&h, &ada, &org, bob_id, body.clone()).await;
    assert_eq!(got["message"], "Reset password policy not enabled");
    set_policy(&h, &ada, &org, true, Value::Null).await;

    // An admin can't reset an owner, and nobody resets someone who isn't in the organization.
    let (status, got) = recover(&h, &dan, &org, ada_id, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        got["message"],
        "No permission to reset this user's password"
    );
    let (_, got) = recover(&h, &ada, &org, UserId::random(), body.clone()).await;
    assert_eq!(
        got["message"],
        "User to reset isn't member of required organization"
    );
    // A member is turned away at the guard.
    let (status, _) = recover(&h, &bob, &org, dan_id, body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An admin resets a member who enrolled.
    let (status, got) = enroll(&h, &bob, &org, bob_id, "4.bobresetkey").await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let (status, got) = recover(&h, &dan, &org, bob_id, body).await;
    assert_eq!(status, StatusCode::OK, "{got}");
}
