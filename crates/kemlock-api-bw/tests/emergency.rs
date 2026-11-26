//! Emergency access through the router, with the shapes and messages of Vaultwarden 1.37.5.

mod common;

use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness, keys, login_request};
use serde_json::{Value, json};
use time::Duration;

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("an id").to_owned()
}

async fn invite(h: &Harness, token: &str, email: &str, kind: i32, days: i32) -> StatusCode {
    h.json(
        "POST",
        "/api/emergency-access/invite",
        Some(token),
        Some(json!({"email": email, "type": kind, "waitTimeDays": days})),
    )
    .await
    .0
}

/// The grantor's first trusted contact.
async fn first_contact(h: &Harness, token: &str) -> Value {
    let (status, list) = h
        .json("GET", "/api/emergency-access/trusted", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    list["data"][0].clone()
}

async fn post(h: &Harness, token: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/emergency-access/{path}"),
        Some(token),
        body,
    )
    .await
}

/// The contact follows the link of the invitation mail: a token Ada's server would have mailed.
async fn accept_as(h: &Harness, email: &str, id: &str) {
    let body = h.login(email, HASH).await;
    let token = body["access_token"].as_str().expect("a token").to_owned();
    let now = h.env.time().unix_timestamp();
    let user = common::claims(&token, now).sub;
    let link = keys()
        .encode(&json!({
            "nbf": now,
            "exp": now + 3600,
            "iss": format!("{DOMAIN}|emergencyaccessinvite"),
            "sub": user,
            "email": email,
            "emer_id": id,
            "grantor_name": "Kemlock test",
            "grantor_email": "ada@example.com",
        }))
        .expect("a token");
    let (status, body) = post(
        h,
        &token,
        &format!("{id}/accept"),
        Some(json!({"token": link})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Ada names Bob, who has an account; Bob follows the link to accept, and Ada confirms it.
async fn confirmed(h: &Harness, ada: &str, kind: i32) -> String {
    assert_eq!(
        invite(h, ada, "bob@example.com", kind, 7).await,
        StatusCode::OK
    );
    let id = id_of(&first_contact(h, ada).await);
    accept_as(h, "bob@example.com", &id).await;
    let (status, body) = post(
        h,
        ada,
        &format!("{id}/confirm"),
        Some(json!({"key": "4.wrapped"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], 2);
    id
}

#[tokio::test]
async fn an_invited_account_stays_invited_until_it_accepts_and_is_then_listed_with_vaultwardens_keys()
 {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;

    assert_eq!(
        invite(&h, &ada, "Bob@Example.com", 0, 7).await,
        StatusCode::OK
    );
    // Naming someone who has an account does not make them a contact: they accept for themselves.
    let waiting = first_contact(&h, &ada).await;
    assert_eq!(waiting["status"], 0, "invited, and it stays so");
    let (status, list) = h
        .json("GET", "/api/emergency-access/granted", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["data"], json!([]));
    // A resend only mails again: Ada can not accept for Bob.
    let waiting_id = id_of(&waiting);
    let (status, body) = post(&h, &ada, &format!("{waiting_id}/reinvite"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(first_contact(&h, &ada).await["status"], 0);
    // Ada can not confirm a contact who has not accepted.
    let (status, _) = post(
        &h,
        &ada,
        &format!("{waiting_id}/confirm"),
        Some(json!({"key": "4.wrapped"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    accept_as(&h, "bob@example.com", &waiting_id).await;

    let contact = first_contact(&h, &ada).await;
    assert_eq!(
        sorted_keys(&contact),
        [
            "avatarColor",
            "email",
            "granteeId",
            "id",
            "name",
            "object",
            "status",
            "type",
            "waitTimeDays"
        ]
    );
    assert_eq!(contact["object"], "emergencyAccessGranteeDetails");
    assert_eq!(contact["status"], 1, "accepted by the contact");
    assert_eq!(contact["type"], 0);
    assert_eq!(contact["waitTimeDays"], 7);
    assert_eq!(contact["email"], "bob@example.com");
    assert_eq!(contact["granteeId"], bob_id.to_string());

    let (status, list) = h
        .json("GET", "/api/emergency-access/granted", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["object"], "list");
    assert!(list["continuationToken"].is_null());
    let granted = &list["data"][0];
    assert_eq!(
        sorted_keys(granted),
        [
            "avatarColor",
            "email",
            "grantorId",
            "id",
            "name",
            "object",
            "status",
            "type",
            "waitTimeDays"
        ]
    );
    assert_eq!(granted["object"], "emergencyAccessGrantorDetails");
    assert_eq!(granted["grantorId"], ada_id.to_string());
    assert_eq!(granted["email"], "ada@example.com");
    assert_eq!(id_of(granted), id_of(&contact));
}

#[tokio::test]
async fn an_invite_is_checked_with_vaultwardens_messages() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    h.signed_in("bob@example.com").await;

    let (status, body) = h
        .json(
            "POST",
            "/api/emergency-access/invite",
            Some(&ada),
            Some(json!({"email": "ada@example.com", "type": 0, "waitTimeDays": 7})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "You can not set yourself as an emergency contact."
    );

    for days in [0, 91, -1] {
        let (status, body) = h
            .json(
                "POST",
                "/api/emergency-access/invite",
                Some(&ada),
                Some(json!({"email": "bob@example.com", "type": 0, "waitTimeDays": days})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{days}");
        assert_eq!(
            body["message"],
            "Emergency access wait time is out-of-bounds!"
        );
    }

    let (_, body) = h
        .json(
            "POST",
            "/api/emergency-access/invite",
            Some(&ada),
            Some(json!({"email": "bob@example.com", "type": 2, "waitTimeDays": 7})),
        )
        .await;
    assert_eq!(body["message"], "Invalid emergency access type.");

    // The type may be text, as Vaultwarden's NumberOrString allows.
    let (status, _) = h
        .json(
            "POST",
            "/api/emergency-access/invite",
            Some(&ada),
            Some(json!({"email": "bob@example.com", "type": "Takeover", "waitTimeDays": 7})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = h
        .json(
            "POST",
            "/api/emergency-access/invite",
            Some(&ada),
            Some(json!({"email": "bob@example.com", "type": 0, "waitTimeDays": 7})),
        )
        .await;
    assert_eq!(
        body["message"],
        "Grantee user already invited: bob@example.com"
    );
}

#[tokio::test]
async fn a_contact_without_an_account_waits_as_invited_and_accepts_with_the_link() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    assert_eq!(
        invite(&h, &ada, "carol@example.com", 1, 3).await,
        StatusCode::OK
    );

    let contact = first_contact(&h, &ada).await;
    assert_eq!(contact["status"], 0);
    assert_eq!(contact["email"], "carol@example.com");
    assert_eq!(contact["type"], 1);
    let id = id_of(&contact);

    // A re-invite with no account for the address is accepted quietly.
    let (status, _) = post(&h, &ada, &format!("{id}/reinvite"), None).await;
    assert_eq!(status, StatusCode::OK);

    // Carol signs up and follows the link Ada's invitation carried.
    let (carol, carol_id) = h.signed_in("carol@example.com").await;
    let now = h.env.time().unix_timestamp();
    let link = keys()
        .encode(&json!({
            "nbf": now,
            "exp": now + 3600,
            "iss": format!("{DOMAIN}|emergencyaccessinvite"),
            "sub": carol_id.to_string(),
            "email": "carol@example.com",
            "emer_id": id,
            "grantor_name": "Kemlock test",
            "grantor_email": "ada@example.com",
        }))
        .expect("a token");

    // Somebody else's link is refused.
    let (bob, _) = h.signed_in("bob@example.com").await;
    let (status, body) = post(
        &h,
        &bob,
        &format!("{id}/accept"),
        Some(json!({"token": link})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Claim email does not match current users email"
    );

    let (status, body) = post(
        &h,
        &carol,
        &format!("{id}/accept"),
        Some(json!({"token": link})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(first_contact(&h, &ada).await["status"], 1);

    let (status, _) = post(
        &h,
        &carol,
        &format!("{id}/accept"),
        Some(json!({"token": link})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a grant is accepted once");
}

#[tokio::test]
async fn a_request_runs_from_confirmed_to_approved_and_the_contact_views_the_vault() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;

    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&ada),
            Some(login_request(ada_id, "2.one")),
        )
        .await;
    let cipher_id = id_of(&cipher);

    let id = confirmed(&h, &ada, 0).await;

    // Nothing can be viewed before the request is approved.
    let (status, body) = post(&h, &bob, &format!("{id}/view"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Emergency access not valid.");

    let (status, body) = post(&h, &bob, &format!("{id}/initiate"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        sorted_keys(&body),
        ["id", "object", "status", "type", "waitTimeDays"]
    );
    assert_eq!(body["status"], 3);
    assert_eq!(body["object"], "emergencyAccess");

    let (status, body) = post(&h, &ada, &format!("{id}/approve"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], 4);

    let (status, view) = post(&h, &bob, &format!("{id}/view"), None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["object"], "emergencyAccessView");
    assert_eq!(view["keyEncrypted"], "4.wrapped");
    assert_eq!(view["ciphers"][0]["id"], cipher_id.as_str());
    assert_eq!(view["ciphers"][0]["object"], "cipherDetails");
    assert_eq!(view["ciphers"].as_array().map(Vec::len), Some(1));

    // A view grant has no takeover.
    let (status, body) = post(&h, &bob, &format!("{id}/takeover"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Emergency access not valid.");
}

#[tokio::test]
async fn a_refused_request_goes_back_to_confirmed_and_can_be_made_again() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let id = confirmed(&h, &ada, 0).await;

    // Only a running or approved request can be refused.
    let (status, _) = post(&h, &ada, &format!("{id}/reject"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    post(&h, &bob, &format!("{id}/initiate"), None).await;
    let (status, body) = post(&h, &ada, &format!("{id}/reject"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], 2);

    let (status, body) = post(&h, &bob, &format!("{id}/initiate"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], 3);

    // Ada's side can't start a request, Bob's can't approve one.
    let (status, _) = post(&h, &bob, &format!("{id}/approve"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_request_whose_wait_has_ended_is_approved_when_it_is_read() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let id = confirmed(&h, &ada, 0).await;
    post(&h, &bob, &format!("{id}/initiate"), None).await;

    // The access tokens end with the clock's jump, so Ada signs in again each time.
    h.env.advance(Duration::days(6));
    let ada = h.login("ada@example.com", HASH).await["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert_eq!(first_contact(&h, &ada).await["status"], 3);
    h.env.advance(Duration::days(2));
    let ada = h.login("ada@example.com", HASH).await["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert_eq!(first_contact(&h, &ada).await["status"], 4);
}

#[tokio::test]
async fn a_takeover_sets_the_grantors_password_and_ends_their_sessions() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let id = confirmed(&h, &ada, 1).await;
    post(&h, &bob, &format!("{id}/initiate"), None).await;
    post(&h, &ada, &format!("{id}/approve"), None).await;

    let (status, takeover) = post(&h, &bob, &format!("{id}/takeover"), None).await;
    assert_eq!(status, StatusCode::OK, "{takeover}");
    assert_eq!(
        sorted_keys(&takeover),
        [
            "kdf",
            "kdfIterations",
            "kdfMemory",
            "kdfParallelism",
            "keyEncrypted",
            "object",
            "salt"
        ]
    );
    assert_eq!(takeover["object"], "emergencyAccessTakeover");
    assert_eq!(takeover["kdf"], 0);
    assert_eq!(takeover["kdfIterations"], 1_000);
    assert_eq!(takeover["salt"], "ada@example.com");
    assert_eq!(takeover["keyEncrypted"], "4.wrapped");

    let (status, body) = post(
        &h,
        &bob,
        &format!("{id}/password"),
        Some(json!({"newMasterPasswordHash": "a-new-hash", "key": "2.new|key|mac"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Ada's old session is over, her old password no longer signs in, the new one does.
    let (status, _) = h
        .json("GET", "/api/accounts/profile", Some(&ada), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let signed = h.login("ada@example.com", "a-new-hash").await;
    assert_eq!(signed["Key"], "2.new|key|mac");

    // The current payload must agree with the grantor's account.
    let (status, body) = post(
        &h,
        &bob,
        &format!("{id}/password"),
        Some(json!({
            "authenticationData": {
                "salt": "ada@example.com",
                "kdf": {"kdfType": 0, "iterations": 5, "memory": null, "parallelism": null},
                "masterPasswordAuthenticationHash": "x"
            },
            "unlockData": {
                "salt": "ada@example.com",
                "kdf": {"kdfType": 0, "iterations": 5, "memory": null, "parallelism": null},
                "masterKeyWrappedUserKey": "2.k"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "KDF settings do not match the grantor account"
    );

    let (_, body) = post(&h, &bob, &format!("{id}/password"), Some(json!({}))).await;
    assert_eq!(body["message"], "Invalid request!");
}

#[tokio::test]
async fn either_party_deletes_a_grant_and_a_stranger_can_not() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let id = confirmed(&h, &ada, 0).await;

    let (status, body) = h
        .json(
            "DELETE",
            &format!("/api/emergency-access/{id}"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Emergency access not valid.");
    let (status, _) = h
        .json(
            "GET",
            &format!("/api/emergency-access/{id}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "only the grantor reads one"
    );

    let (status, _) = post(&h, &bob, &format!("{id}/delete"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(first_contact(&h, &ada).await.is_null());
}

#[tokio::test]
async fn a_grant_is_updated_by_its_grantor() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    // Bob must have an account to follow the link of the invitation, and then it is ready to confirm.
    let (_bob, _) = h.signed_in("bob@example.com").await;
    let id = confirmed(&h, &ada, 0).await;

    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/emergency-access/{id}"),
            Some(&ada),
            Some(json!({"type": 1, "waitTimeDays": 30, "keyEncrypted": "4.rewrapped"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["type"], 1);
    assert_eq!(body["waitTimeDays"], 30);
    assert_eq!(body["status"], 2);

    let (status, one) = h
        .json(
            "GET",
            &format!("/api/emergency-access/{id}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["type"], 1);
    assert_eq!(one["waitTimeDays"], 30);

    let (_, body) = h
        .json(
            "PUT",
            &format!("/api/emergency-access/{id}"),
            Some(&ada),
            Some(json!({"type": 1, "waitTimeDays": 0})),
        )
        .await;
    assert_eq!(
        body["message"],
        "Emergency access wait time is out-of-bounds!"
    );
}

#[tokio::test]
async fn the_policies_of_a_takeover_are_a_list() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    let id = confirmed(&h, &ada, 1).await;
    post(&h, &bob, &format!("{id}/initiate"), None).await;
    post(&h, &ada, &format!("{id}/approve"), None).await;

    let (status, list) = h
        .json(
            "GET",
            &format!("/api/emergency-access/{id}/policies"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["object"], "list");
    assert_eq!(list["data"], json!([]));
}

#[tokio::test]
async fn the_invitation_link_accepts_for_the_contact_without_signing_in() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, _) = h.signed_in("bob@example.com").await;
    assert_eq!(
        invite(&h, &ada, "bob@example.com", 0, 7).await,
        StatusCode::OK
    );
    let id = id_of(&first_contact(&h, &ada).await);

    // The grantor copies the link; the contact is not given it.
    let uri = format!("/api/emergency-access/{id}/invite-link");
    let (status, _) = h.json("GET", &uri, Some(&bob), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "only the grantor's grant");
    let (status, body) = h.json("GET", &uri, Some(&ada), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let link = body["link"].as_str().expect("a link").to_owned();
    assert!(
        link.starts_with(&format!("{DOMAIN}/#/accept-emergency/?id={id}&name=")),
        "{link}"
    );
    let token = body["token"].as_str().expect("a token").to_owned();
    assert!(link.ends_with(&format!("&token={token}")), "{link}");

    // The token alone accepts, for the address it names, once.
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/emergency-access/{id}/accept"),
            None,
            Some(json!({"token": token})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(first_contact(&h, &ada).await["status"], 1);
    let (status, _) = h
        .json(
            "POST",
            &format!("/api/emergency-access/{id}/accept"),
            None,
            Some(json!({"token": token})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.json("GET", &uri, Some(&ada), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "nothing left to hand over");
}
