//! Emergency access: the routes the web vault and the mobile apps call, as Vaultwarden 1.37.5
//! (with mail off, its default) answers them.
//!
//! The source is Vaultwarden's `src/api/core/emergency_access.rs`. With no mail, Vaultwarden takes an
//! invited account that has a password as accepted at once. Kemlock Server leaves it invited until it
//! accepts, so a test accepts first when the grant is still waiting (`accept_if_waiting`), with the
//! link the grantor can copy from `.../invite-link`, which Vaultwarden doesn't have and needn't.

use kemlock_contract_tests::account::login_cipher;
use kemlock_contract_tests::enc::{b64, random_bytes};
use kemlock_contract_tests::util::message_of;
use kemlock_contract_tests::{Reply, Session, fresh_session};
use serde_json::{Value, json};

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("an object, got {value}"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn wrapped_key() -> String {
    format!("4.{}", b64(&random_bytes(256)))
}

async fn post_empty(s: &Session, path: &str) -> Reply {
    s.send(s.call("POST", path)).await
}

async fn invite(grantor: &Session, contact: &Session, kind: i64, days: i64) -> Reply {
    grantor
        .post(
            "/api/emergency-access/invite",
            &json!({"email": contact.account.email, "type": kind, "waitTimeDays": days}),
        )
        .await
}

/// The grantor's first trusted contact, as `GET /api/emergency-access/trusted` lists it.
async fn first_contact(grantor: &Session) -> Value {
    let list = grantor
        .get("/api/emergency-access/trusted")
        .await
        .ok_json("GET /api/emergency-access/trusted");
    list["data"][0].clone()
}

/// The token of an invitation link.
fn token_of(link: &str) -> &str {
    link.rsplit_once("token=")
        .map(|(_, token)| token)
        .expect("a link with a token")
}

/// Accepts the grant `id` as `contact` when it is still waiting for that. Vaultwarden with mail off
/// has taken an existing account as accepted already (status 1) and has nothing to accept; Kemlock
/// Server leaves it invited (status 0) until the contact follows the link, which the grantor can
/// copy.
async fn accept_if_waiting(grantor: &Session, contact: &Session, id: &str) {
    if first_contact(grantor).await["status"] != 0 {
        return;
    }
    let link = grantor
        .get(&format!("/api/emergency-access/{id}/invite-link"))
        .await
        .ok_json("GET invite-link");
    let token = token_of(link["link"].as_str().expect("a link")).to_owned();
    let reply = contact
        .post(
            &format!("/api/emergency-access/{id}/accept"),
            &json!({"token": token}),
        )
        .await;
    assert!(
        reply.is_success(),
        "accept: got {} {}",
        reply.status,
        reply.text()
    );
}

/// A grant of `grantor` to `contact`, accepted and confirmed; its id.
async fn confirmed(grantor: &Session, contact: &Session, kind: i64) -> String {
    let reply = invite(grantor, contact, kind, 7).await;
    assert!(
        reply.is_success(),
        "invite: Vaultwarden takes an invitation to an account that exists; got {} {}",
        reply.status,
        reply.text()
    );
    let id = first_contact(grantor).await["id"]
        .as_str()
        .expect("the grant has an id")
        .to_owned();
    accept_if_waiting(grantor, contact, &id).await;
    let confirm = grantor
        .post(
            &format!("/api/emergency-access/{id}/confirm"),
            &json!({"key": wrapped_key()}),
        )
        .await
        .ok_json("confirm");
    assert_eq!(
        confirm["status"], 2,
        "a confirmed grant is status 2: {confirm}"
    );
    id
}

#[tokio::test]
async fn an_invited_account_that_accepted_is_listed_on_both_sides() {
    let grantor = fresh_session().await;
    let contact = fresh_session().await;
    let reply = invite(&grantor, &contact, 0, 7).await;
    assert!(reply.is_success(), "{} {}", reply.status, reply.text());
    let waiting = first_contact(&grantor).await;
    let id = waiting["id"].as_str().expect("an id").to_owned();
    accept_if_waiting(&grantor, &contact, &id).await;

    let trusted = first_contact(&grantor).await;
    assert_eq!(
        sorted_keys(&trusted),
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
        ],
        "the grantor's list entry has Vaultwarden's keys: {trusted}"
    );
    assert_eq!(trusted["object"], "emergencyAccessGranteeDetails");
    assert_eq!(
        trusted["status"], 1,
        "an existing account has accepted, at once on Vaultwarden and by the link here: {trusted}"
    );
    assert_eq!(trusted["type"], 0);
    assert_eq!(trusted["waitTimeDays"], 7);
    assert_eq!(trusted["email"], contact.account.email.as_str());
    assert_eq!(trusted["granteeId"], contact.user_id.as_str());

    let granted = contact
        .get("/api/emergency-access/granted")
        .await
        .ok_json("GET /api/emergency-access/granted");
    assert_eq!(granted["object"], "list");
    assert!(granted["continuationToken"].is_null());
    let entry = &granted["data"][0];
    assert_eq!(
        sorted_keys(entry),
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
        ],
        "the contact's list entry has Vaultwarden's keys: {entry}"
    );
    assert_eq!(entry["object"], "emergencyAccessGrantorDetails");
    assert_eq!(entry["grantorId"], grantor.user_id.as_str());
    assert_eq!(entry["id"], trusted["id"]);
}

#[tokio::test]
async fn an_invite_is_checked_with_vaultwardens_messages() {
    let grantor = fresh_session().await;
    let contact = fresh_session().await;

    let own = grantor
        .post(
            "/api/emergency-access/invite",
            &json!({"email": grantor.account.email, "type": 0, "waitTimeDays": 7}),
        )
        .await;
    assert_eq!(own.status, 400);
    assert_eq!(
        message_of(&own.json()).as_deref(),
        Some("You can not set yourself as an emergency contact.")
    );

    for days in [0, 91] {
        let reply = invite(&grantor, &contact, 0, days).await;
        assert_eq!(reply.status, 400, "{days}");
        assert_eq!(
            message_of(&reply.json()).as_deref(),
            Some("Emergency access wait time is out-of-bounds!")
        );
    }
    let reply = invite(&grantor, &contact, 2, 7).await;
    assert_eq!(
        message_of(&reply.json()).as_deref(),
        Some("Invalid emergency access type.")
    );

    // The type is a number or its name.
    let by_name = grantor
        .post(
            "/api/emergency-access/invite",
            &json!({"email": contact.account.email, "type": "Takeover", "waitTimeDays": 7}),
        )
        .await;
    assert!(
        by_name.is_success(),
        "{} {}",
        by_name.status,
        by_name.text()
    );
    let again = invite(&grantor, &contact, 0, 7).await;
    assert_eq!(
        message_of(&again.json()),
        Some(format!(
            "Grantee user already invited: {}",
            contact.account.email
        ))
    );
}

#[tokio::test]
async fn a_request_runs_to_approval_and_the_contact_views_the_vault() {
    let grantor = fresh_session().await;
    let contact = fresh_session().await;
    let cipher = grantor
        .create_cipher(&login_cipher(&grantor.user_id, "Emergency login"))
        .await;
    let id = confirmed(&grantor, &contact, 0).await;

    let early = post_empty(&contact, &format!("/api/emergency-access/{id}/view")).await;
    assert_eq!(early.status, 400);
    assert_eq!(
        message_of(&early.json()).as_deref(),
        Some("Emergency access not valid."),
        "nothing is viewable before the request is approved"
    );

    let initiated = post_empty(&contact, &format!("/api/emergency-access/{id}/initiate"))
        .await
        .ok_json("initiate");
    assert_eq!(
        sorted_keys(&initiated),
        ["id", "object", "status", "type", "waitTimeDays"]
    );
    assert_eq!(initiated["status"], 3);
    assert_eq!(initiated["object"], "emergencyAccess");

    let approved = post_empty(&grantor, &format!("/api/emergency-access/{id}/approve"))
        .await
        .ok_json("approve");
    assert_eq!(approved["status"], 4);

    let view = post_empty(&contact, &format!("/api/emergency-access/{id}/view"))
        .await
        .ok_json("view");
    assert_eq!(view["object"], "emergencyAccessView");
    assert!(view["keyEncrypted"].is_string(), "{view}");
    let ids: Vec<&str> = view["ciphers"]
        .as_array()
        .map(|all| all.iter().filter_map(|c| c["id"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(ids, [cipher["id"].as_str().expect("an id")], "{view}");

    // A view grant has no takeover.
    let takeover = post_empty(&contact, &format!("/api/emergency-access/{id}/takeover")).await;
    assert_eq!(takeover.status, 400);
}

#[tokio::test]
async fn a_refused_request_goes_back_to_confirmed_and_can_be_made_again() {
    let grantor = fresh_session().await;
    let contact = fresh_session().await;
    let id = confirmed(&grantor, &contact, 0).await;

    let early = post_empty(&grantor, &format!("/api/emergency-access/{id}/reject")).await;
    assert_eq!(
        early.status, 400,
        "only a running or approved request is refused"
    );

    post_empty(&contact, &format!("/api/emergency-access/{id}/initiate"))
        .await
        .ok_json("initiate");
    let rejected = post_empty(&grantor, &format!("/api/emergency-access/{id}/reject"))
        .await
        .ok_json("reject");
    assert_eq!(
        rejected["status"], 2,
        "a refusal leaves the grant Confirmed: {rejected}"
    );

    let again = post_empty(&contact, &format!("/api/emergency-access/{id}/initiate"))
        .await
        .ok_json("initiate again");
    assert_eq!(again["status"], 3);
}

#[tokio::test]
async fn either_party_deletes_a_grant_and_only_the_grantor_updates_or_reads_it() {
    let grantor = fresh_session().await;
    let contact = fresh_session().await;
    let stranger = fresh_session().await;
    let id = confirmed(&grantor, &contact, 0).await;

    let denied = stranger
        .delete(&format!("/api/emergency-access/{id}"))
        .await;
    assert_eq!(denied.status, 400);
    assert_eq!(
        message_of(&denied.json()).as_deref(),
        Some("Emergency access not valid.")
    );
    let read = contact.get(&format!("/api/emergency-access/{id}")).await;
    assert_eq!(
        read.status, 400,
        "the contact can't read the grantor's view of it"
    );

    let updated = grantor
        .put(
            &format!("/api/emergency-access/{id}"),
            &json!({"type": 1, "waitTimeDays": 30}),
        )
        .await
        .ok_json("update");
    assert_eq!(updated["type"], 1);
    assert_eq!(updated["waitTimeDays"], 30);
    assert_eq!(updated["status"], 2);

    let removed = post_empty(&contact, &format!("/api/emergency-access/{id}/delete")).await;
    assert!(
        removed.is_success(),
        "{} {}",
        removed.status,
        removed.text()
    );
    assert!(first_contact(&grantor).await.is_null());
}
