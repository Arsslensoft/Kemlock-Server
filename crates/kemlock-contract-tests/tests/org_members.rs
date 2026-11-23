//! Organization members, collection grants and policies: what the web vault calls to run an
//! organization, as Vaultwarden 1.37.5 (with mail off, its default) answers.
//!
//! The source is Vaultwarden's `src/api/core/organizations.rs` and the organization parts of
//! `ciphers.rs`. With no mail, an invited account that has a password is accepted at once, so two
//! registered accounts need no invitation link. Groups are left out: Vaultwarden has them off
//! unless `ORG_GROUPS_ENABLED` is set.

use kemlock_contract_tests::account::login_cipher;
use kemlock_contract_tests::enc::{b64, enc, random_bytes};
use kemlock_contract_tests::util::message_of;
use kemlock_contract_tests::{Session, fresh_session, stand_aside_on_vaultwarden};
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

/// An organization of one, owned by `s`; its id and its default collection's.
async fn organization(s: &Session) -> (String, String) {
    let reply = s
        .post(
            "/api/organizations",
            &json!({
                "name": "Contract organization",
                "billingEmail": s.account.email,
                "planType": 0,
                "key": wrapped_key(),
                "keys": {
                    "publicKey": s.account.public_key,
                    "encryptedPrivateKey": s.account.private_key,
                },
                "collectionName": enc("Default collection"),
            }),
        )
        .await;
    let created = reply.ok_json("POST /api/organizations");
    let id = created["id"].as_str().expect("an id").to_owned();
    let sync = s.sync().await;
    let collection = sync["collections"]
        .as_array()
        .and_then(|all| all.iter().find(|c| c["organizationId"] == json!(id)))
        .expect("the organization has a collection in /api/sync")["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    (id, collection)
}

/// `member` invited by `owner` and confirmed.
async fn add_member(owner: &Session, org: &str, member: &Session) {
    let reply = owner
        .post(
            &format!("/api/organizations/{org}/users/invite"),
            &json!({
                "emails": [member.account.email],
                "type": 2,
                "collections": [],
                "groups": []
            }),
        )
        .await;
    assert!(
        reply.is_success(),
        "invite: Vaultwarden takes an invitation to an account that exists; got {} {}",
        reply.status,
        reply.text()
    );
    let reply = owner
        .post(
            &format!(
                "/api/organizations/{org}/users/{}/confirm",
                member_id(owner, org, member).await
            ),
            &json!({"key": wrapped_key()}),
        )
        .await;
    assert!(
        reply.is_success(),
        "confirm: got {} {}",
        reply.status,
        reply.text()
    );
}

/// The id the organization's member list gives `member`.
async fn member_id(owner: &Session, org: &str, member: &Session) -> String {
    let list = owner
        .get(&format!("/api/organizations/{org}/users"))
        .await
        .ok_json("GET /api/organizations/{id}/users");
    list["data"]
        .as_array()
        .and_then(|all| {
            all.iter()
                .find(|m| m["email"] == json!(member.account.email))
        })
        .unwrap_or_else(|| panic!("the member list names {}: {list}", member.account.email))["id"]
        .as_str()
        .expect("an id")
        .to_owned()
}

#[tokio::test]
async fn an_invited_account_is_accepted_then_confirmed_and_sees_the_organization() {
    let owner = fresh_session().await;
    let member = fresh_session().await;
    let (org, _) = organization(&owner).await;

    let reply = owner
        .post(
            &format!("/api/organizations/{org}/users/invite"),
            &json!({"emails": [member.account.email], "type": 2, "collections": [], "groups": []}),
        )
        .await;
    assert!(reply.is_success(), "{} {}", reply.status, reply.text());

    let list = owner
        .get(&format!("/api/organizations/{org}/users"))
        .await
        .ok_json("GET users");
    assert_eq!(list["object"], json!("list"));
    let row = list["data"]
        .as_array()
        .and_then(|all| {
            all.iter()
                .find(|m| m["email"] == json!(member.account.email))
        })
        .expect("the invited account is listed")
        .clone();
    assert_eq!(
        sorted_keys(&row),
        [
            "accessSecretsManager",
            "avatarColor",
            "claimedByOrganization",
            "collections",
            "email",
            "externalId",
            "groups",
            "hasMasterPassword",
            "id",
            "name",
            "object",
            "permissions",
            "resetPasswordEnrolled",
            "ssoBound",
            "status",
            "twoFactorEnabled",
            "type",
            "userId",
            "usesKeyConnector"
        ],
        "a member as an admin sees them"
    );
    assert_eq!(row["object"], json!("organizationUserUserDetails"));
    assert_eq!(
        row["status"],
        json!(1),
        "mail is off, so the account has accepted"
    );
    assert_eq!(row["type"], json!(2));

    let before = member.sync().await;
    assert_eq!(
        before["profile"]["organizations"],
        json!([]),
        "only confirmed memberships are in `organizations`"
    );
    assert_eq!(before["profile"]["organizationsNew"][0]["status"], json!(1));

    let id = row["id"].as_str().expect("an id");
    let key = wrapped_key();
    let reply = owner
        .post(
            &format!("/api/organizations/{org}/users/{id}/confirm"),
            &json!({"key": key}),
        )
        .await;
    assert!(reply.is_success(), "{} {}", reply.status, reply.text());
    let after = member.sync().await;
    let joined = &after["profile"]["organizations"][0];
    assert_eq!(joined["object"], json!("profileOrganization"));
    assert_eq!(joined["key"], json!(key));
    assert_eq!(joined["status"], json!(2));
    assert_eq!(joined["type"], json!(2));

    let again = owner
        .post(
            &format!("/api/organizations/{org}/users/{id}/confirm"),
            &json!({"key": wrapped_key()}),
        )
        .await;
    assert_eq!(again.status, 400);
    assert_eq!(
        message_of(&again.json()).as_deref(),
        Some("User in invalid state")
    );

    let refused = member.get(&format!("/api/organizations/{org}/users")).await;
    assert_eq!(
        refused.status, 401,
        "a plain member is turned away at the guard"
    );
}

#[tokio::test]
async fn a_collection_grant_sets_what_a_member_sees_and_may_do_with_a_cipher() {
    let owner = fresh_session().await;
    let member = fresh_session().await;
    let (org, _) = organization(&owner).await;
    add_member(&owner, &org, &member).await;
    let member_id = member_id(&owner, &org, &member).await;

    let made = owner
        .post(
            &format!("/api/organizations/{org}/collections"),
            &json!({
                "name": enc("Shared"),
                "groups": [],
                "users": [{"id": member_id, "readOnly": true, "hidePasswords": true, "manage": false}],
                "externalId": null
            }),
        )
        .await
        .ok_json("POST collection");
    assert_eq!(made["object"], json!("collectionDetails"));
    let collection = made["id"].as_str().expect("an id").to_owned();

    let seen = member.sync().await["collections"]
        .as_array()
        .and_then(|all| all.iter().find(|c| c["id"] == json!(collection)))
        .cloned()
        .expect("the member sees the collection");
    assert_eq!(seen["readOnly"], json!(true));
    assert_eq!(seen["hidePasswords"], json!(true));
    assert_eq!(seen["manage"], json!(false));

    let mut cipher = login_cipher(&owner.user_id, "Shared login");
    cipher["organizationId"] = json!(org);
    cipher["key"] = json!(enc("cipher key"));
    let created = owner
        .post(
            "/api/ciphers/create",
            &json!({"cipher": cipher, "collectionIds": [collection]}),
        )
        .await
        .ok_json("POST /api/ciphers/create");
    assert_eq!(created["organizationId"], json!(org));
    assert_eq!(created["collectionIds"], json!([collection]));
    let id = created["id"].as_str().expect("an id").to_owned();

    let theirs = member
        .synced_cipher(&id)
        .await
        .expect("the member's sync has the cipher");
    assert_eq!(theirs["organizationId"], json!(org));
    assert_eq!(theirs["collectionIds"], json!([collection]));
    assert_eq!(theirs["edit"], json!(false));
    assert_eq!(theirs["viewPassword"], json!(false));

    let mut change = login_cipher(&member.user_id, "Changed");
    change["organizationId"] = json!(org);
    let refused = member.update_cipher(&id, &change).await;
    assert_eq!(refused.status, 400, "{}", refused.text());
    assert_eq!(
        message_of(&refused.json()).as_deref(),
        Some("Cipher is not write accessible")
    );
}

#[tokio::test]
async fn policies_are_set_listed_read_and_synced_to_members() {
    let owner = fresh_session().await;
    let member = fresh_session().await;
    let (org, _) = organization(&owner).await;
    add_member(&owner, &org, &member).await;

    let set = owner
        .put(
            &format!("/api/organizations/{org}/policies/3"),
            &json!({"policy": {"enabled": true, "data": null}}),
        )
        .await
        .ok_json("PUT policy");
    assert_eq!(set["object"], json!("policy"));
    assert_eq!(set["type"], json!(3));
    assert_eq!(set["enabled"], json!(true));
    assert_eq!(set["organizationId"], json!(org));

    let list = owner
        .get(&format!("/api/organizations/{org}/policies"))
        .await
        .ok_json("GET policies");
    assert_eq!(list["data"][0]["type"], json!(3));
    let blank = owner
        .get(&format!("/api/organizations/{org}/policies/0"))
        .await
        .ok_json("GET policy");
    assert_eq!(blank["enabled"], json!(false), "a policy nobody set is off");

    let unknown = owner
        .put(
            &format!("/api/organizations/{org}/policies/9"),
            &json!({"policy": {"enabled": true, "data": null}}),
        )
        .await;
    assert_eq!(unknown.status, 400);
    assert_eq!(
        message_of(&unknown.json()).as_deref(),
        Some("Invalid or unsupported policy type")
    );

    let synced = member.sync().await;
    assert_eq!(synced["policies"][0]["type"], json!(3));
    assert_eq!(synced["policies"][0]["enabled"], json!(true));

    let refused = member
        .put(
            &format!("/api/organizations/{org}/policies/0"),
            &json!({"policy": {"enabled": true, "data": null}}),
        )
        .await;
    assert_eq!(refused.status, 401);
}

#[tokio::test]
async fn require_sso_is_a_policy_type_of_this_server() {
    // Vaultwarden has no Require SSO policy; this server serves it so Bitwarden apps enforce it.
    if stand_aside_on_vaultwarden("Require SSO is a policy type only Kemlock Server serves") {
        return;
    }
    let owner = fresh_session().await;
    let (org, _) = organization(&owner).await;
    let set = owner
        .put(
            &format!("/api/organizations/{org}/policies/4"),
            &json!({"policy": {"enabled": true, "data": null}}),
        )
        .await
        .ok_json("PUT Require SSO");
    assert_eq!(set["type"], json!(4));
    assert_eq!(set["enabled"], json!(true));
}

#[tokio::test]
async fn members_are_revoked_restored_and_removed() {
    let owner = fresh_session().await;
    let member = fresh_session().await;
    let (org, _) = organization(&owner).await;
    add_member(&owner, &org, &member).await;
    let id = member_id(&owner, &org, &member).await;

    let reply = owner
        .put_empty(&format!("/api/organizations/{org}/users/{id}/revoke"))
        .await;
    assert!(reply.is_success(), "{} {}", reply.status, reply.text());
    let list = owner
        .get(&format!("/api/organizations/{org}/users"))
        .await
        .ok_json("GET users");
    let row = list["data"]
        .as_array()
        .and_then(|all| all.iter().find(|m| m["id"] == json!(id)))
        .expect("a revoked member is still listed");
    assert_eq!(row["status"], json!(-1));
    assert_eq!(member.sync().await["profile"]["organizations"], json!([]));

    let again = owner
        .put_empty(&format!("/api/organizations/{org}/users/{id}/revoke"))
        .await;
    assert_eq!(again.status, 400);
    assert_eq!(
        message_of(&again.json()).as_deref(),
        Some("User is already revoked")
    );

    let reply = owner
        .put_empty(&format!("/api/organizations/{org}/users/{id}/restore"))
        .await;
    assert!(reply.is_success(), "{} {}", reply.status, reply.text());
    assert_eq!(
        member.sync().await["profile"]["organizations"][0]["status"],
        json!(2)
    );

    let leave = owner
        .send(owner.call("POST", &format!("/api/organizations/{org}/leave")))
        .await;
    assert_eq!(leave.status, 400);
    assert_eq!(
        message_of(&leave.json()).as_deref(),
        Some("The last owner can't leave")
    );

    let removed = owner
        .delete(&format!("/api/organizations/{org}/users/{id}"))
        .await;
    assert!(
        removed.is_success(),
        "{} {}",
        removed.status,
        removed.text()
    );
    assert_eq!(member.sync().await["profile"]["organizations"], json!([]));
}
