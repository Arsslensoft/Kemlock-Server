//! Organizations through the router: creation, members, collections, groups, policies and the
//! ciphers of an organization, in the shapes Vaultwarden 1.37.5 answers.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{HASH, Harness, USER_KEY, login_request};
use kemlock_api_bw::OrgMembership;
use kemlock_app::sso::{MembershipFacts, SpaceRole};
use kemlock_domain::UserId;
use serde_json::{Value, json};

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";

fn org_body(name: &str) -> Value {
    json!({
        "name": name,
        "billingEmail": "Billing@Example.com",
        "planType": 0,
        "key": ORG_KEY,
        "keys": {
            "publicKey": "MIIBIjANorganizationpublickey",
            "encryptedPrivateKey": "2.orgprivate|key|mac"
        },
        "collectionName": "2.defaultcollection|name|mac"
    })
}

async fn get(h: &Harness, token: &str, uri: &str) -> (StatusCode, Value) {
    h.json("GET", uri, Some(token), None).await
}

async fn sync(h: &Harness, token: &str) -> Value {
    let (status, body) = get(h, token, "/api/sync").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// An organization of one: its id and its default collection's.
async fn organization(h: &Harness, owner: &str) -> (String, String) {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(org_body("Contract organization")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let id = org["id"].as_str().expect("an id").to_owned();
    let collections = sync(h, owner).await["collections"].clone();
    let collection = collections[0]["id"]
        .as_str()
        .expect("a collection")
        .to_owned();
    (id, collection)
}

/// Invites `email` as a plain member and confirms them with `key`; returns nothing but leaves them
/// a confirmed member.
async fn add_member(h: &Harness, owner: &str, org: &str, member: UserId, email: &str) {
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(owner),
            Some(json!({"emails": [email], "type": 2, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.accept_in_space(&org, member).await;
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

/// What Require SSO needs before it can be turned on: the server has a provider, and the
/// organization has Single organization on.
async fn sso_prerequisites(h: &Harness, owner: &str, org: &str) {
    h.configure_sso().await;
    for ptype in [3] {
        let (status, body) = h
            .json(
                "PUT",
                &format!("/api/organizations/{org}/policies/{ptype}"),
                Some(owner),
                Some(json!({"policy": {"enabled": true, "data": null}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn creating_an_organization_answers_as_vaultwarden_does() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (stranger, _) = h.signed_in("eve@example.com").await;

    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(&ada),
            Some(org_body("Contract organization")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    assert_eq!(org["object"], "organization");
    assert_eq!(org["name"], "Contract organization");
    assert_eq!(org["billingEmail"], "billing@example.com");
    assert_eq!(org["planType"], 6);
    assert_eq!(org["maxStorageGb"], 32_767);
    assert_eq!(org["useGroups"], true);
    assert_eq!(org["useEvents"], false);
    assert_eq!(org["useSso"], false);
    assert_eq!(org["hasPublicAndPrivateKeys"], true);
    assert_eq!(org["usersGetPremium"], true);
    let id = org["id"].as_str().expect("an id");

    let synced = sync(&h, &ada).await;
    let mine = &synced["profile"]["organizations"][0];
    assert_eq!(mine["object"], "profileOrganization");
    assert_eq!(mine["id"], id);
    assert_eq!(mine["key"], ORG_KEY);
    assert_eq!(mine["status"], 2);
    assert_eq!(mine["type"], 0);
    assert_eq!(mine["enabled"], true);
    assert_eq!(mine["userId"], ada_id.to_string());
    assert_eq!(mine["organizationUserId"], ada_id.to_string());
    assert_eq!(mine["permissions"]["createNewCollections"], false);
    assert_eq!(synced["profile"]["organizationsNew"][0]["id"], id);

    let collection = &synced["collections"][0];
    assert_eq!(collection["object"], "collectionDetails");
    assert_eq!(collection["organizationId"], id);
    assert_eq!(collection["name"], "2.defaultcollection|name|mac");
    assert_eq!(collection["readOnly"], false);
    assert_eq!(collection["hidePasswords"], false);
    assert_eq!(collection["manage"], true);
    assert_eq!(collection["type"], 0);

    let (status, read) = get(&h, &ada, &format!("/api/organizations/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["id"], id);
    // Someone outside the organization is turned away at the guard, with nothing to read.
    let (status, _) = get(&h, &stranger, &format!("/api/organizations/{id}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, none) = get(&h, &stranger, "/api/sync").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(none["profile"]["organizations"], json!([]));
    assert_eq!(none["collections"], json!([]));

    // A bad billing address is refused with Vaultwarden's words.
    let mut bad = org_body("Second");
    bad["billingEmail"] = json!("nonsense");
    let (status, body) = h
        .json("POST", "/api/organizations", Some(&ada), Some(bad))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "BillingEmail nonsense is not a valid email address"
    );

    let (status, listed) = get(&h, &ada, "/api/collections").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["object"], "list");
    assert_eq!(listed["data"][0]["object"], "collection");
}

#[tokio::test]
async fn an_invited_member_is_confirmed_and_then_sees_the_organization() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(
                json!({"emails": ["Bob@Example.com"], "type": 2, "collections": [], "groups": []}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The same address again is refused.
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(
                json!({"emails": ["bob@example.com"], "type": 2, "collections": [], "groups": []}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "User already in organization: bob@example.com"
    );

    let (_, members) = get(&h, &ada, &format!("/api/organizations/{org}/users")).await;
    assert_eq!(members["object"], "list");
    let rows = members["data"].as_array().expect("a list");
    assert_eq!(rows.len(), 2);
    let row = rows
        .iter()
        .find(|m| m["email"] == "bob@example.com")
        .expect("bob is listed");
    assert_eq!(row["object"], "organizationUserUserDetails");
    assert_eq!(row["id"], bob_id.to_string());
    assert_eq!(row["userId"], bob_id.to_string());
    // An existing account is invited, and stays so until it accepts: nobody is put into an
    // organization they have not agreed to join.
    assert_eq!(row["status"], 0);
    assert_eq!(row["type"], 2);
    assert_eq!(row["name"], "Kemlock test");
    assert_eq!(row["twoFactorEnabled"], false);
    assert_eq!(row["hasMasterPassword"], true);
    assert!(row["permissions"].is_null());

    let before = sync(&h, &bob).await;
    assert_eq!(before["profile"]["organizations"], json!([]));
    assert_eq!(before["profile"]["organizationsNew"][0]["status"], 0);
    assert!(before["profile"]["organizationsNew"][0]["key"].is_null());

    // No one can confirm an invitation nobody accepted.
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.bobskey"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "User in invalid state");

    // Bob accepts with the link of the invitation.
    let token = h.invite_token(&org, bob_id, "bob@example.com");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/accept"),
            Some(&bob),
            Some(json!({"token": token})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let accepted = sync(&h, &bob).await;
    assert_eq!(accepted["profile"]["organizationsNew"][0]["status"], 1);

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.bobskey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = sync(&h, &bob).await;
    let joined = &after["profile"]["organizations"][0];
    assert_eq!(joined["key"], "4.bobskey");
    assert_eq!(joined["status"], 2);
    assert_eq!(joined["type"], 2);
    assert_eq!(joined["limitCollectionCreation"], true);
    assert_eq!(after["collections"], json!([]));

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.again"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "User in invalid state");

    // A member sees the member list through no guard but the manager's.
    let (status, _) = get(&h, &bob, &format!("/api/organizations/{org}/users")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/4"),
            Some(&bob),
            Some(json!({"policy": {"enabled": true, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, mini) = get(
        &h,
        &ada,
        &format!("/api/organizations/{org}/users/mini-details"),
    )
    .await;
    assert_eq!(mini["data"][0]["object"], "organizationUserUserMiniDetails");
}

#[tokio::test]
async fn a_collection_grant_decides_what_a_member_sees_and_may_do() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    let (status, made) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/collections"),
            Some(&ada),
            Some(json!({
                "name": "2.shared|name|mac",
                "groups": [],
                "users": [{"id": bob_id.to_string(), "readOnly": true, "hidePasswords": true, "manage": false}],
                "externalId": ""
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert_eq!(made["object"], "collectionDetails");
    assert!(made["externalId"].is_null(), "an empty external id is none");
    let collection = made["id"].as_str().expect("an id").to_owned();

    let synced = sync(&h, &bob).await;
    let seen = synced["collections"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|c| c["id"] == collection.as_str())
        .expect("bob sees the collection he was given");
    assert_eq!(seen["readOnly"], true);
    assert_eq!(seen["hidePasswords"], true);
    assert_eq!(seen["manage"], false);
    assert_eq!(synced["collections"].as_array().map(Vec::len), Some(1));

    // Ada makes a cipher in it, as the web vault does.
    let mut cipher = login_request(ada_id, "2.shared login");
    cipher["organizationId"] = json!(org);
    let (status, created) = h
        .json(
            "POST",
            "/api/ciphers/create",
            Some(&ada),
            Some(json!({"cipher": cipher, "collectionIds": [collection]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["object"], "cipherDetails");
    assert_eq!(created["organizationId"], org.as_str());
    assert_eq!(created["collectionIds"], json!([collection]));
    assert_eq!(created["edit"], true);
    let id = created["id"].as_str().expect("an id").to_owned();

    // Bob reads it but may not change it, nor see its passwords.
    let bob_view = sync(&h, &bob).await["ciphers"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|c| c["id"] == id.as_str())
        .cloned()
        .expect("bob's sync has the cipher");
    assert_eq!(bob_view["organizationId"], org.as_str());
    assert_eq!(bob_view["collectionIds"], json!([collection]));
    assert_eq!(bob_view["edit"], false);
    assert_eq!(bob_view["viewPassword"], false);
    assert_eq!(
        bob_view["permissions"],
        json!({"delete": false, "restore": false})
    );
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&bob),
            Some({
                let mut change = login_request(bob_id, "2.bobs edit");
                change["organizationId"] = json!(org);
                change
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher is not write accessible");
    let (status, body) = h
        .json("DELETE", &format!("/api/ciphers/{id}"), Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher can't be deleted by user");

    // Ada's edit moves bob's revision date, and an update that drops the organization is refused.
    let (_, before) = h
        .json("GET", "/api/accounts/revision-date", Some(&bob), None)
        .await;
    let mut edit = login_request(ada_id, "2.renamed");
    edit["organizationId"] = json!(org);
    let (status, edited) = h
        .json("PUT", &format!("/api/ciphers/{id}"), Some(&ada), Some(edit))
        .await;
    assert_eq!(status, StatusCode::OK, "{edited}");
    assert_eq!(edited["name"], "2.renamed");
    assert_eq!(edited["organizationId"], org.as_str());
    let (_, after) = h
        .json("GET", "/api/accounts/revision-date", Some(&bob), None)
        .await;
    assert!(after.as_i64() > before.as_i64());
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&ada),
            Some(login_request(ada_id, "2.no org")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Organization mismatch. Please resync the client before updating the cipher"
    );

    // Someone outside the organization can't read it.
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (status, body) = get(&h, &eve, &format!("/api/ciphers/{id}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher is not owned by user");

    // The cipher goes into a second collection.
    let (_, second) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/collections"),
            Some(&ada),
            Some(json!({"name": "2.second|name|mac", "groups": [], "users": []})),
        )
        .await;
    let second = second["id"].as_str().expect("an id").to_owned();
    let (status, moved) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}/collections"),
            Some(&ada),
            Some(json!({"collectionIds": [collection, second]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    let mut ids: Vec<String> = moved["collectionIds"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|c| c.as_str().expect("an id").to_owned())
        .collect();
    ids.sort();
    let mut want = vec![collection.clone(), second.clone()];
    want.sort();
    assert_eq!(ids, want);

    // Deleting a collection takes it out of the cipher, which stays.
    let (status, _) = h
        .json(
            "DELETE",
            &format!("/api/organizations/{org}/collections/{second}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, again) = get(&h, &ada, &format!("/api/ciphers/{id}")).await;
    assert_eq!(again["collectionIds"], json!([collection]));

    // The admin's list of the organization's ciphers.
    let (status, details) = get(
        &h,
        &ada,
        &format!("/api/ciphers/organization-details?organizationId={org}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{details}");
    assert_eq!(details["data"][0]["id"], id.as_str());
    assert!(details["data"][0].get("edit").is_none());
}

#[tokio::test]
async fn policies_are_set_read_and_served_to_members() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    sso_prerequisites(&h, &ada, &org).await;
    let (status, policy) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/4"),
            Some(&ada),
            Some(json!({"policy": {"enabled": true, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{policy}");
    assert_eq!(policy["object"], "policy");
    assert_eq!(policy["type"], 4);
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["organizationId"], org.as_str());
    assert!(policy["data"].is_null());
    assert!(policy.get("canToggleState").is_none());

    let (_, master) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/1"),
            Some(&ada),
            Some(json!({"policy": {"enabled": true, "data": {"minLength": 14}}})),
        )
        .await;
    assert_eq!(master["data"]["minLength"], 14);

    let (_, listed) = get(&h, &ada, &format!("/api/organizations/{org}/policies")).await;
    assert_eq!(listed["object"], "list");
    assert_eq!(listed["data"].as_array().map(Vec::len), Some(3));
    let (_, blank) = get(&h, &ada, &format!("/api/organizations/{org}/policies/7")).await;
    assert_eq!(blank["enabled"], false);
    assert!(blank["data"].is_null());
    let (status, body) = get(&h, &ada, &format!("/api/organizations/{org}/policies/9")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid or unsupported policy type");

    // Members get the policies in their sync, and read the master password one.
    let synced = sync(&h, &bob).await;
    assert_eq!(synced["policies"].as_array().map(Vec::len), Some(3));
    assert_eq!(synced["policiesNew"].as_array().map(Vec::len), Some(3));
    let (status, mine) = get(
        &h,
        &bob,
        &format!("/api/organizations/{org}/policies/master-password"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mine["data"]["minLength"], 14);

    // Require SSO binds the member, and not the owner.
    let facts = OrgMembership(h.store.clone());
    let bobs = facts.spaces_of(bob_id).await.expect("facts");
    assert_eq!(bobs.len(), 1);
    assert!(bobs[0].require_sso);
    assert_eq!(bobs[0].role, SpaceRole::Member);
    let owner = h
        .json("GET", "/api/accounts/profile", Some(&ada), None)
        .await
        .1["id"]
        .as_str()
        .and_then(|id| id.parse::<UserId>().ok())
        .expect("an id");
    let owners = facts.spaces_of(owner).await.expect("facts");
    assert_eq!(owners[0].role, SpaceRole::Owner);
}

#[tokio::test]
async fn members_are_revoked_restored_and_removed_by_vaultwardens_rules() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{ada_id}/revoke"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "You cannot revoke yourself");

    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/revoke"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, members) = get(&h, &ada, &format!("/api/organizations/{org}/users")).await;
    let row = members["data"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|m| m["email"] == "bob@example.com")
        .cloned()
        .expect("listed");
    assert_eq!(row["status"], -1);
    let gone = sync(&h, &bob).await;
    assert_eq!(gone["profile"]["organizations"], json!([]));
    assert_eq!(gone["profile"]["organizationsNew"], json!([]));
    let (status, _) = get(
        &h,
        &bob,
        &format!("/api/organizations/{org}/policies/master-password"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/revoke"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "User is already revoked");

    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/restore"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let back = sync(&h, &bob).await;
    assert_eq!(back["profile"]["organizations"][0]["status"], 2);
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/restore"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "User is already active");

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/leave"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "The last owner can't leave");

    let (status, _) = h
        .json(
            "DELETE",
            &format!("/api/organizations/{org}/users/{bob_id}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync(&h, &bob).await["profile"]["organizations"], json!([]));

    // The organization goes with its owner's password.
    let (status, body) = h
        .json(
            "DELETE",
            &format!("/api/organizations/{org}"),
            Some(&ada),
            Some(json!({"masterPasswordHash": "not the password"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = h
        .json(
            "DELETE",
            &format!("/api/organizations/{org}"),
            Some(&ada),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(sync(&h, &ada).await["profile"]["organizations"], json!([]));
    let (status, _) = get(&h, &ada, &format!("/api/organizations/{org}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_group_gives_its_members_its_collections() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, collection) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;
    assert_eq!(sync(&h, &bob).await["collections"], json!([]));

    let (status, group) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/groups"),
            Some(&ada),
            Some(json!({
                "name": "Ops",
                "accessAll": false,
                "externalId": null,
                "collections": [{"id": collection, "readOnly": false, "hidePasswords": false, "manage": false}],
                "users": [bob_id.to_string()]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["object"], "group");
    assert_eq!(group["name"], "Ops");
    assert_eq!(group["organizationId"], org.as_str());
    let group_id = group["id"].as_str().expect("an id").to_owned();

    let (_, details) = get(
        &h,
        &ada,
        &format!("/api/organizations/{org}/groups/details"),
    )
    .await;
    assert_eq!(details["data"][0]["object"], "groupDetails");
    assert_eq!(
        details["data"][0]["collections"][0]["id"],
        collection.as_str()
    );
    assert_eq!(details["data"][0]["collections"][0]["readOnly"], false);
    assert_eq!(details["data"][0]["collections"][0]["manage"], false);
    let (_, members) = get(
        &h,
        &ada,
        &format!("/api/organizations/{org}/groups/{group_id}/users"),
    )
    .await;
    assert_eq!(members, json!([bob_id.to_string()]));

    // Bob now has the collection through his group, with the right to edit.
    let seen = sync(&h, &bob).await["collections"][0].clone();
    assert_eq!(seen["id"], collection.as_str());
    assert_eq!(seen["readOnly"], false);

    let (status, _) = h
        .json(
            "DELETE",
            &format!("/api/organizations/{org}/groups/{group_id}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync(&h, &bob).await["collections"], json!([]));
    let (status, body) = get(
        &h,
        &ada,
        &format!("/api/organizations/{org}/groups/{group_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Group not found");
}

#[tokio::test]
async fn sharing_a_personal_cipher_moves_it_into_the_organization() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (org, collection) = organization(&h, &ada).await;

    let (status, personal) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&ada),
            Some(login_request(ada_id, "2.mine")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{personal}");
    let old = personal["id"].as_str().expect("an id").to_owned();

    let mut shared = login_request(ada_id, "2.mine");
    shared["organizationId"] = json!(org);
    let (status, moved) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{old}/share"),
            Some(&ada),
            Some(json!({"cipher": shared, "collectionIds": [collection]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["organizationId"], org.as_str());
    assert_eq!(moved["collectionIds"], json!([collection]));

    // Nothing is shared without a collection, nor into an organization the account isn't in.
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{old}/share"),
            Some(&ada),
            Some(json!({"cipher": login_request(ada_id, "2.x"), "collectionIds": [collection]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher OrganizationId is required.");

    let (_, all) = get(&h, &ada, "/api/ciphers").await;
    let rows = all["data"].as_array().expect("a list");
    assert_eq!(rows.len(), 1, "the personal copy is gone");
    assert_eq!(rows[0]["organizationId"], org.as_str());
}

#[tokio::test]
async fn an_invitation_to_an_unknown_address_waits_for_its_registration() {
    let h = Harness::with(|settings| settings.signups_allowed = false).await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (org, _) = organization(&h, &ada).await;

    // Closed sign-ups refuse an address nobody invited.
    let ask = |email: &'static str| {
        h.send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[("content-type", "application/json")],
            Body::from(json!({"email": email}).to_string()),
        )
    };
    let (status, _, _) = ask("new@example.com").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(
                json!({"emails": ["new@example.com"], "type": 2, "collections": [], "groups": []}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, members) = get(&h, &ada, &format!("/api/organizations/{org}/users")).await;
    let pending = members["data"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|m| m["email"] == "new@example.com")
        .cloned()
        .expect("the invitation is listed");
    assert_eq!(pending["status"], 0);
    assert!(pending["name"].is_null());

    let (status, _, bytes) = ask("new@example.com").await;
    assert_eq!(status, StatusCode::OK);
    let token = String::from_utf8(bytes).expect("a token");
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/finish",
            None,
            Some(json!({
                "email": "new@example.com", "masterPasswordHash": HASH,
                "kdf": 0, "kdfIterations": 600_000, "userSymmetricKey": USER_KEY,
                "keys": {"encryptedPrivateKey": "2.priv|key|mac", "publicKey": "MIIBIjAN"},
                "emailVerificationToken": token
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The new account is only invited: whoever registers an address is not proven to be the
    // person the organization invited, so they accept for themselves and an admin then confirms.
    let answer = h.login("new@example.com", HASH).await;
    let new_token = answer["access_token"].as_str().expect("a token").to_owned();
    let synced = sync(&h, &new_token).await;
    assert_eq!(synced["profile"]["organizations"], json!([]));
    assert_eq!(synced["profile"]["organizationsNew"][0]["id"], org.as_str());
    assert_eq!(synced["profile"]["organizationsNew"][0]["status"], 0);
    let (_, members) = get(&h, &ada, &format!("/api/organizations/{org}/users")).await;
    let joined = members["data"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|m| m["email"] == "new@example.com")
        .cloned()
        .expect("listed");
    assert_eq!(joined["status"], 0);
    let new_id = joined["id"].as_str().expect("an id");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{new_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.newkey"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "User in invalid state");
    let new_user: UserId = new_id.parse().expect("an account id");
    let link = h.invite_token(&org, new_user, "new@example.com");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{new_id}/accept"),
            Some(&new_token),
            Some(json!({"token": link})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{new_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.newkey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        sync(&h, &new_token).await["profile"]["organizations"][0]["key"],
        "4.newkey"
    );
}

#[tokio::test]
async fn require_sso_closes_the_password_to_members_and_not_to_owners() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (_, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    sso_prerequisites(&h, &ada, &org).await;
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/4"),
            Some(&ada),
            Some(json!({"policy": {"enabled": true, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Single sign-on is required for your organization. Sign in with SSO."
    );
    // The owner is exempt, so someone can always get in to fix the provider.
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Turning the policy off opens the password again.
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/4"),
            Some(&ada),
            Some(json!({"policy": {"enabled": false, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .token(&Harness::password_fields("bob@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn require_sso_closes_the_api_key_to_members_and_not_to_owners() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    let api_key = |token: String| {
        let h = &h;
        async move {
            let (_, body) = h
                .json(
                    "POST",
                    "/api/accounts/api-key",
                    Some(&token),
                    Some(json!({"masterPasswordHash": HASH})),
                )
                .await;
            body["apiKey"].as_str().expect("a key").to_owned()
        }
    };
    let (ada_key, bob_key) = (api_key(ada.clone()).await, api_key(bob.clone()).await);
    let sign_in = |id: UserId, key: String| {
        let h = &h;
        async move {
            let client_id = format!("user.{id}");
            h.token(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", key.as_str()),
                ("scope", "api"),
                ("deviceType", "8"),
                ("deviceIdentifier", "cli-1"),
                ("deviceName", "Amethystora Vault"),
            ])
            .await
        }
    };

    sso_prerequisites(&h, &ada, &org).await;
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/4"),
            Some(&ada),
            Some(json!({"policy": {"enabled": true, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = sign_in(bob_id, bob_key).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Single sign-on is required for your organization. Sign in with SSO."
    );
    // A wrong secret is just wrong: nothing about the account's spaces is said before the key.
    let (_, body) = sign_in(bob_id, "wrong".to_owned()).await;
    assert_eq!(body["message"], "Incorrect client_secret");
    // The owner is exempt.
    let (status, body) = sign_in(ada_id, ada_key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Invites `email` with `kind` (0 owner, 1 admin, 2 user) and confirms them.
async fn add_member_as(h: &Harness, owner: &str, org: &str, member: UserId, email: &str, kind: i32) {
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(owner),
            Some(json!({"emails": [email], "type": kind, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.accept_in_space(org, member).await;
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

#[tokio::test]
async fn an_admin_demoted_through_the_space_rows_loses_bitwarden_admin_access() {
    use kemlock_domain::spaces::SpaceRole as Role;
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member_as(&h, &ada, &org, bob_id, "bob@example.com", 1).await;
    let members = format!("/api/organizations/{org}/users");
    let (status, _) = get(&h, &bob, &members).await;
    assert_eq!(status, StatusCode::OK, "an admin lists the members");

    // The Kemlock API's role change touches only the space row.
    h.change_row(&org, bob_id, |row| row.role = Role::Member).await;
    let (status, _) = get(&h, &bob, &members).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no longer an admin here");
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/policies/3"),
            Some(&bob),
            Some(json!({"policy": {"enabled": true, "data": null}})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, listed) = get(&h, &ada, &members).await;
    let row = listed["data"]
        .as_array()
        .and_then(|rows| rows.iter().find(|m| m["email"] == "bob@example.com"))
        .expect("bob is listed");
    assert_eq!(row["type"], 2, "the owner sees the new role");
}

#[tokio::test]
async fn a_member_revoked_or_removed_through_the_space_rows_is_out_of_the_organization() {
    use kemlock_domain::spaces::MemberState;
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (cat, cat_id) = h.signed_in("cat@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member_as(&h, &ada, &org, bob_id, "bob@example.com", 1).await;
    add_member_as(&h, &ada, &org, cat_id, "cat@example.com", 1).await;
    let members = format!("/api/organizations/{org}/users");

    h.change_row(&org, bob_id, |row| row.state = MemberState::Revoked)
        .await;
    let (status, _) = get(&h, &bob, &members).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, listed) = get(&h, &ada, &members).await;
    let bobs = listed["data"]
        .as_array()
        .and_then(|rows| rows.iter().find(|m| m["email"] == "bob@example.com"))
        .expect("bob is still listed");
    assert_eq!(bobs["status"], -1);

    h.drop_row(&org, cat_id).await;
    let (status, _) = get(&h, &cat, &members).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(sync(&h, &cat).await["profile"]["organizations"], json!([]));
    let (_, listed) = get(&h, &ada, &members).await;
    assert_eq!(listed["data"].as_array().map(Vec::len), Some(2));
}
