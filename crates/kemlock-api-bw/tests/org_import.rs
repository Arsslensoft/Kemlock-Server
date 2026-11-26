//! Importing ciphers into an organization (`POST /api/ciphers/import-organization`) through the
//! router, with Vaultwarden 1.37.5's rules about who may use which collection.

mod common;

use axum::http::StatusCode;
use common::{Harness, login_request};
use kemlock_domain::UserId;
use serde_json::{Value, json};

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";

struct Fixture {
    h: Harness,
    ada: String,
    ada_id: UserId,
    bob: String,
    carol: String,
    eve: String,
    org: String,
    collection: String,
}

async fn fixture() -> Fixture {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (carol, carol_id) = h.signed_in("carol@example.com").await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(&ada),
            Some(json!({
                "name": "Import organization",
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": ORG_KEY,
                "keys": {"publicKey": "MIIBIjANorg", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let org = org["id"].as_str().expect("an id").to_owned();
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    let collection = synced["collections"][0]["id"]
        .as_str()
        .expect("a collection")
        .to_owned();

    // Bob may write the default collection; Carol has no collection at all.
    for (id, email, grants) in [
        (
            bob_id,
            "bob@example.com",
            json!([{"id": collection, "readOnly": false, "hidePasswords": false}]),
        ),
        (carol_id, "carol@example.com", json!([])),
    ] {
        let (status, body) = h
            .json(
                "POST",
                &format!("/api/organizations/{org}/users/invite"),
                Some(&ada),
                Some(json!({"emails": [email], "type": 2, "collections": grants, "groups": []})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        h.accept_in_space(&org, id).await;
        let (status, body) = h
            .json(
                "POST",
                &format!("/api/organizations/{org}/users/{id}/confirm"),
                Some(&ada),
                Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    Fixture {
        h,
        ada,
        ada_id,
        bob,
        carol,
        eve,
        org,
        collection,
    }
}

async fn import(f: &Fixture, token: &str, body: Value) -> (StatusCode, Value) {
    f.h.json(
        "POST",
        &format!("/api/ciphers/import-organization?organizationId={}", f.org),
        Some(token),
        Some(body),
    )
    .await
}

async fn listed(f: &Fixture) -> Vec<Value> {
    let (status, page) =
        f.h.json(
            "GET",
            &format!("/api/ciphers/organization-details?organizationId={}", f.org),
            Some(&f.ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["data"].as_array().expect("a list").clone()
}

#[tokio::test]
async fn an_admin_imports_ciphers_into_new_and_existing_collections() {
    let f = fixture().await;
    let (status, body) = import(
        &f,
        &f.ada,
        json!({
            "ciphers": [
                login_request(f.ada_id, "2.one"),
                login_request(f.ada_id, "2.two"),
                login_request(f.ada_id, "2.three")
            ],
            "collections": [
                {"name": "2.newcollection|x|y", "id": null, "externalId": "ext-1"},
                {"name": "2.defaultcollection|name|mac", "id": f.collection}
            ],
            "collectionRelationships": [
                {"key": 0, "value": 0},
                {"key": 1, "value": 1},
                {"key": 1, "value": 0}
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A new collection beside the default one, with the directory's id on it.
    let (_, collections) =
        f.h.json(
            "GET",
            &format!("/api/organizations/{}/collections/details", f.org),
            Some(&f.ada),
            None,
        )
        .await;
    let rows = collections["data"].as_array().expect("a list");
    assert_eq!(rows.len(), 2, "the default one wasn't made again");
    let made = rows
        .iter()
        .find(|c| c["name"] == "2.newcollection|x|y")
        .expect("the new collection");
    assert_eq!(made["externalId"], "ext-1");
    let made_id = made["id"].as_str().expect("an id").to_owned();

    // Every cipher is the organization's, in the collections the relationships say.
    let ciphers = listed(&f).await;
    assert_eq!(ciphers.len(), 3);
    for cipher in &ciphers {
        assert_eq!(cipher["organizationId"], f.org.as_str());
        let name = cipher["name"].as_str().expect("a name");
        let mut in_collections: Vec<String> = cipher["collectionIds"]
            .as_array()
            .expect("ids")
            .iter()
            .map(|c| c.as_str().expect("an id").to_owned())
            .collect();
        in_collections.sort();
        let mut wanted = match name {
            "2.one" => vec![made_id.clone()],
            "2.two" => vec![made_id.clone(), f.collection.clone()],
            _ => Vec::new(),
        };
        wanted.sort();
        assert_eq!(in_collections, wanted, "{name}");
    }
}

#[tokio::test]
async fn nothing_is_imported_when_a_relationship_names_nothing() {
    let f = fixture().await;
    let (status, body) = import(
        &f,
        &f.ada,
        json!({
            "ciphers": [login_request(f.ada_id, "2.one")],
            "collections": [{"name": "2.new|x|y", "id": null}],
            "collectionRelationships": [{"key": 4, "value": 0}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid collection relationship");
    assert!(listed(&f).await.is_empty());

    // A cipher that doesn't validate is refused whole.
    let mut bad = login_request(f.ada_id, "2.bad");
    bad["passwordHistory"] = json!([{"password": null, "lastUsedDate": "2026-01-01T00:00:00Z"}]);
    let (status, body) = import(
        &f,
        &f.ada,
        json!({"ciphers": [bad], "collections": [], "collectionRelationships": []}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "The model state is invalid.");
    assert!(listed(&f).await.is_empty());
}

#[tokio::test]
async fn a_member_imports_only_into_collections_they_may_write() {
    let f = fixture().await;
    let one = |name: &str| login_request(f.ada_id, name);

    // Bob may write the default collection, and may not make one.
    let (status, body) = import(
        &f,
        &f.bob,
        json!({
            "ciphers": [one("2.new")],
            "collections": [{"name": "2.new|x|y", "id": null}],
            "collectionRelationships": [{"key": 0, "value": 0}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "The current user isn't allowed to create new collections"
    );
    let (status, body) = import(
        &f,
        &f.bob,
        json!({
            "ciphers": [one("2.mine")],
            "collections": [{"name": "2.defaultcollection|name|mac", "id": f.collection}],
            "collectionRelationships": [{"key": 0, "value": 0}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ciphers = listed(&f).await;
    assert_eq!(ciphers.len(), 1);
    assert_eq!(ciphers[0]["collectionIds"], json!([f.collection]));

    // Carol has no access to it.
    let (status, body) = import(
        &f,
        &f.carol,
        json!({
            "ciphers": [one("2.hers")],
            "collections": [{"name": "2.defaultcollection|name|mac", "id": f.collection}],
            "collectionRelationships": [{"key": 0, "value": 0}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "The current user isn't allowed to manage this collection"
    );
    assert_eq!(listed(&f).await.len(), 1);

    // Someone outside the organization is turned away at the guard.
    let (status, _) = import(
        &f,
        &f.eve,
        json!({"ciphers": [], "collections": [], "collectionRelationships": []}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
