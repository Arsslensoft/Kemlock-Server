//! The organization API key and the public API's import through the router: what Bitwarden's
//! Directory Connector does, in the shapes of Vaultwarden 1.37.5.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use serde_json::{Value, json};

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";

async fn organization(h: &Harness, owner: &str) -> String {
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(owner),
            Some(json!({
                "name": "Directory organization",
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

async fn api_key(h: &Harness, owner: &str, org: &str, route: &str) -> Value {
    let (status, key) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/{route}"),
            Some(owner),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    key
}

/// The token request of the Directory Connector.
async fn connector_token(h: &Harness, org: &str, secret: &str) -> (StatusCode, Value) {
    let client_id = format!("organization.{org}");
    h.token(&[
        ("grant_type", "client_credentials"),
        ("scope", "api.organization"),
        ("client_id", client_id.as_str()),
        ("client_secret", secret),
    ])
    .await
}

async fn members(h: &Harness, owner: &str, org: &str) -> Vec<Value> {
    let (status, page) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users"),
            Some(owner),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["data"].as_array().expect("a list").clone()
}

fn find<'a>(rows: &'a [Value], email: &str) -> Option<&'a Value> {
    rows.iter().find(|r| r["email"] == email)
}

#[tokio::test]
async fn the_owner_makes_reads_and_rotates_the_organization_api_key() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let org = organization(&h, &ada).await;

    let key = api_key(&h, &ada, &org, "api-key").await;
    assert_eq!(key["object"], "apiKey");
    let secret = key["apiKey"].as_str().expect("a key").to_owned();
    assert_eq!(secret.len(), 30);
    assert!(secret.bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(key["revisionDate"], "2026-11-21T12:00:00.000000Z");

    // Asking again gives the same key; rotating makes another, with a new date.
    assert_eq!(api_key(&h, &ada, &org, "api-key").await["apiKey"], secret);
    h.env.advance(time::Duration::minutes(5));
    let rotated = api_key(&h, &ada, &org, "rotate-api-key").await;
    assert_ne!(rotated["apiKey"], secret.as_str());
    assert_eq!(rotated["revisionDate"], "2026-11-21T12:05:00.000000Z");
    assert_eq!(api_key(&h, &ada, &org, "api-key").await, rotated);

    // The password is checked, and there must be one.
    let uri = format!("/api/organizations/{org}/api-key");
    let (status, body) = h
        .json(
            "POST",
            &uri,
            Some(&ada),
            Some(json!({"masterPasswordHash": "wrong"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = h.json("POST", &uri, Some(&ada), Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "No validation provided");
}

#[tokio::test]
async fn only_an_owner_has_the_key() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(
                json!({"emails": ["bob@example.com"], "type": 1, "collections": [], "groups": []}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.accept_in_space(&org, bob_id).await;
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An admin is not an owner.
    for route in ["api-key", "rotate-api-key"] {
        let (status, _) = h
            .json(
                "POST",
                &format!("/api/organizations/{org}/{route}"),
                Some(&bob),
                Some(json!({"masterPasswordHash": HASH})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}");
    }
}

#[tokio::test]
async fn the_connector_signs_in_with_the_key_and_is_refused_without_it() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let org = organization(&h, &ada).await;

    // No key yet: the client id is not one.
    let (status, body) = connector_token(&h, &org, "x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid client_id");

    let secret = api_key(&h, &ada, &org, "api-key").await["apiKey"]
        .as_str()
        .expect("a key")
        .to_owned();
    let (status, body) = connector_token(&h, &org, "wrong").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Incorrect client_secret");
    let (status, body) = h
        .token(&[
            ("grant_type", "client_credentials"),
            ("scope", "api.organization"),
            ("client_id", "user.x"),
            ("client_secret", secret.as_str()),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Malformed client_id");

    let (status, token) = connector_token(&h, &org, &secret).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    assert_eq!(token["scope"], "api.organization");
    assert_eq!(token["unofficialServer"], true);
    assert!(token["access_token"].as_str().is_some());
}

#[tokio::test]
async fn the_import_makes_members_and_groups_match_the_directory() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (_, bob_id) = h.signed_in("bob@example.com").await;
    let org = organization(&h, &ada).await;
    let secret = api_key(&h, &ada, &org, "api-key").await["apiKey"]
        .as_str()
        .expect("a key")
        .to_owned();
    let (_, token) = connector_token(&h, &org, &secret).await;
    let token = token["access_token"].as_str().expect("a token").to_owned();
    let import = |body: Value| {
        let (h, token) = (&h, token.clone());
        async move {
            h.json(
                "POST",
                "/api/public/organization/import",
                Some(&token),
                Some(body),
            )
            .await
        }
    };

    // Bob has an account and is invited, to accept for himself; Cleo has none and waits for her registration. Both
    // are in the group.
    let (status, body) = import(json!({
        "groups": [{"name": "Engineering", "externalId": "g1", "memberExternalIds": ["b1", "c1"]}],
        "members": [
            {"email": "Bob@Example.com", "externalId": "b1", "deleted": false},
            {"email": "cleo@example.com", "externalId": "c1", "deleted": false}
        ],
        "overwriteExisting": false
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = members(&h, &ada, &org).await;
    assert_eq!(rows.len(), 3);
    let bob = find(&rows, "bob@example.com").expect("bob is a member");
    assert_eq!(bob["status"], 0);
    assert_eq!(bob["type"], 2);
    assert_eq!(bob["externalId"], "b1");
    assert_eq!(bob["id"], bob_id.to_string());
    let cleo = find(&rows, "cleo@example.com").expect("cleo is invited");
    assert_eq!(cleo["status"], 0);
    assert_eq!(cleo["externalId"], "c1");

    // The group has Bob; Cleo is in it by her invitation and joins when she registers.
    let (_, groups) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/groups"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(groups["data"][0]["name"], "Engineering");
    assert_eq!(groups["data"][0]["externalId"], "g1");
    let group = groups["data"][0]["id"].as_str().expect("an id").to_owned();
    let (_, users) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/groups/{group}/users"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(users, json!([bob_id.to_string()]));
    let (_, listed) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/users?includeGroups=true"),
            Some(&ada),
            None,
        )
        .await;
    let listed = listed["data"].as_array().expect("a list").clone();
    let cleo = find(&listed, "cleo@example.com").expect("cleo");
    assert_eq!(cleo["groups"], json!([group]));

    // The same import again changes nothing and doesn't make a second group.
    let (status, _) = import(json!({
        "groups": [{"name": "Engineering", "externalId": "g1", "memberExternalIds": ["b1"]}],
        "members": [{"email": "bob@example.com", "externalId": "b1", "deleted": false}],
        "overwriteExisting": false
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(members(&h, &ada, &org).await.len(), 3);
    let (_, groups) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/groups"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(groups["data"].as_array().map(Vec::len), Some(1));

    // A member the directory deleted is revoked; overwriting drops who it doesn't list, but not
    // the owner, who was never imported.
    let (status, body) = import(json!({
        "groups": [],
        "members": [{"email": "bob@example.com", "externalId": "b1", "deleted": true}],
        "overwriteExisting": true
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = members(&h, &ada, &org).await;
    assert_eq!(rows.len(), 2, "Cleo is gone");
    assert_eq!(find(&rows, "bob@example.com").expect("bob")["status"], -1);
    assert_eq!(
        find(&rows, "ada@example.com").expect("ada")["id"],
        ada_id.to_string()
    );
    assert!(find(&rows, "cleo@example.com").is_none());

    // Listing him again restores him.
    let (status, _) = import(json!({
        "groups": [],
        "members": [{"email": "bob@example.com", "externalId": "b1", "deleted": false}],
        "overwriteExisting": false
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = members(&h, &ada, &org).await;
    assert_eq!(find(&rows, "bob@example.com").expect("bob")["status"], 0);
}

#[tokio::test]
async fn the_public_api_takes_only_the_organizations_token() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let org = organization(&h, &ada).await;
    let body = json!({"groups": [], "members": [], "overwriteExisting": false});
    let uri = "/api/public/organization/import";

    // No token, an account's own token, and garbage are all a 401.
    let (status, _) = h.json("POST", uri, None, Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.json("POST", uri, Some(&ada), Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.json("POST", uri, Some("a.b.c"), Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let secret = api_key(&h, &ada, &org, "api-key").await["apiKey"]
        .as_str()
        .expect("a key")
        .to_owned();
    let (_, token) = connector_token(&h, &org, &secret).await;
    let token = token["access_token"].as_str().expect("a token").to_owned();
    let (status, _) = h.json("POST", uri, Some(&token), Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK);

    // The body must be complete, and a token lasts an hour.
    let (status, _) = h
        .json("POST", uri, Some(&token), Some(json!({"groups": []})))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    h.env.advance(time::Duration::minutes(61));
    let (status, _) = h.json("POST", uri, Some(&token), Some(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rotating_the_key_ends_the_tokens_made_with_the_old_one() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let org = organization(&h, &ada).await;
    let old = api_key(&h, &ada, &org, "api-key").await["apiKey"]
        .as_str()
        .expect("a key")
        .to_owned();
    let (_, token) = connector_token(&h, &org, &old).await;
    let token = token["access_token"].as_str().expect("a token").to_owned();
    let public = |token: String| {
        let h = &h;
        async move {
            h.json(
                "POST",
                "/api/public/organization/import",
                Some(&token),
                Some(json!({"groups": [], "members": [], "overwriteExisting": false})),
            )
            .await
            .0
        }
    };
    assert_eq!(public(token.clone()).await, StatusCode::OK);

    let rotated = api_key(&h, &ada, &org, "rotate-api-key").await["apiKey"]
        .as_str()
        .expect("a key")
        .to_owned();
    // The old token is refused at once, though it had most of its hour left.
    assert_eq!(public(token).await, StatusCode::UNAUTHORIZED);
    // A new sign-in with the new key works.
    let (status, fresh) = connector_token(&h, &org, &rotated).await;
    assert_eq!(status, StatusCode::OK, "{fresh}");
    assert_eq!(
        public(fresh["access_token"].as_str().expect("a token").to_owned()).await,
        StatusCode::OK
    );
}
