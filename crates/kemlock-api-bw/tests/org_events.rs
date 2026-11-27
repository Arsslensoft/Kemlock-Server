//! Organization events through the router: what organization actions record when events are on,
//! and what the three event lists answer, in Vaultwarden 1.37.5's shapes.
//!
//! The clock moves between actions so the events have distinct times: the lists order by time.

mod common;

use axum::http::StatusCode;
use common::{Harness, login_request};
use kemlock_app::event_reader::{EventQuery, EventReader};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use time::Duration;

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";
const RANGE: &str = "start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z";

fn org_body() -> Value {
    json!({
        "name": "Events organization",
        "billingEmail": "billing@example.com",
        "planType": 0,
        "key": ORG_KEY,
        "keys": {
            "publicKey": "MIIBIjANorganizationpublickey",
            "encryptedPrivateKey": "2.orgprivate|key|mac"
        },
        "collectionName": "2.defaultcollection|name|mac"
    })
}

async fn events_on() -> Harness {
    Harness::with(|settings| settings.org_events_enabled = true).await
}

/// An organization of one: its id and its default collection's.
async fn organization(h: &Harness, owner: &str) -> (String, String) {
    let (status, org) = h
        .json("POST", "/api/organizations", Some(owner), Some(org_body()))
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let id = org["id"].as_str().expect("an id").to_owned();
    let (_, synced) = h.json("GET", "/api/sync", Some(owner), None).await;
    let collection = synced["collections"][0]["id"]
        .as_str()
        .expect("a collection")
        .to_owned();
    (id, collection)
}

/// Invites `email` as a plain member and, a second later, confirms them.
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
    h.env.advance(Duration::seconds(1));
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

async fn list(h: &Harness, token: &str, uri: &str) -> Value {
    let (status, page) = h.json("GET", uri, Some(token), None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page
}

fn types(page: &Value) -> Vec<i64> {
    page["data"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|e| e["type"].as_i64().expect("a type"))
        .collect()
}

async fn rename_collection(h: &Harness, token: &str, org: &str, collection: &str, name: &str) {
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/collections/{collection}"),
            Some(token),
            Some(json!({"name": name, "groups": [], "users": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn organization_actions_are_listed_newest_first_with_their_sources() {
    let h = events_on().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (_, bob_id) = h.signed_in("bob@example.com").await;
    let (org, collection) = organization(&h, &ada).await;

    h.env.advance(Duration::minutes(1));
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;
    h.env.advance(Duration::minutes(1));
    rename_collection(&h, &ada, &org, &collection, "2.renamed|name|mac").await;

    let page = list(
        &h,
        &ada,
        &format!("/api/organizations/{org}/events?{RANGE}"),
    )
    .await;
    assert_eq!(page["object"], "list");
    assert!(page["continuationToken"].is_null());
    // Invited, confirmed, then the collection updated; newest first.
    assert_eq!(types(&page), [1301, 1501, 1500]);

    let newest = &page["data"][0];
    assert_eq!(newest["collectionId"], collection.as_str());
    assert_eq!(newest["organizationId"], org.as_str());
    assert_eq!(newest["actingUserId"], ada_id.to_string());
    assert!(newest["userId"].is_null());
    // Without a peer address the client is 0.0.0.0; the event keeps only its /24.
    assert_eq!(newest["ipAddress"], "0.0.0.0/24");
    assert_eq!(newest["deviceType"], 0);
    assert_eq!(newest["date"], "2026-11-21T12:02:01.000000Z");
    for key in [
        "cipherId",
        "groupId",
        "policyId",
        "providerId",
        "providerUserId",
        "providerOrganizationId",
    ] {
        assert!(newest[key].is_null(), "{key}");
    }
    let confirmed = &page["data"][1];
    assert_eq!(confirmed["organizationUserId"], bob_id.to_string());

    // The range cuts: nothing before the first action.
    let before = list(
        &h,
        &ada,
        &format!(
            "/api/organizations/{org}/events?start=2026-10-01T00:00:00Z&end=2026-11-01T00:00:00Z"
        ),
    )
    .await;
    assert_eq!(before["data"], json!([]));
}

#[tokio::test]
async fn a_members_events_are_about_them_or_by_them() {
    let h = events_on().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, _) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    // A member is not an admin: no list for them.
    let (status, _) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/events?{RANGE}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let page = list(
        &h,
        &ada,
        &format!("/api/organizations/{org}/users/{bob_id}/events?{RANGE}"),
    )
    .await;
    assert_eq!(types(&page), [1501, 1500]);

    // Revoking Bob is an event about Bob, made by Ada.
    h.env.advance(Duration::minutes(1));
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/organizations/{org}/users/{bob_id}/revoke"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page = list(
        &h,
        &ada,
        &format!("/api/organizations/{org}/users/{bob_id}/events?{RANGE}"),
    )
    .await;
    assert_eq!(types(&page), [1511, 1501, 1500]);

    // Someone who isn't a member of the organization has no events in it.
    let stranger = UserId::random();
    let page = list(
        &h,
        &ada,
        &format!("/api/organizations/{org}/users/{stranger}/events?{RANGE}"),
    )
    .await;
    assert_eq!(page["data"], json!([]));
}

#[tokio::test]
async fn a_ciphers_events_go_to_the_admins_of_its_organization() {
    let h = events_on().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (org, collection) = organization(&h, &ada).await;
    add_member(&h, &ada, &org, bob_id, "bob@example.com").await;

    h.env.advance(Duration::minutes(1));
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
    let id = created["id"].as_str().expect("an id").to_owned();

    // Trash it and bring it back.
    for (method, uri) in [
        ("PUT", format!("/api/ciphers/{id}/delete")),
        ("PUT", format!("/api/ciphers/{id}/restore")),
    ] {
        h.env.advance(Duration::minutes(1));
        let (status, body) = h.json(method, &uri, Some(&ada), None).await;
        assert_eq!(status, StatusCode::OK, "{method} {uri}: {body}");
    }

    let page = list(&h, &ada, &format!("/api/ciphers/{id}/events?{RANGE}")).await;
    assert_eq!(types(&page), [1116, 1115, 1100]);
    assert_eq!(page["data"][0]["cipherId"], id.as_str());
    assert_eq!(page["data"][0]["organizationId"], org.as_str());

    // Deleting it for good is the next event.
    h.env.advance(Duration::minutes(1));
    let (status, body) = h
        .json("DELETE", &format!("/api/ciphers/{id}"), Some(&ada), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, org_page) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/events?{RANGE}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(types(&org_page)[0], 1102);

    // A plain member and a cipher that isn't in any organization both get an empty page.
    let page = list(&h, &bob, &format!("/api/ciphers/{id}/events?{RANGE}")).await;
    assert_eq!(page["data"], json!([]));
    let (status, personal) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&ada),
            Some(login_request(ada_id, "2.mine")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{personal}");
    let mine = personal["id"].as_str().expect("an id");
    let page = list(&h, &ada, &format!("/api/ciphers/{mine}/events?{RANGE}")).await;
    assert_eq!(page["data"], json!([]));
}

#[tokio::test]
async fn a_full_page_carries_the_date_of_its_last_event_as_the_continuation_token() {
    let h = events_on().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (org, collection) = organization(&h, &ada).await;
    // Thirty-one updates, a minute apart: more than a page.
    for i in 0..31 {
        h.env.advance(Duration::minutes(1));
        rename_collection(&h, &ada, &org, &collection, &format!("2.n{i}|x|y")).await;
    }
    let uri = format!("/api/organizations/{org}/events?{RANGE}");
    let page = list(&h, &ada, &uri).await;
    assert_eq!(page["data"].as_array().map(Vec::len), Some(30));
    let token = page["continuationToken"].as_str().expect("a token");
    assert_eq!(token, page["data"][29]["date"].as_str().expect("a date"));

    // The token is the end of the next page, whose range includes that date: the last event of
    // the first page comes again, then the one that didn't fit, as Vaultwarden's lists do.
    let next = list(&h, &ada, &format!("{uri}&continuationToken={token}")).await;
    assert_eq!(next["data"].as_array().map(Vec::len), Some(2));
    assert_eq!(next["data"][0]["date"], token);
    assert!(next["continuationToken"].is_null());
}

#[tokio::test]
async fn nothing_is_recorded_while_events_are_off() {
    let h = Harness::new().await;
    let (ada, _) = h.signed_in("ada@example.com").await;
    let (org, collection) = organization(&h, &ada).await;
    rename_collection(&h, &ada, &org, &collection, "2.renamed|name|mac").await;

    let stored = h
        .store
        .read_events(&EventQuery::new(
            "bw.event",
            h.env.time() - Duration::days(1),
            h.env.time() + Duration::days(1),
            100,
        ))
        .await
        .expect("read");
    assert!(stored.is_empty());
    let page = list(
        &h,
        &ada,
        &format!("/api/organizations/{org}/events?{RANGE}"),
    )
    .await;
    assert_eq!(page["data"], json!([]));
}
