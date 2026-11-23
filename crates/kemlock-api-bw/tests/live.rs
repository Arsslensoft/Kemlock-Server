//! What the Bitwarden API tells the live channels after each write: the events Vaultwarden's
//! `nt.send_*` calls correspond to, read from the recorder the harness installs.

mod common;

use axum::http::StatusCode;
use common::{Harness, claims, login_request};
use kemlock_app::bw_events::{BwEvent, Change, CipherEvent, FolderEvent, SendEvent, UserSync};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use uuid::Uuid;

/// The identifier the harness's sign-in names.
const APP_ID: &str = "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a";
const DELETE_IN_A_WEEK: &str = "2026-11-28T12:00:00.000Z";

fn app_id() -> Uuid {
    Uuid::parse_str(APP_ID).expect("a uuid")
}

fn cipher(event: &BwEvent) -> &CipherEvent {
    match event {
        BwEvent::Cipher(cipher) => cipher,
        other => panic!("not a cipher event: {other:?}"),
    }
}

fn folder(event: &BwEvent) -> &FolderEvent {
    match event {
        BwEvent::Folder(folder) => folder,
        other => panic!("not a folder event: {other:?}"),
    }
}

fn send_event(event: &BwEvent) -> &SendEvent {
    match event {
        BwEvent::Send(send) => send,
        other => panic!("not a Send event: {other:?}"),
    }
}

fn id_of(value: &Value) -> Uuid {
    Uuid::parse_str(value["id"].as_str().expect("an id")).expect("a uuid")
}

async fn create_cipher(h: &Harness, token: &str, user: UserId, name: &str) -> Uuid {
    let (status, body) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(token),
            Some(login_request(user, name)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    id_of(&body)
}

#[tokio::test]
async fn a_cipher_is_told_as_created_updated_trashed_restored_and_deleted() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    h.events.take();

    let id = create_cipher(&h, &token, user, "2.one").await;
    let events = h.events.take();
    assert_eq!(events.len(), 1);
    let created = cipher(&events[0]);
    assert_eq!(created.change, Change::Created);
    assert_eq!(created.id, id);
    assert_eq!(created.user, Some(user));
    assert_eq!(created.organization, None);
    assert_eq!(created.collections, None);
    assert_eq!(created.recipients, vec![user]);
    // The acting device is named by the identifier it signed in with, so it ignores its echo.
    let acting = created.device.expect("the acting device");
    assert_eq!(acting.identifier, Some(app_id()));

    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&token),
            Some(login_request(user, "2.two")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = h.events.take();
    assert_eq!(cipher(&events[0]).change, Change::Updated);

    h.json(
        "PUT",
        &format!("/api/ciphers/{id}/delete"),
        Some(&token),
        None,
    )
    .await;
    // A trashed cipher is an update, as in Vaultwarden.
    assert_eq!(cipher(&h.events.take()[0]).change, Change::Updated);

    h.json(
        "PUT",
        &format!("/api/ciphers/{id}/restore"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(cipher(&h.events.take()[0]).change, Change::Updated);

    h.json(
        "POST",
        &format!("/api/ciphers/{id}/delete"),
        Some(&token),
        None,
    )
    .await;
    let events = h.events.take();
    assert_eq!(events.len(), 1);
    assert_eq!(cipher(&events[0]).change, Change::Deleted);
    assert_eq!(cipher(&events[0]).id, id);
}

#[tokio::test]
async fn a_refused_write_tells_nobody() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    h.events.take();
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{}", Uuid::new_v4()),
            Some(&token),
            Some(login_request(user, "2.missing")),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert!(h.events.take().is_empty());
}

#[tokio::test]
async fn a_bulk_change_is_one_general_sync_not_a_message_per_cipher() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let a = create_cipher(&h, &token, user, "2.a").await;
    let b = create_cipher(&h, &token, user, "2.b").await;
    h.events.take();

    let (status, _) = h
        .json(
            "PUT",
            "/api/ciphers/delete",
            Some(&token),
            Some(json!({"ids": [a.to_string(), b.to_string()]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = h.events.take();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(matches!(
        &events[0],
        BwEvent::Sync { sync: UserSync::Ciphers, user: u, .. } if *u == user
    ));

    let (status, _) = h
        .json(
            "PUT",
            "/api/ciphers/restore",
            Some(&token),
            Some(json!({"ids": [a.to_string(), b.to_string()]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = h.events.take();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(matches!(
        &events[0],
        BwEvent::Sync {
            sync: UserSync::Ciphers,
            ..
        }
    ));
}

#[tokio::test]
async fn moving_one_cipher_is_told_as_that_cipher_and_moving_several_as_a_sync() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let a = create_cipher(&h, &token, user, "2.a").await;
    let b = create_cipher(&h, &token, user, "2.b").await;
    h.events.take();

    let (status, _) = h
        .json(
            "POST",
            "/api/ciphers/move",
            Some(&token),
            Some(json!({"folderId": "", "ids": [a.to_string()]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = h.events.take();
    assert_eq!(cipher(&events[0]).id, a);
    assert_eq!(cipher(&events[0]).change, Change::Updated);

    h.json(
        "POST",
        "/api/ciphers/move",
        Some(&token),
        Some(json!({"folderId": "", "ids": [a.to_string(), b.to_string()]})),
    )
    .await;
    let events = h.events.take();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        BwEvent::Sync {
            sync: UserSync::Ciphers,
            ..
        }
    ));
}

#[tokio::test]
async fn a_folder_is_told_as_created_renamed_and_deleted() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    h.events.take();

    let (_, made) = h
        .json(
            "POST",
            "/api/folders",
            Some(&token),
            Some(json!({"name": "2.folder"})),
        )
        .await;
    let id = id_of(&made);
    let events = h.events.take();
    let created = folder(&events[0]);
    assert_eq!(
        (created.change, created.id, created.user),
        (Change::Created, id, user)
    );
    assert_eq!(created.device.expect("a device").identifier, Some(app_id()));

    h.json(
        "PUT",
        &format!("/api/folders/{id}"),
        Some(&token),
        Some(json!({"name": "2.renamed"})),
    )
    .await;
    assert_eq!(folder(&h.events.take()[0]).change, Change::Updated);

    h.json("DELETE", &format!("/api/folders/{id}"), Some(&token), None)
        .await;
    let events = h.events.take();
    assert_eq!(events.len(), 1, "only the folder, not the ciphers it held");
    assert_eq!(folder(&events[0]).change, Change::Deleted);
    assert_eq!(folder(&events[0]).id, id);
}

#[tokio::test]
async fn an_import_is_a_vault_sync_and_the_equivalent_domains_are_a_settings_sync() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    h.events.take();

    let (status, body) = h
        .json(
            "POST",
            "/api/ciphers/import",
            Some(&token),
            Some(json!({
                "ciphers": [login_request(user, "2.imported")],
                "folders": [],
                "folderRelationships": [],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = h.events.take();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(matches!(
        &events[0],
        BwEvent::Sync {
            sync: UserSync::Vault,
            ..
        }
    ));

    let (status, _) = h
        .json(
            "PUT",
            "/api/settings/domains",
            Some(&token),
            Some(json!({
                "excludedGlobalEquivalentDomains": [],
                "equivalentDomains": [["a.example", "b.example"]],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        &h.events.take()[0],
        BwEvent::Sync {
            sync: UserSync::Settings,
            ..
        }
    ));
}

fn text_send(name: &str) -> Value {
    json!({
        "type": 0,
        "key": "2.key|iv|mac",
        "name": name,
        "notes": null,
        "text": {"text": "2.text|iv|mac", "hidden": false},
        "file": null,
        "deletionDate": DELETE_IN_A_WEEK,
        "expirationDate": null,
        "maxAccessCount": null,
        "password": null,
        "disabled": false,
        "hideEmail": false
    })
}

#[tokio::test]
async fn a_send_is_told_as_created_updated_and_deleted() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    h.events.take();

    let (status, made) = h
        .json(
            "POST",
            "/api/sends",
            Some(&token),
            Some(text_send("2.send")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{made}");
    let id = id_of(&made);
    let events = h.events.take();
    let created = send_event(&events[0]);
    assert_eq!(
        (created.change, created.id, created.user),
        (Change::Created, id, user)
    );

    h.json(
        "PUT",
        &format!("/api/sends/{id}"),
        Some(&token),
        Some(text_send("2.renamed")),
    )
    .await;
    assert_eq!(send_event(&h.events.take()[0]).change, Change::Updated);

    h.json("DELETE", &format!("/api/sends/{id}"), Some(&token), None)
        .await;
    let events = h.events.take();
    assert_eq!(events.len(), 1);
    assert_eq!(send_event(&events[0]).change, Change::Deleted);
}

#[tokio::test]
async fn the_access_token_names_the_app_and_a_refresh_keeps_it() {
    let h = Harness::new().await;
    h.account("ada@example.com", common::HASH).await;
    let body = h.login("ada@example.com", common::HASH).await;
    let now = h.env.time().unix_timestamp();
    let first = claims(body["access_token"].as_str().expect("a token"), now);
    assert_eq!(first.appid.as_deref(), Some(APP_ID));

    let (status, refreshed) = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", "mobile"),
            (
                "refresh_token",
                body["refresh_token"].as_str().expect("a refresh token"),
            ),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let second = claims(refreshed["access_token"].as_str().expect("a token"), now);
    assert_eq!(second.appid.as_deref(), Some(APP_ID));
}

fn org_body() -> Value {
    json!({
        "name": "Live organization",
        "billingEmail": "billing@example.com",
        "planType": 0,
        "key": "4.orgkeywrappedforthefirstowner",
        "keys": {
            "publicKey": "MIIBIjANorganizationpublickey",
            "encryptedPrivateKey": "2.orgprivate|key|mac"
        },
        "collectionName": "2.defaultcollection|name|mac"
    })
}

#[tokio::test]
async fn an_organization_cipher_in_a_collection_is_told_to_the_members_who_can_see_it_only() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let grace = h.account("grace@example.com", common::HASH).await;

    let (status, org) = h
        .json("POST", "/api/organizations", Some(&ada), Some(org_body()))
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let org_id = org["id"].as_str().expect("an id").to_owned();
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    let collection = synced["collections"][0]["id"]
        .as_str()
        .expect("a collection")
        .to_owned();

    // Grace is a member with no collection: she can't see what is in it.
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org_id}/users/invite"),
            Some(&ada),
            Some(json!({"emails": ["grace@example.com"], "type": 2, "collections": [], "groups": []})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org_id}/users/{grace}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Confirming a member is a key sync for her.
    let confirmed = h.events.take();
    assert!(confirmed.iter().any(|e| matches!(
        e,
        BwEvent::Sync { sync: UserSync::OrgKeys, user, .. } if *user == grace
    )));

    let mut body = login_request(ada_id, "2.shared");
    body["organizationId"] = json!(org_id);
    let (status, created) = h
        .json(
            "POST",
            "/api/ciphers/create",
            Some(&ada),
            Some(json!({"cipher": body, "collectionIds": [collection]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let events = h.events.take();
    let told = cipher(&events[0]);
    assert_eq!(told.change, Change::Created);
    assert_eq!(told.id, id_of(&created));
    assert_eq!(told.user, None, "an organization's cipher names no account");
    assert_eq!(
        told.organization.map(|o| o.0.to_string()),
        Some(org_id.clone())
    );
    // A share names its collections, as Vaultwarden's does.
    assert_eq!(
        told.collections,
        Some(vec![Uuid::parse_str(&collection).expect("a uuid")])
    );
    assert_eq!(told.recipients, vec![ada_id], "grace can't see it");
}
