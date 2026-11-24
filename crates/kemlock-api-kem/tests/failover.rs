//! The failover routes: the server list in `/config`, siblings in `/sync` and their resolve path,
//! and device-key sign-in on a replica. The federation state is a fake `FederationView` the
//! router gets as a request extension, as the server provides it.
#![allow(dead_code)]

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::b64url;
use kemlock_app::federation_view::{
    BoxFut, FederationView, ServerEntry, ServerRole, SharedView, SiblingSet, VaultServers,
};
use kemlock_app::ports::StoreError;
use kemlock_domain::{
    ChangeId, Hlc, Item, ItemFormat, ItemId, ItemKind, Owner, Revision, ServerId, UserId,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// A federation view over maps, with a record of what was resolved.
#[derive(Default)]
struct FakeView {
    vaults: HashMap<Owner, VaultServers>,
    /// Vaults added once an account exists, whose id the test learns at sign-in.
    late_vaults: Mutex<HashMap<Owner, VaultServers>>,
    siblings: Mutex<HashMap<Owner, Vec<SiblingSet>>>,
    replica_accounts: Mutex<HashSet<UserId>>,
    resolved: Mutex<Vec<(Owner, ItemId)>>,
    /// Makes `resolve_siblings` fail the way the store does for a head already sent to a peer.
    refuse_resolve: bool,
}

impl FederationView for FakeView {
    fn vault_servers(&self, vault: Owner) -> BoxFut<'_, Result<Option<VaultServers>, StoreError>> {
        Box::pin(async move {
            let late = self.late_vaults.lock().expect("lock").get(&vault).cloned();
            Ok(self.vaults.get(&vault).cloned().or(late))
        })
    }

    fn siblings(&self, owner: Owner) -> BoxFut<'_, Result<Vec<SiblingSet>, StoreError>> {
        Box::pin(async move {
            Ok(self
                .siblings
                .lock()
                .expect("lock")
                .get(&owner)
                .cloned()
                .unwrap_or_default())
        })
    }

    fn resolve_siblings(&self, owner: Owner, item: ItemId) -> BoxFut<'_, Result<u64, StoreError>> {
        Box::pin(async move {
            if self.refuse_resolve {
                return Err(StoreError::Backend(
                    "the head was already sent to a peer".to_owned(),
                ));
            }
            self.resolved.lock().expect("lock").push((owner, item));
            Ok(self
                .siblings
                .lock()
                .expect("lock")
                .get(&owner)
                .and_then(|sets| sets.iter().find(|s| s.item == item))
                .map_or(0, |s| s.siblings.len() as u64))
        })
    }

    fn is_replica_account(&self, user: UserId) -> BoxFut<'_, Result<bool, StoreError>> {
        Box::pin(async move { Ok(self.replica_accounts.lock().expect("lock").contains(&user)) })
    }
}

/// An app (signing up allowed) whose router carries `view`, and a device that talks to it.
fn with_view(view: Arc<FakeView>) -> (App, Client) {
    let app = App::new(true);
    let shared: SharedView = view;
    let router = app.router.clone().layer(axum::Extension(shared));
    let client = Client::new(router, app.clock.clone(), DpopSigner::es256());
    (app, client)
}

fn entry(role: ServerRole, address: &str, key: u8) -> ServerEntry {
    ServerEntry {
        server: ServerId::random(),
        address: address.to_owned(),
        identity_key: vec![key; 8],
        role,
    }
}

fn servers_of(vault: Owner, epoch: u64, promotion: Option<Vec<u8>>) -> VaultServers {
    VaultServers {
        vault,
        epoch,
        servers: vec![
            entry(ServerRole::Home, "https://nas.example.org", 1),
            entry(ServerRole::Replica, "https://vps.example.net", 2),
        ],
        promotion,
    }
}

// ---------------------------------------------------------------------------------------------
// /config

#[tokio::test]
async fn config_lists_a_federated_vaults_servers_home_first() {
    let vault = Owner::User(UserId::random());
    let mut view = FakeView::default();
    let known = servers_of(vault, 3, Some(vec![7; 12]));
    view.vaults.insert(vault, known.clone());
    let (_app, client) = with_view(Arc::new(view));

    let reply = client.get(&format!("/kem/v1/config?vault={vault}")).await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    // What /config always said is still there.
    assert_eq!(json["server"], "kemlock-server");
    let listed = &json["vaults"][0];
    assert_eq!(listed["vault"], vault.to_string());
    assert_eq!(listed["epoch"], 3);
    assert_eq!(listed["promotion"], b64url::encode(&[7; 12]));
    assert_eq!(listed["servers"][0]["role"], "home");
    assert_eq!(listed["servers"][0]["address"], "https://nas.example.org");
    assert_eq!(listed["servers"][0]["identityKey"], b64url::encode(&[1; 8]));
    assert_eq!(
        listed["servers"][0]["serverId"],
        known.servers[0].server.0.to_string()
    );
    assert_eq!(listed["servers"][1]["role"], "replica");
    assert_eq!(listed["servers"][1]["address"], "https://vps.example.net");
}

#[tokio::test]
async fn an_epoch_one_vault_has_no_promotion_record() {
    let vault = Owner::Space(kemlock_domain::SpaceId::random());
    let mut view = FakeView::default();
    view.vaults.insert(vault, servers_of(vault, 1, None));
    let (_app, client) = with_view(Arc::new(view));

    let json = client
        .get(&format!("/kem/v1/config?vault={vault}"))
        .await
        .json();
    assert!(json["vaults"][0]["promotion"].is_null());
}

#[tokio::test]
async fn config_leaves_out_vaults_it_does_not_federate() {
    let known = Owner::User(UserId::random());
    let unknown = Owner::User(UserId::random());
    let mut view = FakeView::default();
    view.vaults.insert(known, servers_of(known, 1, None));
    let (_app, client) = with_view(Arc::new(view));

    let reply = client
        .get(&format!("/kem/v1/config?vault={unknown}&vault={known}"))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    let vaults = json["vaults"].as_array().expect("an array");
    assert_eq!(vaults.len(), 1, "the unknown vault is not mentioned");
    assert_eq!(vaults[0]["vault"], known.to_string());
}

#[tokio::test]
async fn config_without_a_question_or_a_view_lists_no_vaults() {
    let vault = Owner::User(UserId::random());
    let mut view = FakeView::default();
    view.vaults.insert(vault, servers_of(vault, 1, None));
    let (_app, client) = with_view(Arc::new(view));
    assert_eq!(
        client.get("/kem/v1/config").await.json()["vaults"],
        json!([])
    );

    // A server with no federation wired answers the same for a vault it is asked about.
    let app = App::new(false);
    let reply = app
        .client()
        .get(&format!("/kem/v1/config?vault={vault}"))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["vaults"], json!([]));
}

#[tokio::test]
async fn a_bad_or_too_long_vault_list_is_a_400() {
    let (_app, client) = with_view(Arc::new(FakeView::default()));
    for bad in ["vault=nope", "vault=user:not-a-uuid", "vault=team:1"] {
        let reply = client.get(&format!("/kem/v1/config?{bad}")).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(reply.problem(), "invalid-request");
    }
    let many: Vec<String> = (0..33)
        .map(|_| format!("vault={}", Owner::User(UserId::random())))
        .collect();
    let reply = client
        .get(&format!("/kem/v1/config?{}", many.join("&")))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let ok: Vec<String> = (0..32)
        .map(|_| format!("vault={}", Owner::User(UserId::random())))
        .collect();
    let reply = client
        .get(&format!("/kem/v1/config?{}", ok.join("&")))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Siblings in /sync and the resolve path

/// A version of an item as a replica holds it beside the head.
fn sibling_item(id: ItemId, owner: Owner, revision: u64, fill: u8) -> Item {
    Item {
        id,
        owner,
        kind: ItemKind::try_from("login".to_owned()).expect("a kind"),
        format: ItemFormat::Kem1,
        revision: Revision(revision),
        key_version: 1,
        ciphertext: Some(vec![fill; 40]),
        item_key: Some(vec![fill; 60]),
        deleted_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        change: ChangeId {
            origin: ServerId::random(),
            seq: 1,
            hlc: Hlc(1),
        },
    }
}

/// Writes a new item as `session` and returns its id.
async fn put_new(client: &Client, session: &Session) -> String {
    let id = new_item_id();
    let reply = client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                access_token: Some(&session.access_token),
                headers: vec![("if-none-match", "*".to_owned())],
                body: Some(item_json(&session.user_id, &id, 1)),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    id
}

fn owner_of(session: &Session) -> Owner {
    Owner::User(user_of(session))
}

fn user_of(session: &Session) -> UserId {
    session.user_id.parse().expect("a user id")
}

fn resolve_path(id: &str) -> String {
    format!("/kem/v1/items/{id}/siblings/resolve")
}

#[tokio::test]
async fn sync_lists_the_siblings_beside_the_head() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view.clone());
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let id = put_new(&client, &session).await;
    let owner = owner_of(&session);
    let item: ItemId = id.parse().expect("an item id");
    view.siblings.lock().expect("lock").insert(
        owner,
        vec![SiblingSet {
            item,
            siblings: vec![sibling_item(item, owner, 1, 0x5a)],
        }],
    );

    let reply = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let json = reply.json();
    assert_eq!(json["items"][0]["id"], id, "the head is listed as before");
    let sets = json["siblings"].as_array().expect("siblings are listed");
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0]["itemId"], id);
    assert_eq!(sets[0]["versions"][0]["id"], id);
    assert_eq!(
        sets[0]["versions"][0]["ciphertext"],
        b64url::encode(&[0x5a; 40])
    );
    assert_eq!(sets[0]["versions"][0]["owner"], owner.to_string());
}

#[tokio::test]
async fn sync_has_an_empty_siblings_list_without_federation_or_siblings() {
    // No view at all.
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    put_new(&client, &session).await;
    let json = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await
        .json();
    assert_eq!(json["siblings"], json!([]));

    // A view that knows no siblings.
    let (_app, client) = with_view(Arc::new(FakeView::default()));
    let session = register_and_sign_in(&client, "sam@example.org").await;
    put_new(&client, &session).await;
    let json = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await
        .json();
    assert_eq!(json["siblings"], json!([]));
}

#[tokio::test]
async fn resolving_drops_the_siblings_of_the_callers_own_item() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view.clone());
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let id = put_new(&client, &session).await;
    let owner = owner_of(&session);
    let item: ItemId = id.parse().expect("an item id");
    view.siblings.lock().expect("lock").insert(
        owner,
        vec![SiblingSet {
            item,
            siblings: vec![
                sibling_item(item, owner, 1, 1),
                sibling_item(item, owner, 1, 2),
            ],
        }],
    );

    let reply = client
        .post_authed(&resolve_path(&id), &session.access_token, json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["resolved"], 2);
    assert_eq!(*view.resolved.lock().expect("lock"), vec![(owner, item)]);
}

#[tokio::test]
async fn another_persons_or_an_unknown_item_cannot_be_resolved() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view.clone());
    let alice = register_and_sign_in(&client, "alice@example.org").await;
    let bob = register_and_sign_in(&client, "bob@example.org").await;
    let alices = put_new(&client, &alice).await;

    let other = client
        .post_authed(&resolve_path(&alices), &bob.access_token, json!({}))
        .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    let unknown = client
        .post_authed(&resolve_path(&new_item_id()), &bob.access_token, json!({}))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    // The two answers are the same, so they say nothing about who owns what.
    assert_eq!(other.body, unknown.body);
    assert!(view.resolved.lock().expect("lock").is_empty());

    let bad = client
        .post_authed(&resolve_path("nope"), &bob.access_token, json!({}))
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn resolving_needs_federation_and_a_sign_in() {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let id = put_new(&client, &session).await;
    let reply = client
        .post_authed(&resolve_path(&id), &session.access_token, json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "no view, no siblings");

    let (_app, client) = with_view(Arc::new(FakeView::default()));
    let anonymous = client.post(&resolve_path(&new_item_id()), json!({})).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_head_already_sent_to_a_peer_is_a_409() {
    let view = Arc::new(FakeView {
        refuse_resolve: true,
        ..FakeView::default()
    });
    let (_app, client) = with_view(view);
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let id = put_new(&client, &session).await;
    let reply = client
        .post_authed(&resolve_path(&id), &session.access_token, json!({}))
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.problem(), "siblings-already-sent");
}

// ---------------------------------------------------------------------------------------------
// Device-key sign-in on a replica

/// Another device of the same app, with its own DPoP key.
fn client_with(app: &App, view: &Arc<FakeView>) -> Client {
    let shared: SharedView = view.clone();
    Client::new(
        app.router.clone().layer(axum::Extension(shared)),
        app.clock.clone(),
        DpopSigner::es256(),
    )
}

const CHALLENGE: &str = "/kem/v1/auth/device-key/challenge";
const VERIFY: &str = "/kem/v1/auth/device-key/verify";

#[tokio::test]
async fn a_copied_accounts_device_signs_in_with_its_key_and_no_password() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view.clone());
    // The registration is what the home copied: the device id and the key that signed in.
    let registered = register_and_sign_in(&client, "sam@example.org").await;
    view.replica_accounts
        .lock()
        .expect("lock")
        .insert(user_of(&registered));

    let challenge = client
        .post(CHALLENGE, json!({"deviceId": registered.device_id}))
        .await;
    assert_eq!(challenge.status, StatusCode::OK, "{:?}", challenge.json());
    let challenge = challenge.json()["challenge"]
        .as_str()
        .expect("a challenge")
        .to_owned();

    let verified = client.post(VERIFY, json!({"challenge": challenge})).await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.json());
    let tokens = Session::from_tokens(&verified.json());
    assert_eq!(tokens.user_id, registered.user_id);
    assert_eq!(tokens.device_id, registered.device_id);
    assert_eq!(verified.json()["tokenType"], "DPoP");

    // The new tokens work, bound to the same key.
    let synced = client
        .get_authed("/kem/v1/sync", &tokens.access_token)
        .await;
    assert_eq!(synced.status, StatusCode::OK, "{:?}", synced.json());
}

#[tokio::test]
async fn an_account_that_lives_here_is_sent_to_its_ordinary_sign_in() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view);
    let registered = register_and_sign_in(&client, "sam@example.org").await;

    let reply = client
        .post(CHALLENGE, json!({"deviceId": registered.device_id}))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn another_key_or_an_unknown_device_gets_the_same_401() {
    let view = Arc::new(FakeView::default());
    let (app, client) = with_view(view.clone());
    let registered = register_and_sign_in(&client, "sam@example.org").await;
    view.replica_accounts
        .lock()
        .expect("lock")
        .insert(user_of(&registered));

    let stranger = client_with(&app, &view);
    let wrong_key = stranger
        .post(CHALLENGE, json!({"deviceId": registered.device_id}))
        .await;
    assert_eq!(wrong_key.status, StatusCode::UNAUTHORIZED);
    let unknown = client
        .post(CHALLENGE, json!({"deviceId": uuid::Uuid::new_v4()}))
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_key.body, unknown.body);

    // A challenge made for the registered key is no use to another key.
    let challenge = client
        .post(CHALLENGE, json!({"deviceId": registered.device_id}))
        .await
        .json()["challenge"]
        .as_str()
        .expect("a challenge")
        .to_owned();
    let stolen = stranger.post(VERIFY, json!({"challenge": challenge})).await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_device_key_routes_need_federation_and_a_proof() {
    // No view: both are 404, as if the routes weren't there.
    let app = App::new(true);
    let client = app.client();
    let registered = register_and_sign_in(&client, "sam@example.org").await;
    let reply = client
        .post(CHALLENGE, json!({"deviceId": registered.device_id}))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = client.post(VERIFY, json!({"challenge": "AAAA"})).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // With a view but no DPoP proof, nothing is signed.
    let (_app, client) = with_view(Arc::new(FakeView::default()));
    let reply = client
        .send(
            "POST",
            CHALLENGE,
            Req {
                body: Some(json!({"deviceId": uuid::Uuid::new_v4()})),
                no_proof: true,
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_device_key_routes_are_in_the_openapi_document() {
    let (_app, client) = with_view(Arc::new(FakeView::default()));
    let json = client.get("/kem/v1/openapi.json").await.json();
    for (path, method) in [
        (CHALLENGE, "post"),
        (VERIFY, "post"),
        ("/kem/v1/items/{id}/siblings/resolve", "post"),
    ] {
        assert!(
            json["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// /placement

#[tokio::test]
async fn placement_lists_the_accounts_federated_vault_and_its_apps() {
    let view = Arc::new(FakeView::default());
    let (_app, client) = with_view(view.clone());
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let owner = owner_of(&session);
    let mut servers = servers_of(owner, 1, None);
    // The replica is the server answering: the test app's domain.
    servers.servers[1].address = format!("{DOMAIN}/");
    let replica = servers.servers[1].server.0.to_string();
    view.late_vaults.lock().expect("lock").insert(owner, servers);

    let reply = client
        .get_authed("/kem/v1/placement", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let json = reply.json();
    let vault = &json["vaults"][0];
    assert_eq!(vault["id"], "me");
    assert_eq!(vault["servers"][0]["role"], "home");
    assert_eq!(vault["servers"][0]["name"], "nas.example.org");
    assert_eq!(vault["servers"][0]["status"], "online");
    assert_eq!(vault["servers"][0]["inUse"], false);
    assert_eq!(vault["servers"][1]["id"], replica);
    assert_eq!(vault["servers"][1]["role"], "replica");
    assert_eq!(vault["servers"][1]["inUse"], true);
    assert!(vault["pending"].is_null());
    // The device that signed in is an app of the vault, on the server answering.
    assert!(
        json["apps"]
            .as_array()
            .is_some_and(|apps| !apps.is_empty() && apps[0]["server"] == "kemlock.test")
    );
}

#[tokio::test]
async fn placement_is_not_found_without_federation_or_for_a_vault_that_is_not_federated() {
    // No view at all.
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let reply = client
        .get_authed("/kem/v1/placement", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // A view that holds none of the account's vaults.
    let (_app, client) = with_view(Arc::new(FakeView::default()));
    let session = register_and_sign_in(&client, "sam@example.org").await;
    let reply = client
        .get_authed("/kem/v1/placement", &session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // It needs a signed-in account, and a waiting change is never there to cancel.
    let anonymous = client.get("/kem/v1/placement").await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let cancel = client
        .send(
            "DELETE",
            "/kem/v1/placement/me/pending/c1",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(cancel.status, StatusCode::NOT_FOUND);
}
