//! The root-key rotation routes through the router, in-process, with a real DPoP client and real
//! OPAQUE. The browser's key worker makes the new keys and every wrap; here the wraps are fillers of
//! the right length (the server never opens them) and the bundle is a real one, since the server
//! checks its signature. The store is a fake that runs the same checks `SqlStore` runs inside its
//! transaction.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, PASSWORD, Req, Session, b64, register_and_sign_in, unb64};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{RotationApiDoc, rotation_router};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::rotation::{
    Holdings, Install, PreviousKeys, RotationError, RotationStore, StagedItem, check_install,
};
use kemlock_domain::unlock::{EmergencyState, GrantId};
use kemlock_domain::{ChangeId, PasskeyId, UserId};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use utoipa::OpenApi;

use common::fakes::FakeStore;

const EMAIL: &str = "sam@example.org";

fn next_peer() -> SocketAddr {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    SocketAddr::from(([10, 2, (n >> 8) as u8, (n & 0xff) as u8], 5000))
}

/// A rotation store over the fake account store: what the account holds is set by the test, the
/// install runs `check_install` and writes the account.
#[derive(Clone)]
struct FakeRotation {
    users: FakeStore,
    holdings: Arc<Mutex<Holdings>>,
    installs: Arc<Mutex<u32>>,
}

impl RotationStore for FakeRotation {
    async fn holdings(&self, _user: UserId) -> Result<Holdings, StoreError> {
        Ok(self.holdings.lock().expect("lock").clone())
    }

    async fn stage(
        &self,
        _user: UserId,
        _rotation: [u8; 16],
        items: Vec<StagedItem>,
        _now: OffsetDateTime,
        _since: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        Ok(items.len() as u64)
    }

    async fn discard(&self, _user: UserId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn install(&self, install: Install) -> Result<Option<ChangeId>, RotationError> {
        let holdings = self.holdings.lock().expect("lock").clone();
        check_install(&install, &holdings, &[])?;
        UserRepo::update(&self.users, &install.after).await?;
        *self.installs.lock().expect("lock") += 1;
        Ok(None)
    }

    async fn previous_keys(&self, _user: UserId) -> Result<Option<PreviousKeys>, StoreError> {
        Ok(None)
    }

    async fn clear_previous_keys(&self, _user: UserId) -> Result<bool, StoreError> {
        Ok(false)
    }
}

/// The mail the server sent.
#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<Notice>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("the lock").push(notice);
        })
    }
}

struct Rig {
    app: App,
    router: Router,
    repo: FakeRotation,
    mailbox: Mailbox,
}

fn rig() -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    let repo = FakeRotation {
        users: app.store.clone(),
        holdings: Arc::new(Mutex::new(Holdings::default())),
        installs: Arc::new(Mutex::new(0)),
    };
    let router = app
        .router
        .clone()
        .merge(rotation_router(app.api.clone(), repo.clone()));
    Rig {
        app,
        router,
        repo,
        mailbox,
    }
}

struct Person {
    client: Client,
    session: Session,
    id: UserId,
}

impl Rig {
    async fn person(&self) -> Person {
        let mut client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        client.peer = Some(next_peer());
        let session = register_and_sign_in(&client, EMAIL).await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        Person {
            client,
            session,
            id,
        }
    }
}

impl Person {
    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> common::Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    body,
                    peer: Some(next_peer()),
                    ..Req::default()
                },
            )
            .await
    }

    /// The two OPAQUE messages of a fresh login with the account's password.
    async fn reauth_body(&self) -> Value {
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
        let started = self
            .client
            .send(
                "POST",
                "/kem/v1/auth/opaque/start",
                Req {
                    body: Some(json!({"email": EMAIL, "request": b64(&request)})),
                    peer: Some(next_peer()),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        let (finalization, _session_key, _export_key) =
            kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &response)
                .expect("client login finish");
        json!({"loginState": started["loginState"], "finalization": b64(&finalization)})
    }

    /// An install request for key version 2, with the password.
    async fn install_body(&self) -> Value {
        let mut body = self.reauth_body().await;
        let (bundle, signature) = bundle_v2(self.id);
        body["rotationId"] = json!(b64(&[7u8; 16]));
        body["fromVersion"] = json!(1);
        body["toVersion"] = json!(2);
        body["publicBundle"] = json!(b64(&bundle));
        body["bundleSignature"] = json!(b64(&signature));
        body["sealedPrivateKeys"] = json!(b64(&[0x22u8; 189]));
        body["sealedPreviousPrivateKeys"] = json!(b64(&[0x23u8; 189]));
        body["wrappedRootKey"] = json!(b64(&[0x44u8; 92]));
        body
    }
}

/// A bundle for `user` at key version 2 with a key pair other than the registered one's.
fn bundle_v2(user: UserId) -> (Vec<u8>, Vec<u8>) {
    let key = kemlock_crypto::sig1::SigningKey::from_bytes(&[0x5b; 64]);
    let bundle = kemlock_crypto::bundle::Bundle {
        account_id: *user.as_bytes(),
        key_version: 2,
        kx1_public: kemlock_crypto::kx1::PublicKey::from_bytes(&[0x43; 1600]).expect("a length"),
        sig1_public: key.public_key().expect("a public key"),
    };
    let signature = bundle.sign(&key).expect("the bundle signs");
    (bundle.to_bytes(), signature)
}

#[tokio::test]
async fn every_route_needs_a_session() {
    let rig = rig();
    let client = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    for (method, uri) in [
        ("GET", "/kem/v1/account/rotation"),
        ("POST", "/kem/v1/account/rotation"),
        ("DELETE", "/kem/v1/account/rotation"),
        ("PUT", "/kem/v1/account/rotation/items"),
        ("DELETE", "/kem/v1/account/rotation/previous-keys"),
    ] {
        let reply = client
            .send(
                method,
                uri,
                Req {
                    body: (method == "POST" || method == "PUT").then(|| json!({})),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn the_plan_says_what_the_account_holds() {
    let rig = rig();
    let sam = rig.person().await;
    let passkey = PasskeyId::random();
    rig.repo.holdings.lock().expect("lock").passkeys = vec![(passkey, vec![1, 2, 3])];
    let plan = sam.call("GET", "/kem/v1/account/rotation", None).await;
    assert_eq!(plan.status, StatusCode::OK, "{:?}", plan.body);
    let plan = plan.json();
    assert_eq!(plan["keyVersion"], 1);
    assert_eq!(plan["hasPassword"], true);
    assert_eq!(plan["passkeys"][0]["id"], passkey.to_string());
    assert_eq!(plan["items"]["count"], 0);
    // A contact is shown with the address and the bundle the server holds for them now.
    rig.repo.holdings.lock().expect("lock").emergency =
        vec![(GrantId::random(), EmergencyState::Confirmed, Some(sam.id))];
    let plan = sam
        .call("GET", "/kem/v1/account/rotation", None)
        .await
        .json();
    assert_eq!(plan["emergency"][0]["granteeEmail"], EMAIL);
    assert!(plan["emergency"][0]["granteeBundle"].is_string(), "{plan}");
    assert!(plan["previousKeys"].is_null());
}

#[tokio::test]
async fn an_install_needs_the_password_and_every_wrap_named() {
    let rig = rig();
    let sam = rig.person().await;

    // No password: nothing is installed.
    let mut body = sam.install_body().await;
    body.as_object_mut().expect("object").remove("loginState");
    body.as_object_mut().expect("object").remove("finalization");
    let reply = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);

    // A passkey wrap the request names nowhere is refused, whole.
    rig.repo.holdings.lock().expect("lock").passkeys = vec![(PasskeyId::random(), vec![1])];
    let reply = sam
        .call(
            "POST",
            "/kem/v1/account/rotation",
            Some(sam.install_body().await),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.body);
    assert_eq!(reply.problem(), "rotation-incomplete");
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
    assert_eq!(*rig.repo.installs.lock().expect("lock"), 0);

    // An account in a space must say it moves the space's keys.
    *rig.repo.holdings.lock().expect("lock") = Holdings {
        spaces: 1,
        ..Holdings::default()
    };
    let reply = sam
        .call(
            "POST",
            "/kem/v1/account/rotation",
            Some(sam.install_body().await),
        )
        .await;
    assert_eq!(reply.problem(), "spaces-need-rekey");
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
}

#[tokio::test]
async fn a_stale_version_or_an_unchanged_key_pair_is_refused() {
    let rig = rig();
    let sam = rig.person().await;
    let mut body = sam.install_body().await;
    body["fromVersion"] = json!(2);
    body["toVersion"] = json!(3);
    let reply = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.problem(), "rotation-stale-version");

    // The registered bundle again, at the next version, would keep the old pair.
    let mut body = sam.install_body().await;
    let (same_pair, signature) = {
        let key = common::fakes::bundle_key();
        let old = kemlock_crypto::bundle::Bundle {
            account_id: *sam.id.as_bytes(),
            key_version: 2,
            kx1_public: kemlock_crypto::kx1::PublicKey::from_bytes(&[0x42; 1600])
                .expect("a length"),
            sig1_public: key.public_key().expect("a public key"),
        };
        (old.to_bytes(), old.sign(&key).expect("signs"))
    };
    body["publicBundle"] = json!(b64(&same_pair));
    body["bundleSignature"] = json!(b64(&signature));
    let reply = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
}

#[tokio::test]
async fn an_install_replaces_the_keys_and_ends_every_other_session() {
    let rig = rig();
    let sam = rig.person().await;
    let reply = sam
        .call(
            "POST",
            "/kem/v1/account/rotation",
            Some(sam.install_body().await),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let reply = reply.json();
    assert_eq!(reply["keyVersion"], 2);
    assert!(reply["tokens"]["accessToken"].is_string(), "{reply}");

    let account = rig.app.store.user(sam.id).expect("user");
    assert_eq!(account.key_version, 2);
    assert_eq!(account.wrapped_root_key, vec![0x44u8; 92]);
    assert_eq!(account.sealed_private_keys, vec![0x22u8; 189]);
    assert_eq!(*rig.repo.installs.lock().expect("lock"), 1);

    // The account is told, by mail, with no key in it.
    let mails = rig.mailbox.0.lock().expect("the lock");
    assert!(
        mails
            .iter()
            .any(|notice| matches!(notice, Notice::KeysRotated(n) if n.to.as_str() == EMAIL)),
        "{mails:?}"
    );
    drop(mails);

    // The token the device held ended with the old security stamp.
    let old = sam.call("GET", "/kem/v1/account/rotation", None).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn staging_and_abandoning() {
    let rig = rig();
    let sam = rig.person().await;
    let reply = sam
        .call(
            "PUT",
            "/kem/v1/account/rotation/items",
            Some(json!({"rotationId": b64(&[7u8; 16]), "toVersion": 3, "items": []})),
        )
        .await;
    assert_eq!(reply.problem(), "rotation-stale-version");
    let reply = sam
        .call(
            "PUT",
            "/kem/v1/account/rotation/items",
            Some(json!({"rotationId": b64(&[7u8; 16]), "toVersion": 2, "items": []})),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "an empty batch: {:?}",
        reply.body
    );
    let reply = sam.call("DELETE", "/kem/v1/account/rotation", None).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let reply = sam
        .call("DELETE", "/kem/v1/account/rotation/previous-keys", None)
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
}

#[test]
fn the_document_names_every_rotation_route() {
    let doc = serde_json::to_value(RotationApiDoc::openapi()).expect("serialises");
    let paths = doc["paths"].as_object().expect("paths");
    for path in [
        "/kem/v1/account/rotation",
        "/kem/v1/account/rotation/items",
        "/kem/v1/account/rotation/previous-keys",
    ] {
        assert!(paths.contains_key(path), "{path}");
    }
    assert!(paths["/kem/v1/account/rotation"].get("post").is_some());
    assert!(paths["/kem/v1/account/rotation"].get("get").is_some());
    assert!(paths["/kem/v1/account/rotation"].get("delete").is_some());
}

/// A federation view whose answers a test sets.
#[derive(Default)]
struct FakeFed {
    replica: std::sync::atomic::AtomicBool,
    shared: std::sync::atomic::AtomicBool,
}

impl kemlock_app::federation_view::FederationView for FakeFed {
    fn vault_servers(
        &self,
        vault: kemlock_domain::Owner,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        Result<Option<kemlock_app::federation_view::VaultServers>, StoreError>,
    > {
        Box::pin(async move {
            Ok(self
                .shared
                .load(Ordering::Relaxed)
                .then(|| kemlock_app::federation_view::VaultServers {
                    vault,
                    epoch: 1,
                    servers: Vec::new(),
                    promotion: None,
                }))
        })
    }

    fn siblings(
        &self,
        _owner: kemlock_domain::Owner,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        Result<Vec<kemlock_app::federation_view::SiblingSet>, StoreError>,
    > {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn resolve_siblings(
        &self,
        _owner: kemlock_domain::Owner,
        _item: kemlock_domain::ItemId,
    ) -> kemlock_app::federation_view::BoxFut<'_, Result<u64, StoreError>> {
        Box::pin(async { Ok(0) })
    }

    fn is_replica_account(
        &self,
        _user: UserId,
    ) -> kemlock_app::federation_view::BoxFut<'_, Result<bool, StoreError>> {
        Box::pin(async move { Ok(self.replica.load(Ordering::Relaxed)) })
    }
}

#[tokio::test]
async fn a_federated_account_is_refused_by_every_rotation_route() {
    let rig = rig();
    let fed = Arc::new(FakeFed::default());
    let view: kemlock_app::federation_view::SharedView = fed.clone();
    let router = rig.router.clone().layer(axum::Extension(view));
    let mut client = Client::new(router, rig.app.clock.clone(), DpopSigner::es256());
    client.peer = Some(next_peer());
    let session = register_and_sign_in(&client, EMAIL).await;
    let id = UserId(session.user_id.parse().expect("a user id"));
    let sam = Person {
        client,
        session,
        id,
    };

    // On its own server, with nothing federated, the plan is served.
    let plan = sam.call("GET", "/kem/v1/account/rotation", None).await;
    assert_eq!(plan.status, StatusCode::OK, "{:?}", plan.body);

    for (replica, shared) in [(true, false), (false, true)] {
        fed.replica.store(replica, Ordering::Relaxed);
        fed.shared.store(shared, Ordering::Relaxed);
        for (method, uri) in [
            ("GET", "/kem/v1/account/rotation"),
            ("PUT", "/kem/v1/account/rotation/items"),
        ] {
            let body = (method == "PUT")
                .then(|| json!({"rotationId": b64(&[7u8; 16]), "toVersion": 2, "items": []}));
            let reply = sam.call(method, uri, body).await;
            assert_eq!(reply.status, StatusCode::CONFLICT, "{method} {uri} {replica} {shared}");
            assert_eq!(reply.problem(), "rotation-federated");
        }
        let install = sam
            .call(
                "POST",
                "/kem/v1/account/rotation",
                Some(sam.install_body().await),
            )
            .await;
        assert_eq!(install.problem(), "rotation-federated");
        assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
    }
}
