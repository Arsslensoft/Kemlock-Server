//! The root-key rotation routes through the router, in-process, with a real DPoP client and real
//! OPAQUE. The browser's key worker makes the new keys and every wrap; here the wraps are fillers of
//! the right length (the server never opens them) and the bundle is a real one, since the server
//! checks its signature. The store is a fake that runs the same checks `SqlStore` runs inside its
//! transaction.

mod common;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/chain_kit/mod.rs"]
mod chain_kit;
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;

use axum::Router;
use axum::http::StatusCode;
use chain_kit::{Chain, Person as Keys, request as chain_request};
use common::{
    App, Client, PASSWORD, Req, Session, b64, register_and_sign_in, register_and_sign_in_with, unb64,
};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{RotationApiDoc, rotation_router, space_chain_router, spaces_router};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::rotation::{
    Holdings, Install, Installed, PreviousKeys, ResetGrant, RotationError, RotationStore,
    StagedItem, check_install,
};
use kemlock_domain::unlock::{EmergencyState, GrantId};
use kemlock_domain::{ItemId, PasskeyId, Revision, UserId};
use serde_json::{Value, json};
use space_fakes::FakeSpaces;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use utoipa::OpenApi;
use uuid::Uuid;

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
    /// The grantors the install says it reset the grants of.
    reset_grants: Arc<Mutex<Vec<ResetGrant>>>,
    snapshots: Arc<Mutex<u32>>,
    /// The previous private keys an install keeps for an account in a space, as the store does.
    kept: Arc<Mutex<Option<PreviousKeys>>>,
}

impl FakeRotation {
    /// What the account holds, with whether the previous keys are kept filled in from the state.
    fn held(&self) -> Holdings {
        let mut held = self.holdings.lock().expect("lock").clone();
        held.previous_keys = self.kept.lock().expect("lock").is_some();
        held
    }
}

impl RotationStore for FakeRotation {
    async fn holdings(&self, _user: UserId) -> Result<Holdings, StoreError> {
        Ok(self.held())
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

    async fn snapshot(
        &self,
        _user: UserId,
        _rotation: [u8; 16],
        _since: OffsetDateTime,
    ) -> Result<(Holdings, Vec<(ItemId, Revision)>), StoreError> {
        *self.snapshots.lock().expect("lock") += 1;
        Ok((self.held(), Vec::new()))
    }

    async fn discard(&self, _user: UserId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn install(&self, install: Install) -> Result<Installed, RotationError> {
        let holdings = self.held();
        check_install(&install, &holdings, &[])?;
        UserRepo::update(&self.users, &install.after).await?;
        // Kept only for an account in a space, whose rekey needs them.
        *self.kept.lock().expect("lock") = (holdings.spaces > 0).then(|| PreviousKeys {
            key_version: install.before.key_version,
            sealed: install.request.sealed_previous_private_keys.clone(),
        });
        *self.installs.lock().expect("lock") += 1;
        Ok(Installed {
            change: None,
            reset_grants: self.reset_grants.lock().expect("lock").clone(),
        })
    }

    async fn previous_keys(&self, _user: UserId) -> Result<Option<PreviousKeys>, StoreError> {
        Ok(self.kept.lock().expect("lock").clone())
    }

    async fn clear_previous_keys(&self, _user: UserId) -> Result<bool, StoreError> {
        Ok(self.kept.lock().expect("lock").take().is_some())
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

fn fake_rotation(app: &App) -> FakeRotation {
    FakeRotation {
        users: app.store.clone(),
        holdings: Arc::new(Mutex::new(Holdings::default())),
        installs: Arc::new(Mutex::new(0)),
        reset_grants: Arc::new(Mutex::new(Vec::new())),
        snapshots: Arc::new(Mutex::new(0)),
        kept: Arc::new(Mutex::new(None)),
    }
}

fn rig() -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    let repo = fake_rotation(&app);
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

/// A rig that has the space routes too, over the in-memory space fakes, so an account in a space
/// can rotate and then append its `rekey` to the space's chain.
fn space_rig() -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    let repo = fake_rotation(&app);
    let spaces = FakeSpaces::new(app.store.clone());
    let router = app
        .router_with(spaces.clone())
        .merge(spaces_router(app.api.clone(), spaces.clone()))
        .merge(space_chain_router(app.api.clone(), spaces))
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
        self.person_at(EMAIL).await
    }

    /// A person whose registered bundle is `seed`'s real keys, so the space chain accepts the
    /// records they sign. Returns the account and the keys it signs with.
    async fn space_person(&self, email: &str, seed: u8) -> (Person, Keys) {
        let mut client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        client.peer = Some(next_peer());
        let session = register_and_sign_in_with(&client, email, |user| {
            let keys = Keys::new(*user.as_bytes(), seed);
            (keys.bytes(), keys.self_signature())
        })
        .await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        let keys = Keys::new(*id.as_bytes(), seed);
        (
            Person {
                client,
                session,
                id,
            },
            keys,
        )
    }

    async fn person_at(&self, email: &str) -> Person {
        let mut client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        client.peer = Some(next_peer());
        let session = register_and_sign_in(&client, email).await;
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
        self.call_with(self.session.access_token.as_str(), method, uri, body)
            .await
    }

    /// A request with `token`: the one an install answered with, after the old one ended.
    async fn call_with(
        &self,
        token: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> common::Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(token),
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
        let (bundle, signature) = bundle_v2(self.id);
        self.install_body_for(1, &bundle, &signature).await
    }

    /// An install request from key version `from` to the next, with the password, that brings
    /// `bundle`.
    async fn install_body_for(&self, from: u32, bundle: &[u8], signature: &[u8]) -> Value {
        let mut body = self.reauth_body().await;
        body["rotationId"] = json!(b64(&[7u8; 16]));
        body["fromVersion"] = json!(from);
        body["toVersion"] = json!(from + 1);
        body["publicBundle"] = json!(b64(bundle));
        body["bundleSignature"] = json!(b64(signature));
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
    // A grant that names the account as the contact is listed: it waits for a new confirmation.
    rig.repo.holdings.lock().expect("lock").as_contact =
        vec![(GrantId::random(), EmergencyState::Approved)];
    let plan = sam
        .call("GET", "/kem/v1/account/rotation", None)
        .await
        .json();
    assert_eq!(plan["asContact"][0]["state"], "approved");
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
    {
        let mails = rig.mailbox.0.lock().expect("the lock");
        assert!(
            mails
                .iter()
                .any(|notice| matches!(notice, Notice::KeysRotated(n) if n.to.as_str() == EMAIL)),
            "{mails:?}"
        );
    }

    // The token the device held ended with the old security stamp.
    let old = sam.call("GET", "/kem/v1/account/rotation", None).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_grantor_of_a_grant_the_install_reset_is_mailed_to_confirm_the_contact_again() {
    let grantor_email = "grace@example.org";
    let rig = rig();
    let grantor = rig.person_at(grantor_email).await;
    let sam = rig.person().await;
    *rig.repo.holdings.lock().expect("lock") = Holdings {
        as_contact: vec![(GrantId::random(), EmergencyState::Confirmed)],
        ..Holdings::default()
    };
    // The store says, from inside its transaction, which grants it sent back to waiting, and the
    // contact's address as the grant has it (not the one the account has now).
    *rig.repo.reset_grants.lock().expect("lock") = vec![ResetGrant {
        grantor: grantor.id,
        contact: kemlock_domain::Email::parse("sam.old@example.org").expect("an address"),
    }];
    rig.mailbox.0.lock().expect("the lock").clear();

    let reply = sam
        .call(
            "POST",
            "/kem/v1/account/rotation",
            Some(sam.install_body().await),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);

    let mails = rig.mailbox.0.lock().expect("the lock");
    let told: Vec<_> = mails
        .iter()
        .filter_map(|notice| match notice {
            Notice::EmergencyContactRekeyed(n) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(told.len(), 1, "{mails:?}");
    assert_eq!(told[0].to.as_str(), grantor_email);
    assert_eq!(told[0].contact.as_str(), "sam.old@example.org");
    // The contact is told of their own rotation, and not of the grantor's.
    assert!(
        mails
            .iter()
            .any(|notice| matches!(notice, Notice::KeysRotated(n) if n.to.as_str() == EMAIL)),
        "{mails:?}"
    );
}

#[tokio::test]
async fn an_install_that_resets_no_grant_mails_no_grantor() {
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
    let mails = rig.mailbox.0.lock().expect("the lock");
    assert!(
        !mails
            .iter()
            .any(|notice| matches!(notice, Notice::EmergencyContactRekeyed(_))),
        "{mails:?}"
    );
}

/// The whole space half of a rotation: an account in a space rotates, the previous keys are kept
/// until the space has moved, a second rotation is refused meanwhile, the member's `rekey` is
/// accepted by the chain, and then the keys can go and the account can rotate again.
#[tokio::test]
async fn an_account_in_a_space_rekeys_the_chain_before_it_may_rotate_again() {
    let rig = space_rig();
    let (sam, old) = rig.space_person(EMAIL, 1).await;

    // Sam owns a space with a chain, signed by the keys the account registered with.
    let space = Uuid::new_v4();
    let chain_uri = format!("/kem/v1/spaces/{space}/chain");
    let mut chain = Chain::new(
        *space.as_bytes(),
        u64::try_from(rig.app.now()).expect("a time"),
    );
    let create = chain.create(&old, *Uuid::new_v4().as_bytes());
    let reply = sam
        .call("POST", &chain_uri, Some(chain_request(&[&create])))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    // What the rotation store holds for the account says it is in one space.
    rig.repo.holdings.lock().expect("lock").spaces = 1;

    // The first rotation moves the account to key version 2, and the client says it moves the
    // space's keys itself.
    let v2 = old.rotated(0x11, 2);
    let mut body = sam
        .install_body_for(1, &v2.bytes(), &v2.self_signature())
        .await;
    body["spacesHandled"] = json!(true);
    let reply = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let rotated = reply.json();
    assert_eq!(rotated["keyVersion"], 2);
    // The old session ended with the stamp: the device goes on with the tokens it was given.
    let token = rotated["tokens"]["accessToken"]
        .as_str()
        .expect("new tokens")
        .to_owned();
    assert_eq!(
        sam.call("GET", "/kem/v1/account/rotation", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rig.app.store.user(sam.id).expect("user").public_bundle,
        v2.bytes()
    );

    // The old private keys are kept for the space's rekey, and the plan shows them.
    let plan = sam
        .call_with(&token, "GET", "/kem/v1/account/rotation", None)
        .await;
    assert_eq!(plan.status, StatusCode::OK, "{:?}", plan.body);
    let plan = plan.json();
    assert_eq!(plan["spaces"], 1);
    assert_eq!(plan["previousKeys"]["keyVersion"], 1);
    assert_eq!(plan["previousKeys"]["sealed"], b64(&[0x23u8; 189]));

    // A second rotation would replace the only copy of the key the space has on record: refused,
    // and nothing is written.
    let v3 = old.rotated(0x12, 3);
    let mut body = sam
        .install_body_for(2, &v3.bytes(), &v3.self_signature())
        .await;
    body["spacesHandled"] = json!(true);
    let reply = sam
        .call_with(&token, "POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.body);
    assert_eq!(reply.problem(), "rotation-spaces-pending");
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 2);
    assert_eq!(*rig.repo.installs.lock().expect("lock"), 1);

    // Sam's rekey: signed by the key the chain has on record, cosigned by the new one, bringing
    // the bundle the account registered by the rotation, byte for byte.
    let rekey = chain.rekey(&old, &v2);
    let reply = sam
        .call_with(&token, "POST", &chain_uri, Some(chain_request(&[&rekey])))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let served = sam.call_with(&token, "GET", &chain_uri, None).await;
    assert_eq!(served.status, StatusCode::OK, "{:?}", served.body);
    let records = served.json();
    assert_eq!(records.as_array().map(Vec::len), Some(2), "{records}");
    assert_eq!(
        records[1]["entry"],
        kemlock_crypto::space_chain::b64::encode(&rekey.record.entry)
    );
    assert!(records[1]["cosignature"].is_string(), "{records}");

    // The space has moved: the previous keys go, with the password again.
    let done = sam
        .call_with(
            &token,
            "DELETE",
            "/kem/v1/account/rotation/previous-keys",
            Some(sam.reauth_body().await),
        )
        .await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{:?}", done.body);
    assert!(rig.repo.kept.lock().expect("lock").is_none());
    let plan = sam
        .call_with(&token, "GET", "/kem/v1/account/rotation", None)
        .await
        .json();
    assert!(plan["previousKeys"].is_null(), "{plan}");

    // Now the account can rotate again, and keeps its version 2 keys for the next rekey.
    let mut body = sam
        .install_body_for(2, &v3.bytes(), &v3.self_signature())
        .await;
    body["spacesHandled"] = json!(true);
    let reply = sam
        .call_with(&token, "POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.json()["keyVersion"], 3);
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 3);
    assert_eq!(*rig.repo.installs.lock().expect("lock"), 2);
    assert_eq!(
        rig.repo
            .kept
            .lock()
            .expect("lock")
            .as_ref()
            .map(|kept| kept.key_version),
        Some(2)
    );
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
    // Deleting the previous keys takes the password again, as the rotation did.
    let bare = sam
        .call(
            "DELETE",
            "/kem/v1/account/rotation/previous-keys",
            Some(json!({})),
        )
        .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST, "{:?}", bare.body);
    let reply = sam
        .call(
            "DELETE",
            "/kem/v1/account/rotation/previous-keys",
            Some(sam.reauth_body().await),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{:?}", reply.body);
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
            Ok(self.shared.load(Ordering::Relaxed).then(|| {
                kemlock_app::federation_view::VaultServers {
                    vault,
                    epoch: 1,
                    servers: Vec::new(),
                    promotion: None,
                }
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
            assert_eq!(
                reply.status,
                StatusCode::CONFLICT,
                "{method} {uri} {replica} {shared}"
            );
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

#[tokio::test]
async fn a_refused_install_does_not_spend_the_password() {
    let rig = rig();
    let sam = rig.person().await;
    // A passkey wrap the request names nowhere: refused by the check that runs before the login
    // state is spent, so the same body works once the account is as the client read it.
    rig.repo.holdings.lock().expect("lock").passkeys = vec![(PasskeyId::random(), vec![1])];
    let body = sam.install_body().await;
    let refused = sam
        .call("POST", "/kem/v1/account/rotation", Some(body.clone()))
        .await;
    assert_eq!(refused.problem(), "rotation-incomplete");
    assert!(*rig.repo.snapshots.lock().expect("lock") >= 1);

    *rig.repo.holdings.lock().expect("lock") = Holdings::default();
    let again = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
}

#[tokio::test]
async fn an_account_with_no_password_needs_a_passkey_answer_not_a_session() {
    let rig = rig();
    let sam = rig.person().await;
    let mut account = rig.app.store.user(sam.id).expect("user");
    account.wrapped_root_key = Vec::new();
    UserRepo::update(&rig.app.store, &account)
        .await
        .expect("the account has no password wrap now");

    let mut body = sam.install_body().await;
    for field in ["loginState", "finalization", "wrappedRootKey"] {
        body.as_object_mut().expect("object").remove(field);
    }
    // A session alone, a mailed code, and a recovery code are not enough.
    for proof in [None, Some(json!("123456"))] {
        let mut attempt = body.clone();
        if let Some(proof) = proof {
            attempt["proof"] = proof;
        }
        let reply = sam
            .call("POST", "/kem/v1/account/rotation", Some(attempt))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
    }
    // An answer that is no assertion of this account's passkey is refused too, and nothing is written.
    body["proof"] = json!({"webauthn": {"id": "AAAA"}});
    let reply = sam
        .call("POST", "/kem/v1/account/rotation", Some(body))
        .await;
    assert_ne!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(*rig.repo.installs.lock().expect("lock"), 0);
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
}

#[tokio::test]
async fn the_sealed_private_keys_are_exactly_the_size_the_format_makes() {
    let rig = rig();
    let sam = rig.person().await;
    for (field, len) in [
        ("sealedPrivateKeys", 188),
        ("sealedPrivateKeys", 190),
        ("sealedPreviousPrivateKeys", 100),
        ("sealedPreviousPrivateKeys", 4096),
    ] {
        let mut body = sam.install_body().await;
        body[field] = json!(b64(&vec![0x22u8; len]));
        let reply = sam
            .call("POST", "/kem/v1/account/rotation", Some(body))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{field} {len}: {:?}",
            reply.body
        );
    }
    assert_eq!(rig.app.store.user(sam.id).expect("user").key_version, 1);
}
