//! The admin routes the web vault's federation screens need beyond the rows: identity keys, lag and
//! sizes in the overview, the vaults that may be federated, reaching peers and comparing hash trees
//! now, a peer's security and descriptor file, this server's own keys, and a key mismatch. Over
//! in-memory servers with the real identity file in a temp folder.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::request::Parts;
use axum::http::{Method, Request, StatusCode, header};
use kemlock_api_fed::{
    AdminActor, AdminGate, AdminState, FileRotator, GateRefusal, IdentityParams, admin_openapi,
    admin_router, load_or_create,
};
use kemlock_app::federation_view::BoxFut;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{ItemId, Owner, ServerId, UserId};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request as FedRequest, Response as FedResponse};
use kemlock_federation::ports::Peer;
use kemlock_federation::testing::{draft, identity};
use kemlock_federation::{
    Channel, Connector, DescriptorSource, FedError, Federation, LocalIdentity, Pairings,
    PeerRunner, Replica, ServerProfile, SignedDescriptor, Suite, unix_now,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use tower::ServiceExt as _;

const KEY: [u8; 32] = [7; 32];
const BASE: &str = "/admin/v1/federation";

/// What the connector does when the job or the console dials a peer.
#[derive(Clone, Debug)]
enum Mode {
    Down,
    Mismatch(Vec<u8>),
}

#[derive(Clone)]
struct Scripted(Arc<Mutex<Mode>>);

struct NoChannel;

impl Channel for NoChannel {
    async fn call(&mut self, _request: &FedRequest) -> Result<FedResponse, FedError> {
        Err(FedError::Remote("no session in these tests".to_owned()))
    }
}

impl Connector for Scripted {
    type Chan = NoChannel;

    async fn connect(&self, _peer: &Peer) -> Result<NoChannel, FedError> {
        match self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            Mode::Down => Err(FedError::Remote("nobody answers".to_owned())),
            Mode::Mismatch(offered) => Err(FedError::KeyMismatch { offered }),
        }
    }

    async fn close(&self, _channel: NoChannel) -> Result<(), FedError> {
        Ok(())
    }
}

/// The descriptors the "network" serves, by address.
#[derive(Default)]
struct Served(Mutex<HashMap<String, SignedDescriptor>>);

impl Served {
    fn serve(&self, address: &str, descriptor: SignedDescriptor) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(address.to_owned(), descriptor);
    }

    fn withdraw(&self, address: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(address);
    }
}

impl DescriptorSource for Served {
    fn fetch<'a>(&'a self, address: &'a str) -> BoxFut<'a, Result<SignedDescriptor, FedError>> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(address)
                .cloned()
                .ok_or_else(|| FedError::Remote("the peer could not be reached".to_owned()))
        })
    }
}

/// `x-admin` lets a request in, `x-fresh` makes it a fresh sign-in and `x-step-up` gives it a
/// step-up token.
struct Gate;

impl AdminGate for Gate {
    fn authorize<'a>(&'a self, parts: &'a Parts) -> BoxFut<'a, Result<AdminActor, GateRefusal>> {
        Box::pin(async move {
            if !parts.headers.contains_key("x-admin") {
                return Err(GateRefusal {
                    status: StatusCode::UNAUTHORIZED,
                    detail: "send x-admin",
                });
            }
            Ok(AdminActor {
                user: UserId::random(),
                fresh: parts.headers.contains_key("x-fresh"),
                step_up: parts.headers.contains_key("x-step-up"),
            })
        })
    }
}

struct Env {
    app: Router,
    replica: Arc<Replica<MemoryStore>>,
    mode: Arc<Mutex<Mode>>,
    served: Arc<Served>,
    folder: tempfile::TempDir,
}

fn env(seed: u8) -> Env {
    let folder = tempfile::tempdir().expect("a temp dir");
    let identity: LocalIdentity = load_or_create(
        folder.path(),
        &ServerSeal::new(&KEY),
        ServerId::random(),
        &IdentityParams {
            address: format!("https://s{seed}.example.org"),
            operator: format!("Operator {seed}"),
            suites: Suite::IMPLEMENTED.to_vec(),
        },
        unix_now(),
    )
    .expect("an identity");
    let replica = Arc::new(Replica::new(
        MemoryStore::new(identity.server),
        Arc::new(identity),
    ));
    let mode = Arc::new(Mutex::new(Mode::Down));
    let served = Arc::new(Served::default());
    let pairings = Arc::new(Pairings::new(replica.clone(), Arc::new(Dead)));
    let runner = Arc::new(PeerRunner::new(
        replica.clone(),
        Scripted(mode.clone()),
        format!("test-{seed}"),
    ));
    let federation = Federation::new(replica.clone(), runner, pairings)
        .with_rotator(Arc::new(FileRotator::new(folder.path().to_path_buf(), KEY)))
        .with_descriptors(served.clone())
        .with_profile(ServerProfile {
            name: None,
            database: Some("sqlite".to_owned()),
            country: Some("CA".to_owned()),
        });
    let app = admin_router(AdminState {
        federation,
        gate: Arc::new(Gate),
    });
    Env {
        app,
        replica,
        mode,
        served,
        folder,
    }
}

/// A pairing link with nobody at the other end.
struct Dead;

impl kemlock_federation::PairingLink for Dead {
    fn start(&self, _address: &str, _message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, FedError>> {
        Box::pin(async { Err(FedError::Remote("nobody there".to_owned())) })
    }

    fn finish(
        &self,
        _address: &str,
        _initiator: ServerId,
        _message: Vec<u8>,
    ) -> BoxFut<'_, Result<(), FedError>> {
        Box::pin(async { Err(FedError::Remote("nobody there".to_owned())) })
    }
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("a request"))
        .await
        .expect("a response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("a body");
    (status, headers, bytes.to_vec())
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

/// An admin without a step-up token.
async fn read(app: &Router, uri: &str) -> (StatusCode, Value) {
    let (status, _, bytes) = send(app, Method::GET, uri, &[("x-admin", "1")], None).await;
    (status, value(&bytes))
}

/// An admin with a step-up token.
async fn write(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, _, bytes) = send(
        app,
        method,
        uri,
        &[("x-admin", "1"), ("x-step-up", "1")],
        body,
    )
    .await;
    (status, value(&bytes))
}

/// Pins `other` as a paired peer of `e` and serves its descriptor.
async fn pair(e: &Env, other: &LocalIdentity) -> ServerId {
    let peer = e
        .replica
        .pin_peer(&other.descriptor, unix_now())
        .await
        .expect("a peer");
    e.served.serve(&peer.addresses[0], other.descriptor.clone());
    peer.id
}

fn put_items(e: &Env, owner: Owner, count: usize) {
    for _ in 0..count {
        e.replica
            .store()
            .put(draft(ItemId::random(), owner, None, 1, unix_now() * 1000))
            .expect("an item");
    }
}

fn user_vault() -> Owner {
    Owner::User(UserId::random())
}

#[tokio::test]
async fn without_the_gate_nothing_new_is_served() {
    let e = env(1);
    let peer = ServerId::random().0;
    for (method, uri) in [
        (Method::GET, format!("{BASE}/shareable")),
        (Method::POST, format!("{BASE}/check")),
        (Method::POST, format!("{BASE}/consistency")),
        (Method::GET, format!("{BASE}/peers/{peer}/security")),
        (Method::GET, format!("{BASE}/peers/{peer}/descriptor")),
        (Method::GET, format!("{BASE}/self")),
        (Method::POST, format!("{BASE}/self/kem-rotation")),
        (Method::POST, format!("{BASE}/self/identity-rotation")),
        (Method::PUT, format!("{BASE}/self/suites")),
        (Method::GET, format!("{BASE}/mismatches/{peer}")),
        (
            Method::POST,
            format!("{BASE}/mismatches/{peer}/keep-blocking"),
        ),
    ] {
        let (status, _, _) = send(&e.app, method.clone(), &uri, &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn every_new_write_asks_for_a_step_up_token() {
    let e = env(1);
    let peer = ServerId::random().0;
    let suites = json!({"suites": [{"name": Suite::Aes256Gcm.name(), "on": true}]});
    for (method, uri, body) in [
        (Method::POST, format!("{BASE}/check"), None),
        (Method::POST, format!("{BASE}/consistency"), None),
        (Method::POST, format!("{BASE}/self/kem-rotation"), None),
        (Method::POST, format!("{BASE}/self/identity-rotation"), None),
        (Method::PUT, format!("{BASE}/self/suites"), Some(suites)),
        (
            Method::POST,
            format!("{BASE}/mismatches/{peer}/keep-blocking"),
            None,
        ),
    ] {
        // An admin, even one who just signed in, is not an admin with a step-up token.
        for headers in [
            &[("x-admin", "1")][..],
            &[("x-admin", "1"), ("x-fresh", "1")][..],
        ] {
            let (status, _, bytes) =
                send(&e.app, method.clone(), &uri, headers, body.clone()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
            assert_eq!(
                value(&bytes)["type"],
                "urn:kemlock:problem:step-up-required",
                "{method} {uri}"
            );
        }
    }
    // Reads need only the gate.
    let (status, _) = read(&e.app, &format!("{BASE}/self")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = read(&e.app, &format!("{BASE}/shareable")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_step_up_token_is_the_fresh_check_identity_rotation_asks_for() {
    let e = env(1);
    let uri = format!("{BASE}/identity/rotate");
    let (status, _, bytes) = send(&e.app, Method::POST, &uri, &[("x-admin", "1")], None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        value(&bytes)["type"],
        "urn:kemlock:problem:fresh-check-needed"
    );
    let (status, body) = write(&e.app, Method::POST, &uri, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["kind"], "rotation");
}

#[tokio::test]
async fn the_overview_carries_keys_lag_sizes_and_the_server_profile() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;
    let vault = user_vault();
    put_items(&e, vault, 2);
    e.replica
        .federate(vault, vec![peer])
        .await
        .expect("federated");

    let (status, overview) = read(&e.app, BASE).await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    assert_eq!(overview["server"]["name"], "s1.example.org");
    assert_eq!(overview["server"]["database"], "sqlite");
    assert_eq!(overview["server"]["country"], "CA");

    let peer_row = &overview["peers"][0];
    assert_eq!(
        peer_row["identityKey"],
        hex::encode(other.public.as_bytes()),
        "the pinned key"
    );
    assert_eq!(peer_row["name"], "s2.example.org");
    assert_eq!(peer_row["lagChanges"], 2, "two versions the peer may lack");
    assert!(peer_row["lagSeconds"].is_u64(), "{peer_row}");
    assert_eq!(peer_row["lastChangeAt"], Value::Null);
    assert_eq!(peer_row["theySendLogs"], false);

    let vault_row = &overview["vaults"][0];
    assert_eq!(vault_row["sizeBytes"], 80, "two items of 40 bytes");
    assert_eq!(vault_row["members"], 1);
    assert_eq!(vault_row["waitingChanges"], 2);
    assert!(vault_row["waitingNote"].is_string());
    assert_eq!(
        vault_row["ownerEmail"],
        Value::Null,
        "the in-memory store has no accounts"
    );

    // The same fields come with the peer list and the vault list.
    let (_, peers) = read(&e.app, &format!("{BASE}/peers")).await;
    assert_eq!(peers[0]["identityKey"], peer_row["identityKey"]);
    let (_, vaults) = read(&e.app, &format!("{BASE}/vaults")).await;
    assert_eq!(vaults[0]["sizeBytes"], 80);
}

#[tokio::test]
async fn a_peer_that_caught_up_has_no_lag_and_a_vault_nobody_shares_has_none_waiting() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    pair(&e, &other).await;
    let (_, overview) = read(&e.app, BASE).await;
    let peer_row = &overview["peers"][0];
    assert_eq!(peer_row["lagChanges"], 0);
    assert_eq!(peer_row["lagSeconds"], Value::Null, "no vault is shared");
    assert_eq!(overview["vaults"], json!([]));
}

#[tokio::test]
async fn the_vaults_that_may_be_federated_are_those_no_peer_holds() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;
    let shared = user_vault();
    let waiting = user_vault();
    put_items(&e, shared, 1);
    put_items(&e, waiting, 3);
    e.replica
        .federate(shared, vec![peer])
        .await
        .expect("federated");

    let (status, list) = read(&e.app, &format!("{BASE}/shareable")).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let list = list.as_array().expect("a list");
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["vault"], waiting.to_string());
    assert_eq!(list[0]["sizeBytes"], 120);
    assert_eq!(list[0]["members"], 1);
    assert_eq!(list[0]["ownerEmail"], Value::Null);
}

#[tokio::test]
async fn reaching_peers_now_says_how_each_went() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;

    let (status, down) = write(&e.app, Method::POST, &format!("{BASE}/check"), None).await;
    assert_eq!(status, StatusCode::OK, "{down}");
    assert_eq!(down[0]["peer"], peer.0.to_string());
    assert_eq!(down[0]["reach"], "unreachable");
    assert_eq!(down[0]["detail"], "nobody answers");

    *e.mode.lock().unwrap_or_else(PoisonError::into_inner) = Mode::Mismatch(vec![9; 32]);
    let (_, mismatch) = write(&e.app, Method::POST, &format!("{BASE}/check"), None).await;
    assert_eq!(mismatch[0]["reach"], "key-mismatch");
    assert_eq!(mismatch[0]["detail"], Value::Null);
}

#[tokio::test]
async fn comparing_hash_trees_now_says_how_each_peer_went() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;

    // Nothing is shared with the peer yet: nothing to compare, and no session is opened.
    let (status, none) = write(&e.app, Method::POST, &format!("{BASE}/consistency"), None).await;
    assert_eq!(status, StatusCode::OK, "{none}");
    assert_eq!(none[0]["reach"], "nothing-shared");
    assert_eq!(none[0]["vaults"], json!([]));

    let vault = user_vault();
    put_items(&e, vault, 1);
    e.replica
        .federate(vault, vec![peer])
        .await
        .expect("federated");
    let (_, down) = write(&e.app, Method::POST, &format!("{BASE}/consistency"), None).await;
    assert_eq!(down[0]["reach"], "unreachable");
    assert_eq!(down[0]["detail"], "nobody answers");

    // A key that is not the pinned one is recorded as a mismatch.
    *e.mode.lock().unwrap_or_else(PoisonError::into_inner) = Mode::Mismatch(vec![5; 32]);
    let (_, key) = write(&e.app, Method::POST, &format!("{BASE}/consistency"), None).await;
    assert_eq!(key[0]["reach"], "key-mismatch");
    let (status, record) = read(&e.app, &format!("{BASE}/mismatches/{}", peer.0)).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["offeredKey"], hex::encode([5u8; 32]));
}

#[tokio::test]
async fn a_peers_security_shows_its_keys_suites_and_descriptor_file() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;

    let (status, security) = read(&e.app, &format!("{BASE}/peers/{}/security", peer.0)).await;
    assert_eq!(status, StatusCode::OK, "{security}");
    assert_eq!(security["peerId"], peer.0.to_string());
    assert_eq!(security["keysMatch"], true);
    assert_eq!(security["signatureOk"], true);
    assert_eq!(security["fetchError"], Value::Null);
    assert_eq!(
        security["descriptor"]["identityKey"],
        hex::encode(other.public.as_bytes())
    );
    assert_eq!(
        security["descriptor"]["notAfter"],
        other.descriptor.descriptor.not_after
    );
    let kem = &security["kem"];
    assert_eq!(kem["algorithm"], "ML-KEM-1024 + X25519");
    let fingerprint = kem["fingerprint"].as_str().expect("a fingerprint");
    assert_eq!(fingerprint.split(' ').count(), 4, "{fingerprint}");
    let first_seen = kem["firstSeenAt"].as_u64().expect("first seen");
    assert_eq!(
        kem["nextRotationAt"].as_u64().expect("next"),
        first_seen + 30 * 86_400
    );
    let suites = security["suites"].as_array().expect("suites");
    let in_use: Vec<&Value> = suites.iter().filter(|s| s["inUse"] == true).collect();
    assert_eq!(in_use.len(), 1, "{suites:?}");
    assert_eq!(
        in_use[0]["theirs"], 1,
        "the peer's first choice we also run"
    );
    assert!(
        suites
            .iter()
            .any(|s| s["name"] == Suite::Fips.name() && s["ours"].is_null())
    );

    // The descriptor as a file: the signed bytes the peer served.
    let (status, headers, bytes) = send(
        &e.app,
        Method::GET,
        &format!("{BASE}/peers/{}/descriptor", peer.0),
        &[("x-admin", "1")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, other.descriptor.to_bytes());
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/vnd.kemlock.federation-descriptor+cbor"
    );
    assert!(
        headers[header::CONTENT_DISPOSITION]
            .to_str()
            .expect("text")
            .contains("attachment")
    );

    // The key's first sighting is kept: reading again does not make it newer.
    let (_, again) = read(&e.app, &format!("{BASE}/peers/{}/security", peer.0)).await;
    assert_eq!(again["kem"]["firstSeenAt"], kem["firstSeenAt"]);

    // The peer stops answering: the kept descriptor is shown, with why a fresh one is not.
    e.served.withdraw(&other.descriptor.descriptor.addresses[0]);
    let (status, stale) = read(&e.app, &format!("{BASE}/peers/{}/security", peer.0)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stale["fetchError"], "the peer could not be reached");
    assert_eq!(stale["signatureOk"], true);
    assert_eq!(
        stale["descriptor"]["identityKey"],
        hex::encode(other.public.as_bytes())
    );
    let (status, _, bytes) = send(
        &e.app,
        Method::GET,
        &format!("{BASE}/peers/{}/descriptor", peer.0),
        &[("x-admin", "1")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, other.descriptor.to_bytes());

    let (status, _) = read(
        &e.app,
        &format!("{BASE}/peers/{}/security", ServerId::random().0),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_descriptor_with_another_identity_key_is_a_mismatch_that_can_be_kept_blocked() {
    let e = env(1);
    let other = identity(2, unix_now(), &Suite::IMPLEMENTED);
    let peer = pair(&e, &other).await;
    let vault = user_vault();
    put_items(&e, vault, 2);
    e.replica
        .federate(vault, vec![peer])
        .await
        .expect("federated");
    let uri = format!("{BASE}/mismatches/{}", peer.0);

    // No mismatch on record yet.
    let (status, problem) = read(&e.app, &uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["type"], "urn:kemlock:problem:not-found");

    // The peer's address now serves a descriptor signed by another key.
    let impostor = identity(9, unix_now(), &Suite::IMPLEMENTED);
    e.served.serve(
        &other.descriptor.descriptor.addresses[0],
        impostor.descriptor.clone(),
    );
    let (status, security) = read(&e.app, &format!("{BASE}/peers/{}/security", peer.0)).await;
    assert_eq!(status, StatusCode::OK, "{security}");
    assert_eq!(security["keysMatch"], false);

    let (status, record) = read(&e.app, &uri).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["peerId"], peer.0.to_string());
    assert_eq!(record["pinnedKey"], hex::encode(other.public.as_bytes()));
    assert_eq!(
        record["offeredKey"],
        hex::encode(impostor.public.as_bytes())
    );
    assert_eq!(record["fromAddress"], "https://s2.example.org");
    assert_eq!(record["fromHost"], "s2.example.org");
    assert_eq!(record["usualAddresses"], json!(["https://s2.example.org"]));
    assert_eq!(record["tlsValid"], true);
    assert_eq!(record["signedByPinned"], false);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["seenBefore"], false);
    assert_eq!(record["keptBlockingAt"], Value::Null);
    assert_eq!(record["localVaults"], 0);
    let paused = record["pausedVaults"].as_array().expect("paused");
    assert_eq!(paused.len(), 1);
    assert_eq!(paused[0]["vault"], vault.to_string());
    assert_eq!(paused[0]["sizeBytes"], 80);
    assert_eq!(paused[0]["waitingChanges"], 2);

    // Meeting the same key again is another attempt at a key seen before.
    read(&e.app, &format!("{BASE}/peers/{}/security", peer.0)).await;
    let (_, twice) = read(&e.app, &uri).await;
    assert_eq!(twice["attempts"], 2);
    assert_eq!(twice["firstOfferedAt"], record["firstOfferedAt"]);

    // Keeping the key blocked is a write, with the admin on record; the pin stays.
    let blocking = format!("{uri}/keep-blocking");
    let (status, _, _) = send(&e.app, Method::POST, &blocking, &[("x-admin", "1")], None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, kept) = write(&e.app, Method::POST, &blocking, None).await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert!(kept["keptBlockingAt"].is_u64());
    assert!(kept["keptBlockingBy"].is_string());
    assert_eq!(kept["pinnedKey"], hex::encode(other.public.as_bytes()));
    let (_, after) = read(&e.app, &format!("{BASE}/peers")).await;
    assert_eq!(
        after[0]["identityKey"],
        hex::encode(other.public.as_bytes())
    );

    // A peer nobody met a wrong key from has nothing to keep blocking.
    let stranger = format!("{BASE}/mismatches/{}/keep-blocking", ServerId::random().0);
    let (status, _) = write(&e.app, Method::POST, &stranger, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn this_servers_keys_and_suites_are_shown_and_changed() {
    let e = env(1);
    let (status, own) = read(&e.app, &format!("{BASE}/self")).await;
    assert_eq!(status, StatusCode::OK, "{own}");
    assert_eq!(own["server"]["name"], "s1.example.org");
    assert_eq!(own["server"]["database"], "sqlite");
    let fingerprint = own["identityFingerprint"].as_str().expect("a fingerprint");
    assert_eq!(fingerprint.split(' ').count(), 8, "{fingerprint}");
    assert_eq!(
        fingerprint.replace(' ', ""),
        hex::encode(
            &kemlock_federation::crypto::sha256(
                &hex::decode(own["server"]["identityKey"].as_str().expect("a key")).expect("hex")
            )[..16]
        )
    );
    let made_at = own["kemMadeAt"]
        .as_u64()
        .expect("the KEM key's age is known");
    assert_eq!(
        own["kemNextRotationAt"].as_u64(),
        Some(made_at + 30 * 86_400)
    );
    let names: Vec<&str> = own["suites"]
        .as_array()
        .expect("suites")
        .iter()
        .map(|s| s["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names.len(), 3, "every suite is listed, on or off");
    assert_eq!(own["suites"][0]["on"], true);
    assert_eq!(own["suites"][2]["on"], false);
    assert_eq!(
        own["suites"][2]["available"], false,
        "the FIPS suite is refused by this build"
    );
    let descriptor = kemlock_app::b64url::decode(own["descriptor"].as_str().expect("a descriptor"))
        .expect("base64url");
    SignedDescriptor::parse(&descriptor)
        .expect("a descriptor")
        .verify(unix_now(), None)
        .expect("a valid descriptor");

    // A new KEM key: the identity key stays, the descriptor is signed afresh.
    let (status, rotated) = write(
        &e.app,
        Method::POST,
        &format!("{BASE}/self/kem-rotation"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(
        rotated["server"]["identityKey"],
        own["server"]["identityKey"]
    );
    assert_ne!(rotated["descriptor"], own["descriptor"]);
    assert!(rotated["kemMadeAt"].as_u64().expect("made") >= made_at);
    assert_eq!(
        e.replica.identity().kems.len(),
        2,
        "the old KEM key stays for the overlap"
    );

    // Suites: the order is the preference, and the choice outlives a reload of the file.
    let chacha = Suite::ChaCha20Poly1305.name();
    let aes = Suite::Aes256Gcm.name();
    let body = json!({"suites": [{"name": chacha, "on": true}, {"name": aes, "on": false}]});
    let (status, chosen) = write(
        &e.app,
        Method::PUT,
        &format!("{BASE}/self/suites"),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{chosen}");
    assert_eq!(chosen["suites"][0]["name"], chacha);
    assert_eq!(chosen["suites"][0]["on"], true);
    let aes_row = chosen["suites"]
        .as_array()
        .expect("suites")
        .iter()
        .find(|s| s["name"] == aes)
        .expect("aes is listed");
    assert_eq!(aes_row["on"], false);
    assert_eq!(e.replica.identity().suites(), vec![Suite::ChaCha20Poly1305]);
    let reloaded = load_or_create(
        e.folder.path(),
        &ServerSeal::new(&KEY),
        e.replica.server_id(),
        &IdentityParams {
            address: "https://s1.example.org".to_owned(),
            operator: "Operator 1".to_owned(),
            suites: Suite::IMPLEMENTED.to_vec(),
        },
        unix_now(),
    )
    .expect("reloaded");
    assert_eq!(reloaded.suites(), vec![Suite::ChaCha20Poly1305]);

    // None of this build's suites left on, an unknown one, and a TPM this server doesn't have.
    let none = json!({"suites": [{"name": chacha, "on": false}]});
    let (status, _) = write(
        &e.app,
        Method::PUT,
        &format!("{BASE}/self/suites"),
        Some(none),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let unknown = json!({"suites": [{"name": "rot13", "on": true}]});
    let (status, _) = write(
        &e.app,
        Method::PUT,
        &format!("{BASE}/self/suites"),
        Some(unknown),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let tpm = json!({"suites": [{"name": chacha, "on": true}], "keyHolding": "tpm"});
    let (status, _) = write(
        &e.app,
        Method::PUT,
        &format!("{BASE}/self/suites"),
        Some(tpm),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let sealed = json!({"suites": [{"name": chacha, "on": true}], "keyHolding": "sealed"});
    let (status, _) = write(
        &e.app,
        Method::PUT,
        &format!("{BASE}/self/suites"),
        Some(sealed),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A new identity key, signed by the old one.
    let before = e.replica.identity().public.clone();
    let (status, change) = write(
        &e.app,
        Method::POST,
        &format!("{BASE}/self/identity-rotation"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{change}");
    assert_eq!(change["kind"], "rotation");
    assert_ne!(e.replica.identity().public, before);
    let (_, later) = read(&e.app, &format!("{BASE}/self")).await;
    assert_eq!(later["server"]["identityKey"], change["identityKey"]);
}

#[tokio::test]
async fn the_document_names_routes_the_router_answers_and_every_write_names_the_token() {
    let e = env(1);
    let (status, headers, bytes) = send(
        &e.app,
        Method::GET,
        &format!("{BASE}/openapi.json"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the document is public");
    assert_eq!(
        value(&bytes),
        serde_json::to_value(admin_openapi()).expect("a document")
    );
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .expect("text")
            .starts_with("application/json")
    );

    let doc = value(&bytes);
    let mut operations = 0;
    let mut writes = 0;
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("operations") {
            operations += 1;
            let uri = path
                .replace("{id}", &ServerId::random().0.to_string())
                .replace("{peer}", &ServerId::random().0.to_string())
                .replace("{owner}", &user_vault().to_string());
            let (status, _, _) = send(
                &e.app,
                Method::from_bytes(method.to_uppercase().as_bytes()).expect("a method"),
                &uri,
                &[],
                None,
            )
            .await;
            if path.ends_with("/openapi.json") {
                assert_eq!(status, StatusCode::OK);
            } else {
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
            }
            let names: Vec<&str> = operation["parameters"]
                .as_array()
                .map(|p| p.iter().filter_map(|p| p["name"].as_str()).collect())
                .unwrap_or_default();
            if method != "get" {
                writes += 1;
                assert!(
                    names.contains(&"Step-Up-Token"),
                    "{method} {path} should name Step-Up-Token"
                );
            } else {
                assert!(!names.contains(&"Step-Up-Token"), "{method} {path}");
            }
        }
    }
    assert_eq!(operations, 16, "every operation is documented once");
    assert_eq!(writes, 8);
    assert_eq!(
        doc["components"]["securitySchemes"]["dpop"]["type"],
        "apiKey"
    );
    for schema in [
        "ShareableDto",
        "PeerSecurityDto",
        "SelfDto",
        "MismatchDto",
        "PeerDto",
    ] {
        assert!(
            doc["components"]["schemas"][schema].is_object(),
            "{schema} is described"
        );
    }
}
