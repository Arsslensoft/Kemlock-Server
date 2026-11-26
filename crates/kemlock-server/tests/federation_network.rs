//! Federation over the real network: two servers, each on a loopback port, paired over HTTP and
//! replicating a vault over the actual peer session, a WebSocket opened by the production client
//! (`tokio-tungstenite` through `kemlock_federation::WsConnector`) instead of the channels the
//! in-process gate (`federation_gate.rs`) uses.
//!
//! Each server is `kemlock_server::build`, its router served by `axum::serve` on `127.0.0.1:0`, so
//! the descriptor, the session and the pairing messages all cross a TCP socket. The pairing routes
//! the server itself serves keep their hub inside the server, out of the test's reach, so the test
//! serves its own pairing hub (the same `pair_router`, with the production `HttpLink` to reach it)
//! on a second port per server and drives both admins' side of the exchange; the identity each
//! server pins is its real one, read from its own descriptor, and the session then opens against the
//! real server's address.
//!
//! It binds ports, so it is ignored by default. Run it with
//! `cargo test -p kemlock-server --test federation_network -- --ignored`.

use kemlock_api_fed::pair_router;
use kemlock_app::ports::{ItemStore, UserRepo};
use kemlock_domain::{
    AccountMode, Email, ItemId, KdfParams, Owner, Role, ServerId, User, UserId, VersionVector,
};
use kemlock_federation::extra::Acknowledgement;
use kemlock_federation::home::Policy;
use kemlock_federation::hub::Confirmation;
use kemlock_federation::job::RunOutcome;
use kemlock_federation::message::OfferState;
use kemlock_federation::net::Http;
use kemlock_federation::testing::draft;
use kemlock_federation::{Federation, HttpLink, Pairings, PeerRunner, WsConnector, unix_now};
use kemlock_server::{Built, Config, build};
use kemlock_store_sql::SqlStore;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-net-{}-{name}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(data: &Path, domain: &str) -> Config {
    let data = data.display().to_string();
    let domain = domain.to_owned();
    Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some(domain.clone()),
            _ => None,
        },
        None,
    )
    .expect("a valid configuration")
}

type Runner = PeerRunner<SqlStore, WsConnector<SqlStore>>;

/// A server on a loopback port, with the test's own handles on its engine.
struct Net {
    id: ServerId,
    /// The server's address, which its descriptor names and its peers connect to.
    domain: String,
    /// Where the test's pairing hub is served.
    pair_address: String,
    built: Built,
    runner: Arc<Runner>,
    facade: Federation<SqlStore, WsConnector<SqlStore>>,
    pairings: Arc<Pairings<SqlStore>>,
    tasks: Vec<JoinHandle<()>>,
    _dir: TempDir,
}

impl Net {
    async fn start(name: &str) -> Net {
        let dir = TempDir::new(name);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let pair_listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let pair_port = pair_listener.local_addr().expect("an address").port();
        let domain = format!("http://localhost:{port}");

        let built = build(&config(&dir.0, &domain)).await.expect("a server");
        let replica = built.replica.clone();
        let runner = Arc::new(PeerRunner::new(
            replica.clone(),
            WsConnector::new(replica.clone()).expect("a WebSocket client"),
            format!("net-{name}"),
        ));
        let pairings = Arc::new(Pairings::new(
            replica.clone(),
            Arc::new(HttpLink(Http::new().expect("an HTTP client"))),
        ));
        let facade = Federation::new(replica.clone(), runner.clone(), pairings.clone());

        let router = built.router.clone();
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        let pair_routes = pair_router(pairings.clone());
        let pair_server = tokio::spawn(async move {
            let _ = axum::serve(pair_listener, pair_routes).await;
        });
        Net {
            id: replica.server_id(),
            domain,
            pair_address: format!("http://127.0.0.1:{pair_port}"),
            built,
            runner,
            facade,
            pairings,
            tasks: vec![server, pair_server],
            _dir: dir,
        }
    }

    fn store(&self) -> &SqlStore {
        &self.built.store
    }

    /// One run of this server's replication job for `peer`, over the real network.
    async fn visit(&self, peer: &Net) -> RunOutcome {
        self.runner
            .run_peer(peer.id, unix_now())
            .await
            .expect("a run over the network")
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn ack() -> Acknowledgement {
    Acknowledgement {
        metadata: true,
        deletion: true,
        cross_border: true,
        by: "the admin".to_owned(),
        at: unix_now(),
    }
}

/// A public-key bundle and its signature by its own key: a federated copy of an account is kept
/// only when the bundle verifies.
fn signed_bundle() -> (Vec<u8>, Vec<u8>) {
    use kemlock_crypto::bundle::Bundle;
    use kemlock_crypto::{kx1, sig1};
    let key = sig1::SigningKey::from_bytes(&[5; 64]);
    let bundle = Bundle {
        account_id: [1; 16],
        key_version: 1,
        kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("a key"),
        sig1_public: key.public_key().expect("a public key"),
    };
    let signature = bundle.sign(&key).expect("a signature");
    (bundle.to_bytes(), signature)
}

fn new_user(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("an email"),
        name: Some("Ada".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([1; 16]),
        opaque_record: Some(vec![7; 96]),
        wrapped_root_key: vec![1; 80],
        public_bundle: signed_bundle().0,
        bundle_signature: signed_bundle().1,
        sealed_private_keys: vec![4; 120],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds loopback ports: cargo test -p kemlock-server --test federation_network -- --ignored"]
async fn two_servers_on_loopback_pair_over_http_and_replicate_an_item_over_a_websocket() {
    let a = Net::start("a").await;
    let b = Net::start("b").await;

    // The descriptor is served over HTTP and verifies against the key the server holds.
    let http = Http::new().expect("an HTTP client");
    let descriptor = http.descriptor(&a.domain).await.expect("A's descriptor");
    descriptor
        .verify(unix_now(), Some(&a.built.replica.identity().public))
        .expect("signed by A's identity key");
    assert_eq!(descriptor.descriptor.addresses, vec![a.domain.clone()]);

    // Pairing: B's admin shows a code, A's admin types it; both compare the six words and confirm.
    let now = unix_now();
    let (code, _) = b.pairings.new_code(now);
    let awaiting = a
        .pairings
        .start(&b.pair_address, &code, now)
        .await
        .expect("the code opens the exchange over HTTP");
    let there = b.pairings.awaiting(now);
    assert_eq!(there.len(), 1);
    assert_eq!(awaiting.words(), there[0].words(), "the same six words");
    for (node, other) in [(&a, &b), (&b, &a)] {
        node.pairings
            .confirm(
                other.id,
                Confirmation {
                    fingerprint_matches: true,
                    acknowledgement: Some(ack()),
                },
                now,
            )
            .await
            .expect("the pairing is confirmed");
    }
    let peers = a.facade.peers().await.expect("peers");
    assert_eq!(peers.len(), 1);
    // The address A's admin typed to pair is kept first, ahead of the one B's descriptor lists.
    assert_eq!(
        peers[0].peer.addresses,
        vec![b.pair_address.clone(), b.domain.clone()]
    );

    // A vault at A with one item, federated to B.
    let member = new_user("ada@example.org");
    UserRepo::insert(a.store(), &member)
        .await
        .expect("an account");
    let owner = Owner::User(member.id);
    let item = ItemId::random();
    ItemStore::put(a.store(), draft(item, owner, None, 1, 1_000))
        .await
        .expect("an item");
    a.facade
        .set_policy(owner, Policy::Federated, vec![b.id])
        .await
        .expect("the home federates the vault");

    // A opens a session to B over a real WebSocket and offers the vault; B's admin accepts it.
    let RunOutcome::Done(statuses) = a.visit(&b).await else {
        panic!("a run");
    };
    assert_eq!(
        statuses[0].offer,
        Some(OfferState::Pending),
        "{:?}",
        statuses[0]
    );
    b.facade.accept_offer(owner).await.expect("B accepts");
    let RunOutcome::Done(statuses) = a.visit(&b).await else {
        panic!("a run");
    };
    assert_eq!(
        statuses[0].offer,
        Some(OfferState::Accepted),
        "{:?}",
        statuses[0]
    );

    // B opens a session to A and pulls the item.
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].pulled.applied, 1, "{:?}", statuses[0]);
    let held = ItemStore::changes_since(b.store(), &[owner], &VersionVector::new(), 500)
        .await
        .expect("changes")
        .items;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].id, item);
    assert_eq!(
        held[0].change.origin, a.id,
        "the change is A's, signed by A"
    );

    // The session was a real one: B's status shows a successful run and no key alert.
    let status = b.runner.status_of(a.id).expect("a status");
    assert!(status.last_success.is_some());
    assert!(status.key_mismatch.is_none());
    assert!(status.last_error.is_none());
}
