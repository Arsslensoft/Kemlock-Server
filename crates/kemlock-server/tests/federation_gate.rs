//! The federation gate: three servers in one process, driven through their own code.
//!
//! The servers are built by `kemlock_server::build_with`, each with its own database and data
//! folder, and reach each other through a [`Fabric`] instead of sockets: a peer session is the
//! real handshake and sealed frames over channels (`kemlock_api_fed::serve_session` on the far
//! end, `kemlock_federation::SecureChannel` on the near end), and pairing messages are handed to
//! the other server's `Pairings`. The phone is a DPoP key and the servers' own routers.
//!
//! The script: pairing with a code and a fingerprint (a wrong code fails and burns the code);
//! federating a vault, its consent and replication to two replicas (items, the member's account
//! without an OPAQUE record, the device registration); the phone signs in on a replica with its
//! device key; the home goes down and items keep syncing through the replicas, two of them
//! editing one item apart (siblings, and the resolve path); a replica is promoted, the other
//! replica follows, and when the old home returns it is fenced: it takes the promotion, its
//! stale home-only write is quarantined, and it can no longer make home records.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use kemlock_api_fed::{Duplex, FedState, serve_session};
use kemlock_api_kem::testing::{DpopSigner, ProofClaims};
use kemlock_app::b64url;
use kemlock_app::dedup::TagStore;
use kemlock_app::federation_view::BoxFut;
use kemlock_app::policies::PolicyRepo;
use kemlock_app::ports::{DeviceRepo, Event, EventLog, ItemStore, UserRepo};
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_crypto::sig1;
use kemlock_domain::policies::SpacePolicies;
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee,
    KeyCopy, Member, MemberState, Space, SpaceRole,
};
use kemlock_domain::{
    AccountMode, DedupTag, Device, DeviceId, DeviceKind, Email, ItemId, KdfParams, Owner, Revision,
    Role, ServerId, SpaceId, TagSet, User, UserId, VersionVector,
};
use kemlock_federation::descriptor::VALIDITY_SECS;
use kemlock_federation::extra::Acknowledgement;
use kemlock_federation::home::Policy;
use kemlock_federation::hub::Confirmation;
use kemlock_federation::job::RunOutcome;
use kemlock_federation::keyrecs::{IdentityRotator, rotation_record};
use kemlock_federation::message::OfferState;
use kemlock_federation::ports::{
    HomeStatus, LogSwitches, Peer, PeerRepo, PeerState, ReplicaStore, VaultRepo,
};
use kemlock_federation::relay::OriginKeys;
use kemlock_federation::testing::{draft, draft_with};
use kemlock_federation::{
    Connector, DescriptorParams, FedError, Federation, KemPair, LocalIdentity, PairingLink,
    Pairings, PeerRunner, Replica, SecureChannel, Transport, unix_now,
};
use kemlock_server::{Built, Config, RunError};
use kemlock_store_sql::SqlStore;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tower::ServiceExt;
use uuid::Uuid;

// ---- the network between the servers ----

/// What one server offers the others: its session endpoint and its pairing endpoint.
#[derive(Clone)]
struct Target {
    state: FedState<SqlStore>,
    pairings: Arc<Pairings<SqlStore>>,
}

/// Who can reach whom. A server that is down can't be reached; one that is up can.
#[derive(Default)]
struct Fabric {
    nodes: Mutex<HashMap<ServerId, Target>>,
    addresses: Mutex<HashMap<String, ServerId>>,
    down: Mutex<HashSet<ServerId>>,
}

impl Fabric {
    fn register(&self, id: ServerId, address: &str, target: Target) {
        self.nodes.lock().expect("lock").insert(id, target);
        self.addresses
            .lock()
            .expect("lock")
            .insert(address.to_owned(), id);
    }

    fn set_down(&self, id: ServerId, down: bool) {
        let mut set = self.down.lock().expect("lock");
        if down {
            set.insert(id);
        } else {
            set.remove(&id);
        }
    }

    fn reach(&self, id: ServerId) -> Option<Target> {
        if self.down.lock().expect("lock").contains(&id) {
            return None;
        }
        self.nodes.lock().expect("lock").get(&id).cloned()
    }

    fn reach_address(&self, address: &str) -> Option<Target> {
        let id = *self.addresses.lock().expect("lock").get(address)?;
        self.reach(id)
    }
}

/// The client end of a session over two channels.
struct ChanTransport {
    tx: UnboundedSender<Vec<u8>>,
    rx: UnboundedReceiver<Vec<u8>>,
}

impl Transport for ChanTransport {
    async fn exchange(&mut self, message: Vec<u8>) -> Result<Vec<u8>, FedError> {
        self.tx
            .send(message)
            .map_err(|_| FedError::Frame("the session was closed"))?;
        self.rx
            .recv()
            .await
            .ok_or(FedError::Frame("the session was closed"))
    }
}

/// The server end of a session over the same two channels.
struct ChanDuplex {
    rx: UnboundedReceiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
}

impl Duplex for ChanDuplex {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    async fn send(&mut self, message: Vec<u8>) -> bool {
        self.tx.send(message).is_ok()
    }
}

/// Opens sessions to the other servers of the fabric.
#[derive(Clone)]
struct Net {
    fabric: Arc<Fabric>,
    replica: Arc<Replica<SqlStore>>,
}

impl Connector for Net {
    type Chan = SecureChannel<ChanTransport>;

    async fn connect(&self, peer: &Peer) -> Result<Self::Chan, FedError> {
        let target = self
            .fabric
            .reach(peer.id)
            .ok_or_else(|| FedError::Remote("the peer can't be reached".to_owned()))?;
        let (to_server, from_client) = unbounded_channel();
        let (to_client, from_server) = unbounded_channel();
        let state = target.state.clone();
        tokio::spawn(async move {
            let mut io = ChanDuplex {
                rx: from_client,
                tx: to_client,
            };
            let _ = serve_session(&state, &mut io, unix_now).await;
        });
        let descriptor = target.state.replica().identity().descriptor.clone();
        self.replica
            .connect(
                peer.id,
                &descriptor,
                ChanTransport {
                    tx: to_server,
                    rx: from_server,
                },
                unix_now(),
            )
            .await
    }

    async fn close(&self, channel: Self::Chan) -> Result<(), FedError> {
        channel.close().await
    }

    async fn send_key_record(&self, peer: &Peer, record: Vec<u8>) -> Result<(), FedError> {
        let target = self
            .fabric
            .reach(peer.id)
            .ok_or_else(|| FedError::Remote("the peer can't be reached".to_owned()))?;
        target
            .state
            .replica()
            .accept_key_record(&record, unix_now())
            .await
            .map(|_| ())
    }
}

/// Hands pairing messages to the other server's `Pairings`.
struct FabricLink {
    fabric: Arc<Fabric>,
}

impl PairingLink for FabricLink {
    fn start(&self, address: &str, message: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>, FedError>> {
        let target = self.fabric.reach_address(address);
        Box::pin(async move {
            target
                .ok_or_else(|| FedError::Remote("the server can't be reached".to_owned()))?
                .pairings
                .respond(&message, unix_now())
        })
    }

    fn finish(
        &self,
        address: &str,
        initiator: ServerId,
        message: Vec<u8>,
    ) -> BoxFut<'_, Result<(), FedError>> {
        let target = self.fabric.reach_address(address);
        Box::pin(async move {
            target
                .ok_or_else(|| FedError::Remote("the server can't be reached".to_owned()))?
                .pairings
                .finish(initiator, &message, unix_now())
        })
    }
}

// ---- a server ----

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-fed-{}-{name}-{nanos}",
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

struct Node {
    id: ServerId,
    domain: String,
    built: Built,
    runner: Arc<PeerRunner<SqlStore, Net>>,
    facade: Federation<SqlStore, Net>,
    pairings: Arc<Pairings<SqlStore>>,
    _dir: TempDir,
}

impl Node {
    async fn new(name: &str, fabric: &Arc<Fabric>) -> Node {
        let dir = TempDir::new(name);
        let domain = format!("https://{name}.test");
        let for_build = fabric.clone();
        let built = kemlock_server::app::build_with(&config(&dir.0, &domain), move |replica| {
            let net = Net {
                fabric: for_build.clone(),
                replica: replica.clone(),
            };
            let link: Arc<dyn PairingLink> = Arc::new(FabricLink { fabric: for_build });
            Ok::<_, RunError>((net, link))
        })
        .await
        .expect("a server");
        let replica = built.replica.clone();
        let id = replica.server_id();
        // The test drives the engine itself, so it holds its own job, pairing hub and facade over
        // the server's replica and store.
        let runner = Arc::new(PeerRunner::new(
            replica.clone(),
            Net {
                fabric: fabric.clone(),
                replica: replica.clone(),
            },
            format!("gate-{name}"),
        ));
        let pairings = Arc::new(Pairings::new(
            replica.clone(),
            Arc::new(FabricLink {
                fabric: fabric.clone(),
            }),
        ));
        let facade = Federation::new(replica.clone(), runner.clone(), pairings.clone())
            .with_rotator(Arc::new(TestRotator));
        fabric.register(
            id,
            &domain,
            Target {
                state: FedState::new(replica),
                pairings: pairings.clone(),
            },
        );
        Node {
            id,
            domain,
            built,
            runner,
            facade,
            pairings,
            _dir: dir,
        }
    }

    fn store(&self) -> &SqlStore {
        &self.built.store
    }

    /// One run of this server's job for `peer`.
    async fn visit(&self, peer: &Node) -> RunOutcome {
        self.runner
            .run_peer(peer.id, unix_now())
            .await
            .expect("a run")
    }

    /// The items this server holds of `owner` as a device would sync them.
    async fn items(&self, owner: Owner) -> Vec<kemlock_domain::Item> {
        ItemStore::changes_since(self.store(), &[owner], &VersionVector::new(), 500)
            .await
            .expect("changes")
            .items
    }
}

// ---- the phone ----

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "a JSON body, got {e}: {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

/// A phone talking to one server: the shared DPoP key, that server's nonce and router.
struct Phone {
    router: Router,
    domain: String,
    key: Arc<DpopSigner>,
    nonce: Mutex<Option<String>>,
    jti: AtomicU64,
}

impl Phone {
    fn new(node: &Node, key: &Arc<DpopSigner>) -> Phone {
        Phone {
            router: node.built.router.clone(),
            domain: node.domain.clone(),
            key: key.clone(),
            nonce: Mutex::new(None),
            jti: AtomicU64::new(1),
        }
    }

    async fn once(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Reply {
        let path = uri.split('?').next().unwrap_or(uri);
        let nonce = self.nonce.lock().expect("lock").clone();
        let jti = format!("jti-{}", self.jti.fetch_add(1, Ordering::Relaxed));
        let htu = format!("{}{path}", self.domain);
        let proof = self.key.proof(&ProofClaims {
            method,
            htu: &htu,
            iat: i64::try_from(unix_now()).unwrap_or(0),
            jti: &jti,
            access_token: token,
            nonce: nonce.as_deref(),
        });
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("dpop", proof);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("DPoP {token}"));
        }
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        let request = match body {
            Some(json) => builder
                .header("content-type", "application/json")
                .body(Body::from(json.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("a valid request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router never fails");
        let (parts, body) = response.into_parts();
        if let Some(fresh) = parts
            .headers
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
        {
            *self.nonce.lock().expect("lock") = Some(fresh.to_owned());
        }
        Reply {
            status: parts.status,
            body: axum::body::to_bytes(body, usize::MAX)
                .await
                .expect("a readable body")
                .to_vec(),
        }
    }

    /// One request with a proof, retried once when the server asks for a nonce.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        let first = self.once(method, uri, token, extra, body.as_ref()).await;
        if first.status == StatusCode::UNAUTHORIZED
            && first.json()["type"] == "urn:kemlock:problem:use-dpop-nonce"
        {
            return self.once(method, uri, token, extra, body.as_ref()).await;
        }
        first
    }

    /// Signs in with the device key (no password) and returns the access token.
    async fn sign_in(&self, device: DeviceId) -> String {
        let challenge = self
            .send(
                "POST",
                "/kem/v1/auth/device-key/challenge",
                None,
                &[],
                Some(json!({"deviceId": device.0})),
            )
            .await;
        assert_eq!(challenge.status, StatusCode::OK, "{:?}", challenge.json());
        let challenge = challenge.json()["challenge"]
            .as_str()
            .expect("a challenge")
            .to_owned();
        let verified = self
            .send(
                "POST",
                "/kem/v1/auth/device-key/verify",
                None,
                &[],
                Some(json!({"challenge": challenge})),
            )
            .await;
        assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.json());
        verified.json()["accessToken"]
            .as_str()
            .expect("an access token")
            .to_owned()
    }

    /// Writes one revision of an item as the phone's device would.
    async fn put(&self, token: &str, owner: Owner, id: ItemId, revision: u64, fill: u8) -> Reply {
        let body = json!({
            "id": id.0,
            "owner": format!("user:{}", owner_user(owner).0),
            "kind": "login",
            "format": "kem1",
            "revision": revision,
            "keyVersion": 1,
            "ciphertext": b64url::encode(&[fill; 40]),
            "itemKey": b64url::encode(&[9u8; 60]),
        });
        let (name, value) = if revision == 1 {
            ("if-none-match", "*".to_owned())
        } else {
            ("if-match", (revision - 1).to_string())
        };
        self.send(
            "PUT",
            &format!("/kem/v1/items/{}", id.0),
            Some(token),
            &[(name, value.as_str())],
            Some(body),
        )
        .await
    }

    async fn sync(&self, token: &str) -> Value {
        let reply = self
            .send("GET", "/kem/v1/sync", Some(token), &[], None)
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        reply.json()
    }
}

fn owner_user(owner: Owner) -> UserId {
    match owner {
        Owner::User(user) => user,
        Owner::Space(_) => panic!("a personal vault"),
    }
}

fn item_ids(sync: &Value) -> HashSet<String> {
    sync["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["id"].as_str().expect("an id").to_owned())
        .collect()
}

// ---- the script ----

fn ack() -> Acknowledgement {
    Acknowledgement {
        metadata: true,
        deletion: true,
        cross_border: true,
        by: "the admin".to_owned(),
        at: unix_now(),
    }
}

/// Two admins pair their servers: `shower` shows a code, `typer` types it, both compare the six
/// words and confirm.
async fn pair(shower: &Node, typer: &Node) {
    let now = unix_now();
    let (code, _) = shower.pairings.new_code(now);
    let awaiting = typer
        .pairings
        .start(&shower.domain, &code, now)
        .await
        .expect("the code opens the exchange");
    let there = shower.pairings.awaiting(now);
    assert_eq!(there.len(), 1);
    assert_eq!(
        awaiting.words(),
        there[0].words(),
        "both admins read the same six words"
    );
    assert_eq!(awaiting.words().len(), 6);
    for (node, other) in [(shower, typer), (typer, shower)] {
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
}

#[tokio::test]
async fn three_servers_pair_replicate_fail_over_promote_and_fence() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("a", &fabric).await;
    let b = Node::new("b", &fabric).await;
    let c = Node::new("c", &fabric).await;

    // ---- pairing ----
    // A wrong code is a refusal that tells the typing side nothing, and burns the code.
    let now = unix_now();
    let (code, _) = a.pairings.new_code(now);
    let wrong = if code.starts_with('0') {
        code.replacen('0', "1", 1)
    } else {
        code.replacen(&code[..1], "0", 1)
    };
    assert!(b.pairings.start(&a.domain, &wrong, now).await.is_err());
    assert!(
        b.pairings.start(&a.domain, &code, now).await.is_err(),
        "the code was good for one attempt"
    );
    assert!(a.pairings.awaiting(now).is_empty());

    pair(&a, &b).await;
    pair(&a, &c).await;
    pair(&b, &c).await;
    let peers = a.facade.peers().await.expect("peers");
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().all(|p| p.fingerprint.split('-').count() == 6));
    assert!(
        peers.iter().all(|p| p
            .acknowledgement
            .as_ref()
            .is_some_and(Acknowledgement::complete)),
        "the admin's acknowledgements are kept"
    );

    // ---- a vault at A, with a member, a device and three items ----
    let phone_key = Arc::new(DpopSigner::es256());
    let user = User {
        id: UserId::random(),
        email: Email::parse("ada@example.org").expect("an email"),
        name: Some("Ada".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([1; 16]),
        opaque_record: Some(vec![7; 96]),
        wrapped_root_key: vec![1; 80],
        public_bundle: vec![2; 200],
        bundle_signature: vec![3; 100],
        sealed_private_keys: vec![4; 120],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    };
    let owner = Owner::User(user.id);
    UserRepo::insert(a.store(), &user).await.expect("a user");
    let device = Device {
        id: DeviceId::random(),
        user: user.id,
        name: "Phone".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some(phone_key.thumbprint()),
        created_at: OffsetDateTime::now_utc(),
        last_seen_at: OffsetDateTime::now_utc(),
    };
    DeviceRepo::upsert(a.store(), &device)
        .await
        .expect("a device");
    let ids: Vec<ItemId> = (0..3).map(|_| ItemId::random()).collect();
    for (n, id) in ids.iter().enumerate() {
        ItemStore::put(a.store(), draft(*id, owner, None, 1, 1_000 + n as u64))
            .await
            .expect("an item");
    }
    let shared = ids[0];

    // ---- federating it: the replicas must accept ----
    // A vault is Local by default, and only its home changes that.
    assert!(
        b.facade
            .set_policy(owner, Policy::Federated, vec![a.id])
            .await
            .is_err(),
        "B holds no such vault"
    );
    a.facade
        .set_policy(owner, Policy::Federated, vec![b.id, c.id])
        .await
        .expect("the home federates its vault");
    for replica in [&b, &c] {
        let RunOutcome::Done(statuses) = a.visit(replica).await else {
            panic!("a run");
        };
        assert_eq!(statuses[0].offer, Some(OfferState::Pending));
        let offers = replica.facade.offers().await.expect("offers");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].state, OfferState::Pending);
        // Nothing is copied before the admin accepts.
        assert!(replica.items(owner).await.is_empty());
        replica
            .facade
            .accept_offer(owner)
            .await
            .expect("the admin accepts");
    }

    // ---- replication ----
    for replica in [&b, &c] {
        let RunOutcome::Done(statuses) = a.visit(replica).await else {
            panic!("a run");
        };
        assert_eq!(statuses[0].offer, Some(OfferState::Accepted));
        let RunOutcome::Done(statuses) = replica.visit(&a).await else {
            panic!("a run");
        };
        assert_eq!(statuses[0].pulled.applied, 3, "{:?}", statuses[0]);
        assert_eq!(replica.items(owner).await.len(), 3);
        // The member's account is there without the OPAQUE record, and so is the device.
        let copy = UserRepo::by_id(replica.store(), user.id)
            .await
            .expect("a read")
            .expect("the account was copied");
        assert_eq!(copy.email, user.email);
        assert_eq!(copy.opaque_record, None);
        assert_eq!(copy.role, Role::User);
        assert_eq!(copy.wrapped_root_key, user.wrapped_root_key);
        let devices = DeviceRepo::list(replica.store(), user.id)
            .await
            .expect("devices");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].dpop_jkt, device.dpop_jkt);
    }
    // The replicas also hold each other's changes, and agree.
    b.visit(&c).await;
    c.visit(&b).await;

    // ---- the phone, on a replica ----
    let phone_b = Phone::new(&b, &phone_key);
    let token_b = phone_b.sign_in(device.id).await;
    let synced = phone_b.sync(&token_b).await;
    assert_eq!(item_ids(&synced).len(), 3);
    assert_eq!(synced["siblings"].as_array().expect("siblings").len(), 0);
    // The vault's servers are the home first, then the replicas in order.
    let config = phone_b
        .send(
            "GET",
            &format!("/kem/v1/config?vault=user:{}", user.id.0),
            None,
            &[],
            None,
        )
        .await;
    assert_eq!(config.status, StatusCode::OK);
    let vaults = config.json()["vaults"].clone();
    let servers = vaults[0]["servers"].as_array().expect("servers");
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0]["role"], "home");
    assert_eq!(servers[0]["address"], a.domain.as_str());
    assert_eq!(servers[1]["address"], b.domain.as_str());
    assert_eq!(servers[2]["address"], c.domain.as_str());
    assert_eq!(vaults[0]["epoch"], 1);
    // A device that was never registered here signs in with nothing it could present.
    let stranger = Phone::new(&b, &Arc::new(DpopSigner::es256()));
    let refused = stranger
        .send(
            "POST",
            "/kem/v1/auth/device-key/challenge",
            None,
            &[],
            Some(json!({"deviceId": device.id.0})),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    // ---- the home goes down: items keep syncing through the replicas ----
    fabric.set_down(a.id, true);
    assert!(b.runner.run_peer(a.id, unix_now()).await.is_err());
    let down = b.runner.status_of(a.id).expect("a status");
    assert!(down.down_since.is_some() && down.last_error.is_some());

    let fresh = ItemId::random();
    let created = phone_b.put(&token_b, owner, fresh, 1, 0xB1).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    b.visit(&c).await;
    c.visit(&b).await;
    let phone_c = Phone::new(&c, &phone_key);
    let token_c = phone_c.sign_in(device.id).await;
    let synced_c = phone_c.sync(&token_c).await;
    assert!(
        item_ids(&synced_c).contains(&fresh.0.to_string()),
        "an item written on one replica syncs from the other while the home is away"
    );

    // Two replicas edit one item apart: both versions are kept, the sync lists the one that
    // isn't the head, and a merged write plus a resolve call settles it.
    let edited = phone_b.put(&token_b, owner, shared, 2, 0xB2).await;
    assert_eq!(edited.status, StatusCode::OK, "{:?}", edited.json());
    ItemStore::put(
        c.store(),
        draft_with(shared, owner, Some(1), 2, 5_000, 0xC2),
    )
    .await
    .expect("an edit at C");
    b.visit(&c).await;
    c.visit(&b).await;
    let conflicted = phone_b.sync(&token_b).await;
    let sets = conflicted["siblings"].as_array().expect("siblings");
    assert_eq!(sets.len(), 1, "{conflicted}");
    assert_eq!(sets[0]["itemId"], shared.0.to_string());
    assert_eq!(sets[0]["versions"].as_array().expect("versions").len(), 1);
    let head_revision = conflicted["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["id"] == shared.0.to_string())
        .expect("the item")["revision"]
        .as_u64()
        .expect("a revision");
    let merged = phone_b
        .put(&token_b, owner, shared, head_revision + 1, 0xD3)
        .await;
    assert_eq!(merged.status, StatusCode::OK, "{:?}", merged.json());
    let resolved = phone_b
        .send(
            "POST",
            &format!("/kem/v1/items/{}/siblings/resolve", shared.0),
            Some(&token_b),
            &[],
            None,
        )
        .await;
    assert_eq!(resolved.status, StatusCode::OK, "{:?}", resolved.json());
    assert_eq!(resolved.json()["resolved"], 1);
    let settled = phone_b.sync(&token_b).await;
    assert_eq!(settled["siblings"].as_array().expect("siblings").len(), 0);
    b.visit(&c).await;
    c.visit(&b).await;
    assert!(
        ReplicaStore::siblings(c.store(), owner, shared)
            .await
            .expect("siblings")
            .is_empty(),
        "the merged version supersedes both, so the other replica drops them too"
    );

    // ---- promotion: B becomes the home ----
    // The admin did a fresh check (the HTTP route enforces it); the facade signs the record.
    let record = b
        .facade
        .promote(owner, unix_now())
        .await
        .expect("B is a replica of the vault");
    assert!(!record.is_empty());
    let after = VaultRepo::get_vault(b.store(), owner)
        .await
        .expect("a read")
        .expect("the vault");
    assert_eq!((after.home, after.epoch), (b.id, 2));
    assert_eq!(after.replicas, vec![c.id, a.id], "the old home goes last");
    // C takes the promotion when B visits it.
    b.visit(&c).await;
    let at_c = VaultRepo::get_vault(c.store(), owner)
        .await
        .expect("a read")
        .expect("the vault");
    assert_eq!((at_c.home, at_c.epoch), (b.id, 2));

    // The old home, cut off and unaware, makes a home-only write under epoch 1.
    let mut renamed = UserRepo::by_id(a.store(), user.id)
        .await
        .expect("a read")
        .expect("the user");
    renamed.name = Some("Ada Lovelace".to_owned());
    renamed.updated_at = OffsetDateTime::now_utc();
    UserRepo::update(a.store(), &renamed)
        .await
        .expect("an update");
    assert_eq!(
        a.built
            .replica
            .publish_members(owner)
            .await
            .expect("a record"),
        1,
        "A still believes it is the home"
    );

    // ---- the old home returns and is fenced ----
    fabric.set_down(a.id, false);
    // First visit: B tells A of the promotion. A is the home it takes the vault from, so A holds
    // the promotion for its own admin instead of applying it: a replica can't take a vault over.
    b.visit(&a).await;
    let at_a = VaultRepo::get_vault(a.store(), owner)
        .await
        .expect("a read")
        .expect("the vault");
    assert_eq!((at_a.home, at_a.epoch), (a.id, 1), "A waits for its admin");
    assert!(at_a.held_demotion.is_some(), "A holds the promotion");
    // A's admin accepts it (the HTTP route asks for a fresh check).
    let at_a = a
        .facade
        .accept_demotion(owner)
        .await
        .expect("A's admin accepts");
    assert_eq!((at_a.home, at_a.epoch), (b.id, 2), "A took the promotion");
    assert!(at_a.held_demotion.is_none());
    assert_eq!(at_a.replicas, vec![c.id, a.id]);
    // Second visit: B pulls what A wrote while it was cut off. The home-only write is of an older
    // epoch, so it is kept for the admins and applied nowhere.
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].home_quarantined, 1, "{:?}", statuses[0]);
    let quarantined = b.facade.quarantined(owner).await.expect("quarantine");
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].status, HomeStatus::Quarantined);
    assert_eq!(quarantined[0].record.epoch, 1);
    assert_eq!(quarantined[0].record.signer, a.id);
    let at_b = UserRepo::by_id(b.store(), user.id)
        .await
        .expect("a read")
        .expect("the copy");
    assert_eq!(
        at_b.name,
        Some("Ada".to_owned()),
        "the stale rename was not applied"
    );
    // A can no longer make home records, and it catches up on the items written while it was away.
    assert_eq!(
        a.built
            .replica
            .publish_members(owner)
            .await
            .expect("no record"),
        0
    );
    a.visit(&b).await;
    let held = a.items(owner).await;
    assert!(
        held.iter().any(|i| i.id == fresh),
        "A has the item written while it was away"
    );
    assert_eq!(held.len(), 4);
    // The vault's servers now start with the new home, with the promotion record to check.
    let phone_a = Phone::new(&a, &phone_key);
    let config = phone_a
        .send(
            "GET",
            &format!("/kem/v1/config?vault=user:{}", user.id.0),
            None,
            &[],
            None,
        )
        .await;
    let vaults = config.json()["vaults"].clone();
    assert_eq!(vaults[0]["epoch"], 2);
    let servers = vaults[0]["servers"].as_array().expect("servers");
    assert_eq!(servers[0]["address"], b.domain.as_str());
    assert_eq!(servers[0]["role"], "home");
    assert!(vaults[0]["promotion"].is_string());
}

// ---- a space: roles, keys and policies are home-only ----

fn new_user(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("an email"),
        name: None,
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([1; 16]),
        opaque_record: Some(vec![7; 96]),
        wrapped_root_key: vec![1; 80],
        public_bundle: vec![2; 200],
        bundle_signature: vec![3; 100],
        sealed_private_keys: vec![4; 120],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn vault_space(vault: Owner) -> SpaceId {
    match vault {
        Owner::Space(space) => space,
        Owner::User(_) => panic!("a space"),
    }
}

#[tokio::test]
async fn a_space_follows_its_home_in_roles_keys_and_policies_and_stale_writes_are_kept() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("space-a", &fabric).await;
    let b = Node::new("space-b", &fabric).await;
    pair(&a, &b).await;

    // A space at A: its owner (an account at A), a collection, the collection key sealed to the
    // owner, and a policy.
    let owner_account = new_user("grace@example.org");
    UserRepo::insert(a.store(), &owner_account)
        .await
        .expect("an account");
    let space = SpaceId::random();
    let vault = Owner::Space(space);
    let now = OffsetDateTime::now_utc();
    let collection = Collection {
        id: CollectionId::random(),
        space,
        parent: None,
        name: vec![2; 40],
        key_version: 1,
        stale_since: None,
        created_at: now,
    };
    SpaceRepo::create(
        a.store(),
        SpaceChanges {
            space: Some(Space {
                id: space,
                name: vec![1; 40],
                key_version: 1,
                keys_pending_since: None,
                created_at: now,
                updated_at: now,
            }),
            members: vec![Member {
                space,
                user: owner_account.id,
                role: SpaceRole::Owner,
                custom: CustomPermissions::NONE,
                state: MemberState::Confirmed,
                invited_by: owner_account.id,
                invited_at: now,
                accepted_at: Some(now),
                sealed_space_key: Some(vec![5; 64]),
                key_version: Some(1),
                confirmation: None,
                revoked_at: None,
            }],
            collections: vec![collection.clone()],
            grants: vec![CollectionGrant {
                collection: collection.id,
                grantee: Grantee::Member(owner_account.id),
                permission: CollectionPermission::Manage,
            }],
            key_copies: vec![KeyCopy {
                collection: collection.id,
                user: owner_account.id,
                key_version: 1,
                sealed: vec![9; 80],
            }],
            ..SpaceChanges::new(space)
        },
    )
    .await
    .expect("a space");
    PolicyRepo::put_space_policies(
        a.store(),
        space,
        &SpacePolicies {
            require_sso: true,
            ..SpacePolicies::default()
        },
        owner_account.id,
        now,
    )
    .await
    .expect("policies");

    // Federate it; B accepts; B takes what the home published.
    a.facade
        .set_policy(vault, Policy::Federated, vec![b.id])
        .await
        .expect("the home federates the space");
    a.visit(&b).await;
    b.facade.accept_offer(vault).await.expect("B accepts");
    a.visit(&b).await;
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert!(statuses[0].home_applied >= 6, "{:?}", statuses[0]);
    let held = SpaceRepo::load(b.store(), vault_space(vault))
        .await
        .expect("a read")
        .expect("the space was copied");
    assert_eq!(held.members.len(), 1);
    assert_eq!(held.members[0].role, SpaceRole::Owner);
    assert_eq!(held.collections.len(), 1);
    assert_eq!(held.grants.len(), 1);
    assert_eq!(
        SpaceRepo::key_copies(b.store(), space, owner_account.id)
            .await
            .expect("keys")
            .len(),
        1,
        "the collection key sealed to the owner arrived"
    );
    assert!(
        PolicyRepo::space_policies(b.store(), space)
            .await
            .expect("policies")
            .policies
            .require_sso
    );

    // A policy changes at the home and follows at the next visit.
    PolicyRepo::put_space_policies(
        a.store(),
        space,
        &SpacePolicies {
            require_sso: true,
            two_step: true,
            ..SpacePolicies::default()
        },
        owner_account.id,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect("policies");
    a.visit(&b).await;
    b.visit(&a).await;
    assert!(
        PolicyRepo::space_policies(b.store(), space)
            .await
            .expect("policies")
            .policies
            .two_step
    );

    // A replica refuses a home-only write and names the home.
    let phone = Phone::new(&b, &Arc::new(DpopSigner::es256()));
    let refused = phone
        .once(
            "POST",
            &format!("/kem/v1/spaces/{}/members", space.0),
            None,
            &[],
            Some(&json!({})),
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json());
    assert_eq!(refused.json()["type"], "urn:kemlock:problem:home-only");
    assert_eq!(refused.json()["home"]["address"], a.domain.as_str());

    // B is promoted. A, unaware, changes a policy under epoch 1: B keeps it for the admins.
    b.facade
        .promote(vault, unix_now())
        .await
        .expect("B is a replica of the space");
    PolicyRepo::put_space_policies(
        a.store(),
        space,
        &SpacePolicies {
            require_sso: true,
            two_step: true,
            single_space: true,
            ..SpacePolicies::default()
        },
        owner_account.id,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect("policies");
    assert_eq!(
        a.built
            .replica
            .publish_space_state(vault)
            .await
            .expect("a record"),
        1,
        "A still believes it is the home"
    );
    // B tells A of the promotion; A holds it until its admin accepts it.
    b.visit(&a).await;
    a.facade
        .accept_demotion(vault)
        .await
        .expect("A's admin accepts");
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].home_quarantined, 1, "{:?}", statuses[0]);
    let kept = b.facade.quarantined(vault).await.expect("quarantine");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].record.kind, "space-policies");
    assert_eq!(kept[0].record.epoch, 1);
    assert!(
        !PolicyRepo::space_policies(b.store(), space)
            .await
            .expect("policies")
            .policies
            .single_space,
        "the stale policy was not applied"
    );
    // The old home is fenced now: it makes no more records, and refuses the write itself.
    assert_eq!(
        a.built
            .replica
            .publish_space_state(vault)
            .await
            .expect("no record"),
        0
    );
    let phone_a = Phone::new(&a, &Arc::new(DpopSigner::es256()));
    let refused = phone_a
        .once(
            "POST",
            &format!("/kem/v1/spaces/{}/grants", space.0),
            None,
            &[],
            Some(&json!({})),
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json());
    assert_eq!(refused.json()["home"]["address"], b.domain.as_str());
}

// ---- the event logs: only when the sender's Send and the receiver's Pull are both on ----

#[tokio::test]
async fn event_logs_flow_only_when_both_switches_are_on() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("log-a", &fabric).await;
    let b = Node::new("log-b", &fabric).await;
    pair(&a, &b).await;

    let member = new_user("lena@example.org");
    UserRepo::insert(a.store(), &member)
        .await
        .expect("an account");
    let owner = Owner::User(member.id);
    a.facade
        .set_policy(owner, Policy::Federated, vec![b.id])
        .await
        .expect("the home federates the vault");
    a.visit(&b).await;
    b.facade.accept_offer(owner).await.expect("B accepts");
    a.visit(&b).await;
    b.visit(&a).await;

    async fn log(node: &Node, actor: UserId, action: &'static str) {
        EventLog::record(
            node.store(),
            Event {
                actor: Some(actor),
                device: None,
                action,
                target: None,
                at: OffsetDateTime::now_utc(),
            },
        )
        .await
        .expect("an event");
        // Event ids are UUID v7, which sort by the millisecond they are made in.
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    }
    log(&a, member.id, "login").await;
    log(&a, member.id, "item.create").await;

    async fn set(node: &Node, peer: &Node, send: bool, pull: bool) {
        node.facade
            .set_log_switches(peer.id, LogSwitches { send, pull })
            .await
            .expect("switches");
    }
    async fn pulled(b: &Node, a: &Node) -> usize {
        let RunOutcome::Done(statuses) = b.visit(a).await else {
            panic!("a run");
        };
        statuses[0].events_pulled
    }

    // Both switches are off until an admin turns them on.
    assert_eq!(pulled(&b, &a).await, 0);
    // The sender's Send alone is not enough.
    set(&a, &b, true, false).await;
    assert_eq!(pulled(&b, &a).await, 0);
    // Nor is the receiver's Pull alone.
    set(&a, &b, false, false).await;
    set(&b, &a, false, true).await;
    assert_eq!(pulled(&b, &a).await, 0);
    assert!(
        b.facade
            .peer_events(owner, 50)
            .await
            .expect("events")
            .is_empty()
    );

    // Both on: the vault's events move, once.
    set(&a, &b, true, false).await;
    assert_eq!(pulled(&b, &a).await, 2);
    let held = b.facade.peer_events(owner, 50).await.expect("events");
    let actions: Vec<&str> = held.iter().map(|e| e.entry.action.as_str()).collect();
    assert_eq!(actions, ["item.create", "login"], "newest first");
    assert!(held.iter().all(|e| e.from == a.id));
    assert_eq!(pulled(&b, &a).await, 0);
    log(&a, member.id, "logout").await;
    assert_eq!(pulled(&b, &a).await, 1);

    // Turning Pull off stops it again.
    set(&b, &a, false, false).await;
    log(&a, member.id, "login").await;
    assert_eq!(pulled(&b, &a).await, 0);
    assert_eq!(
        b.facade.peer_events(owner, 50).await.expect("events").len(),
        3
    );
}

// ---- unpairing: the peer is asked to delete what it holds ----

#[tokio::test]
async fn unpairing_asks_the_peer_to_delete_and_a_peer_that_is_down_keeps_what_it_has() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("unpair-a", &fabric).await;
    let b = Node::new("unpair-b", &fabric).await;
    let c = Node::new("unpair-c", &fabric).await;
    pair(&a, &b).await;
    pair(&a, &c).await;

    let member = new_user("sam@example.org");
    UserRepo::insert(a.store(), &member)
        .await
        .expect("an account");
    let owner = Owner::User(member.id);
    for n in 0..2 {
        ItemStore::put(
            a.store(),
            draft(ItemId::random(), owner, None, 1, 1_000 + n),
        )
        .await
        .expect("an item");
    }
    a.facade
        .set_policy(owner, Policy::Federated, vec![b.id, c.id])
        .await
        .expect("the home federates the vault");
    for replica in [&b, &c] {
        a.visit(replica).await;
        replica.facade.accept_offer(owner).await.expect("accepts");
        a.visit(replica).await;
        replica.visit(&a).await;
        assert_eq!(replica.items(owner).await.len(), 2);
        assert!(
            UserRepo::by_id(replica.store(), member.id)
                .await
                .expect("a read")
                .is_some(),
            "the account was copied"
        );
    }

    // C is down: it can't be asked, and keeps what it has. The unpairing happens all the same.
    fabric.set_down(c.id, true);
    let report = a.facade.unpair(c.id).await.expect("unpaired");
    assert!(!report.asked);
    assert!(report.detail.is_some());
    assert!(
        report.notice.contains("can't be forced"),
        "the console says the peer can't be forced to delete"
    );
    assert_eq!(c.items(owner).await.len(), 2);
    let vault = VaultRepo::get_vault(a.store(), owner)
        .await
        .expect("a read")
        .expect("the vault");
    assert_eq!(vault.replicas, vec![b.id], "C is out of the replica order");

    // B is asked, and deletes what it holds of A's vault and the people in it.
    let report = a.facade.unpair(b.id).await.expect("unpaired");
    assert!(report.asked, "{:?}", report.detail);
    let said = report.peer_report.expect("what B says it deleted");
    assert_eq!((said.vaults, said.items, said.accounts), (1, 2, 1));
    assert!(b.items(owner).await.is_empty());
    assert!(
        UserRepo::by_id(b.store(), member.id)
            .await
            .expect("a read")
            .is_none(),
        "the account copy went"
    );
    assert!(
        VaultRepo::get_vault(b.store(), owner)
            .await
            .expect("a read")
            .is_none()
    );
    assert!(
        PeerRepo::get_peer(b.store(), a.id)
            .await
            .expect("a read")
            .is_none(),
        "B forgot A"
    );

    // A stopped copying: its vault is Local again, its own items are intact, and it has no peers.
    let vault = VaultRepo::get_vault(a.store(), owner)
        .await
        .expect("a read")
        .expect("the vault");
    assert_eq!(vault.policy, Policy::Local);
    assert!(vault.replicas.is_empty());
    assert_eq!(a.items(owner).await.len(), 2);
    assert!(a.facade.peers().await.expect("peers").is_empty());
}

// ---- identity keys: a rotation signed by the old key, and a revocation ----

/// Makes the next identity in memory, as the server's file rotator does on disk.
struct TestRotator;

impl IdentityRotator for TestRotator {
    fn rotate(&self, current: &LocalIdentity, now: u64) -> Result<LocalIdentity, FedError> {
        let d = &current.descriptor.descriptor;
        LocalIdentity::new(
            current.server,
            sig1::SigningKey::generate(),
            vec![KemPair::generate()?],
            DescriptorParams {
                suites: current.suites(),
                addresses: d.addresses.clone(),
                operator: d.operator.clone(),
                not_before: now,
                not_after: now + VALIDITY_SECS,
            },
        )
    }
}

#[tokio::test]
async fn a_new_identity_key_is_accepted_through_a_rotation_and_a_revocation_stops_trust() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("keys-a", &fabric).await;
    let b = Node::new("keys-b", &fabric).await;
    pair(&a, &b).await;
    assert!(matches!(b.visit(&a).await, RunOutcome::Done(_)));
    let old = a.built.replica.identity();

    // A rotates its key. Until B has the record, the key A offers is not the pinned one.
    let change = a.facade.rotate_identity(unix_now()).await.expect("rotated");
    assert_eq!((change.kind, change.peers), ("rotation", 1));
    let new = a.built.replica.identity();
    assert_ne!(new.public, old.public);
    assert_eq!(new.server, old.server);
    let refused = b.runner.run_peer(a.id, unix_now()).await;
    assert!(
        matches!(refused, Err(FedError::KeyMismatch { .. })),
        "a key that isn't the pinned one is the alert, not a rotation: {refused:?}"
    );
    assert!(
        b.runner
            .status_of(a.id)
            .expect("a status")
            .key_mismatch
            .is_some()
    );

    // A's next visit delivers the record before it opens the session, so B pins the new key.
    assert!(matches!(a.visit(&b).await, RunOutcome::Done(_)));
    let pinned = PeerRepo::get_peer(b.store(), a.id)
        .await
        .expect("a read")
        .expect("the peer");
    assert_eq!(pinned.identity_key, new.public.as_bytes().to_vec());
    assert_eq!(pinned.state, PeerState::Paired);
    assert!(matches!(b.visit(&a).await, RunOutcome::Done(_)));

    // A record signed by a key B never pinned for A is not a rotation.
    let thief = TestRotator.rotate(&old, unix_now()).expect("an identity");
    let (_, forged) = rotation_record(&thief, &thief, unix_now()).expect("a record");
    assert!(
        b.built
            .replica
            .accept_key_record(&forged.encode(), unix_now())
            .await
            .is_err()
    );

    // A says its key is stolen: the revocation goes to B, which stops trusting it.
    let change = a.facade.revoke_identity(unix_now()).await.expect("revoked");
    assert_eq!((change.kind, change.peers), ("revocation", 1));
    let _ = a.runner.run_peer(b.id, unix_now()).await;
    let held = PeerRepo::get_peer(b.store(), a.id)
        .await
        .expect("a read")
        .expect("the peer");
    assert_eq!(held.state, PeerState::Revoked);
    assert!(matches!(
        b.runner.run_peer(a.id, unix_now()).await,
        Ok(RunOutcome::NotPaired)
    ));
}

// ---- a chain of pairings: A - B - C, with no pairing between A and C ----

#[tokio::test]
async fn changes_relay_across_a_chain_of_pairings_with_no_pairing_between_the_ends() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("chain-a", &fabric).await;
    let b = Node::new("chain-b", &fabric).await;
    let c = Node::new("chain-c", &fabric).await;
    pair(&a, &b).await;
    pair(&b, &c).await;
    assert_eq!(a.facade.peers().await.expect("peers").len(), 1);
    assert_eq!(c.facade.peers().await.expect("peers").len(), 1);

    // B is the home of a vault; A and C are its replicas and are paired only with B.
    let member = new_user("ida@example.org");
    UserRepo::insert(b.store(), &member)
        .await
        .expect("an account");
    let owner = Owner::User(member.id);
    b.facade
        .set_policy(owner, Policy::Federated, vec![a.id, c.id])
        .await
        .expect("the home federates the vault");
    for replica in [&a, &c] {
        b.visit(replica).await;
        replica.facade.accept_offer(owner).await.expect("accepts");
        b.visit(replica).await;
        replica.visit(&b).await;
    }

    // A change made at A reaches C through B, signed by A, though C never paired with A.
    let from_a = ItemId::random();
    ItemStore::put(a.store(), draft(from_a, owner, None, 1, 1_000))
        .await
        .expect("a write at A");
    a.visit(&b).await;
    b.visit(&a).await;
    assert!(b.items(owner).await.iter().any(|i| i.id == from_a));
    let RunOutcome::Done(statuses) = c.visit(&b).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].pulled.applied, 1, "{:?}", statuses[0]);
    let at_c = c.items(owner).await;
    let relayed = at_c.iter().find(|i| i.id == from_a).expect("A's item at C");
    assert_eq!(relayed.change.origin, a.id, "the change is still A's");
    let learned = OriginKeys::learned_keys(c.store()).await.expect("keys");
    assert_eq!(learned.len(), 1);
    assert_eq!(learned[0].server, a.id);
    assert_eq!(learned[0].via, b.id);
    assert_eq!(
        c.facade.peers().await.expect("peers").len(),
        1,
        "learning a key is not a pairing"
    );

    // And the other way: C's change reaches A.
    let from_c = ItemId::random();
    ItemStore::put(c.store(), draft(from_c, owner, None, 1, 2_000))
        .await
        .expect("a write at C");
    c.visit(&b).await;
    b.visit(&c).await;
    a.visit(&b).await;
    assert!(a.items(owner).await.iter().any(|i| i.id == from_c));

    // A says its key is stolen. B stops trusting it and passes the record on, so C drops the key it
    // learned for A.
    a.facade.revoke_identity(unix_now()).await.expect("revoked");
    let _ = a.runner.run_peer(b.id, unix_now()).await;
    b.visit(&c).await;
    assert!(
        OriginKeys::learned_keys(c.store())
            .await
            .expect("keys")
            .is_empty(),
        "the revocation reached a server A was never paired with"
    );
}

// ---- duplicate tags: they follow their item revision, where server matching is on ----

#[tokio::test]
async fn duplicate_tags_follow_their_revision_where_matching_is_on() {
    let fabric = Arc::new(Fabric::default());
    let a = Node::new("tags-a", &fabric).await;
    let b = Node::new("tags-b", &fabric).await;
    pair(&a, &b).await;

    let member = new_user("tess@example.org");
    UserRepo::insert(a.store(), &member)
        .await
        .expect("an account");
    let owner = Owner::User(member.id);
    let (one, two, three) = (ItemId::random(), ItemId::random(), ItemId::random());
    for (n, id) in [one, two, three].into_iter().enumerate() {
        ItemStore::put(a.store(), draft(id, owner, None, 1, 1_000 + n as u64))
            .await
            .expect("an item");
    }
    // A person turns server matching on for their vault, at each server that holds it.
    let now = OffsetDateTime::now_utc();
    TagStore::set_matching(a.store(), owner, true, member.id, now)
        .await
        .expect("matching on at A");
    TagStore::set_matching(b.store(), owner, true, member.id, now)
        .await
        .expect("matching on at B");
    let set =
        |bytes: &[u8]| TagSet::new(1, bytes.iter().map(|b| DedupTag([*b; 32]))).expect("a tag set");
    for (id, tags) in [(one, set(&[1, 2])), (two, set(&[2])), (three, set(&[3]))] {
        assert!(
            TagStore::put_tags(a.store(), owner, id, Revision(1), &tags)
                .await
                .expect("tags")
        );
    }

    a.facade
        .set_policy(owner, Policy::Federated, vec![b.id])
        .await
        .expect("the home federates the vault");
    a.visit(&b).await;
    b.facade.accept_offer(owner).await.expect("B accepts");
    a.visit(&b).await;
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].pulled.applied, 3, "{:?}", statuses[0]);
    assert_eq!(statuses[0].tags_pulled, 3, "{:?}", statuses[0]);
    let groups = TagStore::groups(b.store(), owner, 1).await.expect("groups");
    assert_eq!(groups.len(), 1, "the replica finds the duplicates too");
    let mut expected = vec![one, two];
    expected.sort();
    assert_eq!(groups[0].items, expected);

    // A new revision of an item: its old tags are not valid for it anywhere.
    ItemStore::put(a.store(), draft(one, owner, Some(1), 2, 9_000))
        .await
        .expect("a new revision");
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].pulled.applied, 1, "{:?}", statuses[0]);
    assert!(
        TagStore::groups(b.store(), owner, 1)
            .await
            .expect("groups")
            .is_empty(),
        "a tag made for revision 1 does nothing for revision 2"
    );
    // The device uploads the tags of the new revision at A, and they follow it to B.
    assert!(
        TagStore::put_tags(a.store(), owner, one, Revision(2), &set(&[2]))
            .await
            .expect("tags")
    );
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].tags_pulled, 1, "{:?}", statuses[0]);
    assert_eq!(
        TagStore::groups(b.store(), owner, 1)
            .await
            .expect("groups")
            .len(),
        1
    );

    // Matching off at the replica: nothing is asked, and it holds no tag.
    TagStore::set_matching(b.store(), owner, false, member.id, now)
        .await
        .expect("matching off at B");
    let RunOutcome::Done(statuses) = b.visit(&a).await else {
        panic!("a run");
    };
    assert_eq!(statuses[0].tags_pulled, 0, "{:?}", statuses[0]);
    assert!(
        TagStore::groups(b.store(), owner, 1)
            .await
            .expect("groups")
            .is_empty()
    );
}
