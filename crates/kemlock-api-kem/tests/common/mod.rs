//! Shared by the router tests: an `App` over the in-memory fakes of `kemlock-app`'s tests, and a
//! `Client` that talks to it in-process the way a device does (OPAQUE, DPoP with nonces).
#![allow(dead_code, unused_imports)]

#[path = "../../../kemlock-app/tests/fakes/mod.rs"]
pub(crate) mod fakes;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use fakes::{FakeClock, FakeEnv, FakePassword, FakeSeal, FakeStore, FakeTotp};
use kemlock_api_kem::testing::{DpopSigner, ProofClaims};
use kemlock_api_kem::{Api, ApiConfig, ApiSecrets, JwsTokenSigner, LiveHub, router};
use kemlock_app::b64url;
use kemlock_app::ports::{Clock, CryptoError, PasswordAuth, Random, SecretSeal, Totp, Zeroizing};
use kemlock_app::register::{BUNDLE_SIGNATURE_LEN, WRAPPED_ROOT_KEY_LEN};
use kemlock_app::{AuthConfig, Hasher};
use kemlock_crypto::ed25519;
use kemlock_domain::UserId;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;
use tower::ServiceExt;

pub(crate) const DOMAIN: &str = "https://kemlock.test";
pub(crate) const PASSWORD: [u8; 32] = fakes::PASSWORD;

/// One value for every non-store port, delegating to the fakes.
#[derive(Clone)]
pub(crate) struct TestCrypto {
    pub(crate) env: FakeEnv,
    pub(crate) password: FakePassword,
    pub(crate) seal: FakeSeal,
    pub(crate) totp: FakeTotp,
}

impl Clock for TestCrypto {
    fn now(&self) -> OffsetDateTime {
        self.env.now()
    }
}

impl Random for TestCrypto {
    fn fill(&self, buf: &mut [u8]) {
        self.env.fill(buf);
    }
}

impl Hasher for TestCrypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        self.env.sha256(data)
    }
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        self.env.hmac_sha256(key, data)
    }
}

impl SecretSeal for TestCrypto {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        self.seal.seal(purpose, value)
    }
    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.seal.open(purpose, sealed)
    }
}

impl Totp for TestCrypto {
    fn verify_step(&self, secret: &[u8], code: &str, now: OffsetDateTime) -> Option<u64> {
        self.totp.verify_step(secret, code, now)
    }
}

impl PasswordAuth for TestCrypto {
    fn registration_response(&self, id: &[u8], request: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.password.registration_response(id, request)
    }
    fn registration_record(&self, upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.password.registration_record(upload)
    }
    fn login_start(
        &self,
        id: &[u8],
        record: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.password.login_start(id, record, request)
    }
    fn login_finish(&self, state: &[u8], finalization: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.password.login_finish(state, finalization)
    }
}

pub(crate) type TestApi = Api<FakeStore, TestCrypto, JwsTokenSigner>;

/// The router over fakes, with handles to poke at them.
pub(crate) struct App {
    pub(crate) router: Router,
    pub(crate) api: TestApi,
    pub(crate) store: FakeStore,
    pub(crate) clock: FakeClock,
    pub(crate) crypto: TestCrypto,
    pub(crate) hub: LiveHub,
}

impl App {
    pub(crate) fn new(signups_allowed: bool) -> App {
        App::build(signups_allowed, Vec::new(), LiveHub::new())
    }

    /// An app whose emails go to `outbox`.
    pub(crate) fn mailing(
        signups_allowed: bool,
        outbox: std::sync::Arc<dyn kemlock_app::notices::Outbox>,
    ) -> App {
        let notices = kemlock_app::notices::Notices::with_outbox(outbox);
        App::build(
            signups_allowed,
            Vec::new(),
            LiveHub::new().with_notices(notices),
        )
    }

    /// An app whose trusted proxies are `trusted_proxies`.
    pub(crate) fn behind(signups_allowed: bool, trusted_proxies: Vec<std::net::IpAddr>) -> App {
        App::build(signups_allowed, trusted_proxies, LiveHub::new())
    }

    /// An app whose admin named these browser extensions (`KEMLOCK_BROWSER_EXTENSION_IDS`).
    pub(crate) fn with_extension_ids(ids: &[&str]) -> App {
        let ids = ids.iter().map(|id| (*id).to_owned()).collect();
        App::build_with(false, Vec::new(), LiveHub::new(), ids)
    }

    fn build(signups_allowed: bool, trusted_proxies: Vec<std::net::IpAddr>, hub: LiveHub) -> App {
        App::build_with(signups_allowed, trusted_proxies, hub, Vec::new())
    }

    fn build_with(
        signups_allowed: bool,
        trusted_proxies: Vec<std::net::IpAddr>,
        hub: LiveHub,
        browser_extension_ids: Vec<String>,
    ) -> App {
        let env = FakeEnv::new();
        let clock = env.clock.clone();
        let crypto = TestCrypto {
            env,
            password: FakePassword::new(),
            seal: FakeSeal::new(),
            totp: FakeTotp,
        };
        let store = FakeStore::new();
        let config = ApiConfig {
            domain: DOMAIN.to_owned(),
            version: "0.0.0-test".to_owned(),
            commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            source_url: "https://example.org/source/0123456".to_owned(),
            auth: AuthConfig {
                signups_allowed,
                ..AuthConfig::default()
            },
            trusted_proxies,
            ip_header: None,
            browser_extension_ids,
        };
        let secrets = ApiSecrets {
            prelogin: [9u8; 32],
            dpop_nonce: [8u8; 32],
        };
        let signer = JwsTokenSigner::new(ed25519::SigningKey::from_seed(&[1u8; 32]));
        let api = Api::new(
            store.clone(),
            crypto.clone(),
            signer,
            hub.clone(),
            config,
            secrets,
        )
        .expect("the test domain is valid");
        App {
            router: router(api.clone(), fakes::NoSpaceStore),
            api,
            store,
            clock,
            crypto,
            hub,
        }
    }

    /// The router over the same fakes with `spaces` as the space store, for the tests of spaces.
    pub(crate) fn router_with<R: kemlock_app::spaces::SpaceRepo + Clone + 'static>(
        &self,
        spaces: R,
    ) -> Router {
        router(self.api.clone(), spaces)
    }

    /// A device with its own DPoP key.
    pub(crate) fn client(&self) -> Client {
        Client::new(self.router.clone(), self.clock.clone(), DpopSigner::es256())
    }

    /// A device on this machine (the peer is 127.0.0.1): a secure context for first-run setup.
    pub(crate) fn local_client(&self) -> Client {
        let mut client = self.client();
        client.peer = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 40_000)));
        client
    }

    /// A device (with its own DPoP key) talking to a second server over the same database and
    /// keys: its own limits and replay sets in memory, as another replica of one deployment has.
    pub(crate) fn replica_client(&self) -> Client {
        let api = Api::new(
            self.store.clone(),
            self.crypto.clone(),
            JwsTokenSigner::new(ed25519::SigningKey::from_seed(&[1u8; 32])),
            LiveHub::new(),
            self.api.config.clone(),
            ApiSecrets {
                prelogin: [9u8; 32],
                dpop_nonce: [8u8; 32],
            },
        )
        .expect("the test domain is valid");
        Client::new(
            router(api, fakes::NoSpaceStore),
            self.clock.clone(),
            DpopSigner::es256(),
        )
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }
}

/// What came back.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "a JSON body, got {e}: {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub(crate) fn content_type(&self) -> &str {
        self.header("content-type").unwrap_or("")
    }

    /// The problem's `type` slug.
    pub(crate) fn problem(&self) -> String {
        let json = self.json();
        json["type"]
            .as_str()
            .and_then(|t| t.strip_prefix("urn:kemlock:problem:"))
            .unwrap_or("")
            .to_owned()
    }
}

/// How a request is sent.
#[derive(Default)]
pub(crate) struct Req<'a> {
    pub(crate) access_token: Option<&'a str>,
    pub(crate) headers: Vec<(&'a str, String)>,
    pub(crate) body: Option<Value>,
    pub(crate) raw_body: Option<Vec<u8>>,
    /// Skip the DPoP proof.
    pub(crate) no_proof: bool,
    /// Send this proof instead of making one.
    pub(crate) proof: Option<String>,
    /// The peer address the connection comes from; none means the router sees no address.
    pub(crate) peer: Option<std::net::SocketAddr>,
}

/// A device: one DPoP key, the last nonce the server gave, and the router.
pub(crate) struct Client {
    router: Router,
    clock: FakeClock,
    pub(crate) key: DpopSigner,
    /// The peer address requests come from when a request names none.
    pub(crate) peer: Option<std::net::SocketAddr>,
    nonce: Mutex<Option<String>>,
    jti: AtomicU64,
}

impl Client {
    pub(crate) fn new(router: Router, clock: FakeClock, key: DpopSigner) -> Client {
        Client {
            router,
            clock,
            key,
            peer: None,
            nonce: Mutex::new(None),
            jti: AtomicU64::new(1),
        }
    }

    pub(crate) fn nonce(&self) -> Option<String> {
        self.nonce.lock().expect("lock").clone()
    }

    /// A proof for a request, with the nonce the server gave last (if any).
    pub(crate) fn proof_for(&self, method: &str, path: &str, access_token: Option<&str>) -> String {
        let nonce = self.nonce();
        let jti = format!("jti-{}", self.jti.fetch_add(1, Ordering::Relaxed));
        let htu = format!("{DOMAIN}{path}");
        self.key.proof(&ProofClaims {
            method,
            htu: &htu,
            iat: self.clock.now().unix_timestamp(),
            jti: &jti,
            access_token,
            nonce: nonce.as_deref(),
        })
    }

    /// Sends one request exactly as described, with no retry.
    pub(crate) async fn once(&self, method: &str, uri: &str, req: &Req<'_>) -> Reply {
        let path = uri.split('?').next().unwrap_or(uri);
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = req.access_token {
            builder = builder.header("authorization", format!("DPoP {token}"));
        }
        if !req.no_proof {
            let proof = req
                .proof
                .clone()
                .unwrap_or_else(|| self.proof_for(method, path, req.access_token));
            builder = builder.header("dpop", proof);
        }
        for (name, value) in &req.headers {
            builder = builder.header(*name, value);
        }
        let body = match (&req.raw_body, &req.body) {
            (Some(raw), _) => Body::from(raw.clone()),
            (None, Some(json)) => {
                builder = builder.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            (None, None) => Body::empty(),
        };
        let mut request = builder.body(body).expect("a valid request");
        if let Some(peer) = req.peer.or(self.peer) {
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
        }
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router never fails");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("a readable body");
        if let Some(nonce) = parts
            .headers
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
        {
            *self.nonce.lock().expect("lock") = Some(nonce.to_owned());
        }
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: bytes.to_vec(),
        }
    }

    /// Sends a request, retrying once with a new nonce when the server asks for one.
    pub(crate) async fn send(&self, method: &str, uri: &str, req: Req<'_>) -> Reply {
        let first = self.once(method, uri, &req).await;
        if first.status == StatusCode::UNAUTHORIZED
            && first.problem() == "use-dpop-nonce"
            && req.proof.is_none()
        {
            return self.once(method, uri, &req).await;
        }
        first
    }

    pub(crate) async fn get(&self, uri: &str) -> Reply {
        self.send("GET", uri, Req::default()).await
    }

    pub(crate) async fn get_authed(&self, uri: &str, token: &str) -> Reply {
        self.send(
            "GET",
            uri,
            Req {
                access_token: Some(token),
                ..Req::default()
            },
        )
        .await
    }

    pub(crate) async fn post(&self, uri: &str, body: Value) -> Reply {
        self.send(
            "POST",
            uri,
            Req {
                body: Some(body),
                ..Req::default()
            },
        )
        .await
    }

    pub(crate) async fn post_authed(&self, uri: &str, token: &str, body: Value) -> Reply {
        self.send(
            "POST",
            uri,
            Req {
                access_token: Some(token),
                body: Some(body),
                ..Req::default()
            },
        )
        .await
    }
}

/// What a signed-in device holds.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) user_id: String,
    pub(crate) device_id: String,
}

impl Session {
    pub(crate) fn from_tokens(tokens: &Value) -> Session {
        let text = |name: &str| tokens[name].as_str().expect(name).to_owned();
        Session {
            access_token: text("accessToken"),
            refresh_token: text("refreshToken"),
            user_id: text("userId"),
            device_id: text("deviceId"),
        }
    }
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    b64url::encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Vec<u8> {
    b64url::decode(text).expect("base64url")
}

/// Registers `email` with [`PASSWORD`] over HTTP, with real OPAQUE. Returns the user id and the
/// last reply.
pub(crate) async fn register(
    client: &Client,
    email: &str,
    setup_grant: Option<&str>,
) -> (Reply, UserId) {
    register_with(client, email, setup_grant, fakes::bundle_and_signature).await
}

/// [`register`] with the public-key bundle and its signature that `bundle` makes for the new
/// account's id: the server checks that the signature verifies under the key in the bundle.
pub(crate) async fn register_with(
    client: &Client,
    email: &str,
    setup_grant: Option<&str>,
    bundle: impl FnOnce(UserId) -> (Vec<u8>, Vec<u8>),
) -> (Reply, UserId) {
    let (state, request) = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client registration start");
    let mut start = json!({"email": email, "request": b64(&request)});
    if let Some(grant) = setup_grant {
        start["setupGrant"] = json!(grant);
    }
    let started = client.post("/kem/v1/accounts/register/start", start).await;
    let user = UserId::random();
    if started.status != StatusCode::OK {
        return (started, user);
    }
    let response = unb64(started.json()["response"].as_str().expect("response"));
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client registration finish");
    let (public_bundle, bundle_signature) = bundle(user);
    let mut finish = json!({
        "userId": user.to_string(),
        "email": email,
        "name": "Sam",
        "upload": b64(&upload),
        "kdf": {"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": b64(&[4u8; 16])},
        "publicBundle": b64(&public_bundle),
        "bundleSignature": b64(&bundle_signature),
        "sealedPrivateKeys": b64(&[0x22u8; 64]),
        "wrappedRootKey": b64(&[0x33u8; WRAPPED_ROOT_KEY_LEN]),
    });
    if let Some(grant) = setup_grant {
        finish["setupGrant"] = json!(grant);
    }
    (
        client
            .post("/kem/v1/accounts/register/finish", finish)
            .await,
        user,
    )
}

/// Both OPAQUE login messages over HTTP; returns the reply to the last.
pub(crate) async fn sign_in_reply(client: &Client, email: &str, device: Value) -> Reply {
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
    let started = client
        .post(
            "/kem/v1/auth/opaque/start",
            json!({"email": email, "request": b64(&request)}),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let (finalization, _session_key, _export_key) =
        kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &response)
            .expect("client login finish");
    client
        .post(
            "/kem/v1/auth/opaque/finish",
            json!({
                "email": email,
                "loginState": started["loginState"],
                "finalization": b64(&finalization),
                "device": device,
            }),
        )
        .await
}

pub(crate) fn test_device() -> Value {
    json!({"name": "Test device", "kind": "kemlock-cli"})
}

/// Registers (signups must be on) and signs in without a second step.
pub(crate) async fn register_and_sign_in(client: &Client, email: &str) -> Session {
    register_and_sign_in_with(client, email, fakes::bundle_and_signature).await
}

/// [`register_and_sign_in`] with the public-key bundle and signature `bundle` makes for the
/// account's id.
pub(crate) async fn register_and_sign_in_with(
    client: &Client,
    email: &str,
    bundle: impl FnOnce(UserId) -> (Vec<u8>, Vec<u8>),
) -> Session {
    let (reply, _user) = register_with(client, email, None, bundle).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let signed = sign_in_reply(client, email, test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let json = signed.json();
    assert_eq!(json["status"], "signed_in");
    Session::from_tokens(&json["tokens"])
}

/// RFC 4648 base32 without padding, upper case.
pub(crate) fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {c}"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// The TOTP code for a base32 secret at the app's clock.
pub(crate) fn totp_now(app: &App, secret: &str) -> String {
    let now = u64::try_from(app.now()).expect("a positive time");
    kemlock_crypto::totp::code_at(&base32_decode(secret), now)
}

/// An item in docs/crypto.md's wire shape with random bytes where the sealed values go:
/// the server checks only their lengths. `ItemKeys` makes items sealed with `kem1`.
pub(crate) fn item_json(owner: &str, id: &str, revision: u64) -> Value {
    json!({
        "id": id,
        "owner": format!("user:{owner}"),
        "kind": "login",
        "format": "kem1",
        "revision": revision,
        "keyVersion": 1,
        "ciphertext": b64(&kemlock_crypto::rand::bytes::<64>()),
        "itemKey": b64(&kemlock_crypto::rand::bytes::<60>()),
        "deleted": false,
    })
}

pub(crate) fn new_item_id() -> String {
    kemlock_domain::ItemId::random().to_string()
}

/// The keys of a client that seals items for one account.
pub(crate) struct ItemKeys {
    pub(crate) wrap_key: kemlock_crypto::keys::SecretKey,
    pub(crate) user: [u8; 16],
}

impl ItemKeys {
    /// Fresh keys for the account `user` (a UUID string).
    pub(crate) fn new(user: &str) -> ItemKeys {
        let root = kemlock_crypto::keys::RootKey::generate();
        let wrap_key = root
            .user_key()
            .expect("the user key derives")
            .child(kemlock_crypto::keys::ITEM_WRAP_LABEL)
            .expect("the item-wrap key derives");
        ItemKeys {
            wrap_key,
            user: *uuid::Uuid::parse_str(user).expect("a uuid").as_bytes(),
        }
    }

    fn owner(&self) -> kemlock_crypto::owner::Owner {
        kemlock_crypto::owner::Owner::user(self.user)
    }

    /// An item sealed with `kemlock-crypto`'s `kem1` functions, in docs/crypto.md's wire shape.
    pub(crate) fn seal(&self, id: &str, revision: u64, kind: &str, plaintext: &str) -> Value {
        let id_bytes = *uuid::Uuid::parse_str(id).expect("a uuid").as_bytes();
        let item_key = kemlock_crypto::keys::SecretKey::generate();
        let ciphertext = kemlock_crypto::kem1::seal_item(
            &item_key,
            &id_bytes,
            revision,
            kind,
            &self.owner(),
            plaintext.as_bytes(),
        )
        .expect("the item seals");
        let wrapped = kemlock_crypto::kem1::wrap_item_key(
            &self.wrap_key,
            &item_key,
            &id_bytes,
            &self.owner(),
            1,
        )
        .expect("the item key wraps");
        json!({
            "id": id,
            "owner": format!("user:{}", uuid::Uuid::from_bytes(self.user)),
            "kind": kind,
            "format": "kem1",
            "revision": revision,
            "keyVersion": 1,
            "ciphertext": b64(&ciphertext),
            "itemKey": b64(&wrapped),
            "deleted": false,
        })
    }

    /// Opens an item as the server returned it.
    pub(crate) fn open(&self, item: &Value) -> String {
        let id = *uuid::Uuid::parse_str(item["id"].as_str().expect("id"))
            .expect("a uuid")
            .as_bytes();
        let kind = item["kind"].as_str().expect("kind");
        let revision = item["revision"].as_u64().expect("revision");
        let item_key = kemlock_crypto::kem1::unwrap_item_key(
            &self.wrap_key,
            &unb64(item["itemKey"].as_str().expect("itemKey")),
            &id,
            &self.owner(),
            1,
        )
        .expect("the item key unwraps");
        let plaintext = kemlock_crypto::kem1::open_item(
            &item_key,
            &id,
            revision,
            kind,
            &self.owner(),
            &unb64(item["ciphertext"].as_str().expect("ciphertext")),
        )
        .expect("the item opens");
        String::from_utf8(plaintext.to_vec()).expect("UTF-8")
    }
}
