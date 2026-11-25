//! Shared by the router tests: the Bitwarden router over an in-memory store, a clock that only
//! moves when a test says so, and a small client that talks to it the way an app does.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use kemlock_api_bw::password::hash_password;
use kemlock_api_bw::tokens::{LoginClaims, TokenKeys};
use kemlock_api_bw::{
    App, AppParts, BwLive, BwSettings, Env, MemoryBlobStore, TwoStepParts, router,
};
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::bw_events::{BwEvent, BwEvents, BwRelay};
use kemlock_app::notices::{Notices, Outbox};
use kemlock_app::platform::Hasher;
use kemlock_app::ports::{Clock, Random, StoreError, UserRepo};
use kemlock_app::privacy::{EraseAccount, ErasureFiles, NoSends};
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::BlobId;
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_store_sql::SqlStore;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, OnceLock};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const DOMAIN: &str = "https://vault.test";
pub(crate) const SERVER_KEY: [u8; 32] = [7; 32];
/// What a client's `masterPasswordHash` is in these tests: any text.
pub(crate) const HASH: &str = "bZ5Fp0b5n4QvRY+u8o8y5Qm3sN2h7c4w9d1e2f3a4b5=";
pub(crate) const USER_KEY: &str = "2.W7fCTI1c/Pwx6/Q+n6/JgQ==|pnH3a56drGLUm9DVVK7mdYqLH3+AoAQlMMZc3WlNzCRLJA5LJxQq+d8KHOauFEZG8OgRguyAk8mCIQZQALIPLIlHMWWh1ZVXJuRoJ935r4g=|sLmq2YslxnewPfLeKSev6+1yJTm6Xw8Lm9zU2YPjkks=";

/// A clock that moves only when told to.
#[derive(Debug)]
pub(crate) struct TestEnv {
    now: Mutex<OffsetDateTime>,
}

impl TestEnv {
    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self.now.lock().expect("the clock");
        *now += by;
    }

    pub(crate) fn time(&self) -> OffsetDateTime {
        *self.now.lock().expect("the clock")
    }
}

impl Env for TestEnv {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().expect("the clock")
    }

    fn fill(&self, buf: &mut [u8]) {
        kemlock_crypto::rand::fill(buf);
    }
}

/// The PEM of one RSA key for every test: making one takes a moment.
fn shared_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temp dir");
        TokenKeys::load_or_create(dir.path()).expect("a key is made");
        std::fs::read_to_string(dir.path().join("rsa_key.pem")).expect("the key file")
    })
}

pub(crate) fn keys() -> TokenKeys {
    TokenKeys::from_pem(shared_pem()).expect("the key reads back")
}

/// The clock and randomness of the test environment, as the app crate's platform.
struct TestPlatform(Arc<TestEnv>);

impl Clock for TestPlatform {
    fn now(&self) -> OffsetDateTime {
        self.0.now()
    }
}

impl Random for TestPlatform {
    fn fill(&self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

impl Hasher for TestPlatform {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        kemlock_crypto::hash::sha256(data)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        kemlock_crypto::hash::hmac_sha256(key, data)
    }
}

/// Files an erasure frees: the harness keeps them in memory, so there is nothing to delete.
struct NoFiles;

impl ErasureFiles for NoFiles {
    async fn delete_blob(&self, _blob: BlobId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn delete_cipher_file(&self, _key: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

/// What a harness wires beyond the defaults.
#[derive(Default)]
struct Live {
    relay: Option<Arc<dyn BwRelay>>,
    notices: Notices,
    require_device_email: bool,
}

/// Keeps every event the API publishes, in order.
#[derive(Default)]
pub(crate) struct Recorder(Mutex<Vec<BwEvent>>);

impl BwEvents for Recorder {
    fn publish(&self, event: BwEvent) {
        self.0.lock().expect("the recorder").push(event);
    }
}

impl Recorder {
    /// The events since the last call.
    pub(crate) fn take(&self) -> Vec<BwEvent> {
        std::mem::take(&mut *self.0.lock().expect("the recorder"))
    }
}

pub(crate) struct Harness {
    pub router: Router,
    pub store: SqlStore,
    pub env: Arc<TestEnv>,
    pub blobs: Arc<MemoryBlobStore>,
    /// What the API told the live channels.
    pub events: Arc<Recorder>,
}

impl Harness {
    pub(crate) async fn new() -> Self {
        Self::with(|_| {}).await
    }

    pub(crate) async fn with(tweak: impl FnOnce(&mut BwSettings)) -> Self {
        Self::build(None, tweak).await
    }

    /// A harness whose server has a WebAuthn relying party for `DOMAIN`, so accounts can have
    /// security keys.
    pub(crate) async fn with_webauthn() -> Self {
        let rp = kemlock_identity::WebAuthnRp::new(DOMAIN).expect("a relying party");
        Self::build(Some(Arc::new(rp)), |_| {}).await
    }

    async fn build(
        webauthn: Option<Arc<dyn kemlock_app::passkeys::WebAuthn>>,
        tweak: impl FnOnce(&mut BwSettings),
    ) -> Self {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        Self::on_with(store, webauthn, TwoStepParts::default(), tweak).await
    }

    /// A harness with the second steps beyond an authenticator app and a security key set up as
    /// `two_step` says, and a WebAuthn relying party when `webauthn` is on.
    pub(crate) async fn with_two_step(two_step: TwoStepParts, webauthn: bool) -> Self {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        let rp: Option<Arc<dyn kemlock_app::passkeys::WebAuthn>> = if webauthn {
            Some(Arc::new(
                kemlock_identity::WebAuthnRp::new(DOMAIN).expect("a relying party"),
            ))
        } else {
            None
        };
        Self::on_with(store, rp, two_step, |_| {}).await
    }

    /// [`Harness::with_two_step`] over a store the test made.
    pub(crate) async fn on_two_step(
        store: SqlStore,
        two_step: TwoStepParts,
        webauthn: bool,
    ) -> Self {
        let rp: Option<Arc<dyn kemlock_app::passkeys::WebAuthn>> = if webauthn {
            Some(Arc::new(
                kemlock_identity::WebAuthnRp::new(DOMAIN).expect("a relying party"),
            ))
        } else {
            None
        };
        Self::on_with(store, rp, two_step, |_| {}).await
    }

    /// The router over a store the test made, such as one in a file it can also read directly.
    pub(crate) async fn on(store: SqlStore, tweak: impl FnOnce(&mut BwSettings)) -> Self {
        Self::on_with(store, None, TwoStepParts::default(), tweak).await
    }

    async fn on_with(
        store: SqlStore,
        webauthn: Option<Arc<dyn kemlock_app::passkeys::WebAuthn>>,
        two_step: TwoStepParts,
        tweak: impl FnOnce(&mut BwSettings),
    ) -> Self {
        Self::on_live(store, webauthn, two_step, Live::default(), tweak).await
    }

    /// A harness whose server has Bitwarden's push relay, as `relay`.
    pub(crate) async fn with_relay(relay: Arc<dyn BwRelay>) -> Self {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        let live = Live {
            relay: Some(relay),
            ..Live::default()
        };
        Self::on_live(store, None, TwoStepParts::default(), live, |_| {}).await
    }

    /// A harness whose server mails through `outbox`; `require` is `REQUIRE_DEVICE_EMAIL`.
    pub(crate) async fn with_mail(outbox: Arc<dyn Outbox>, require: bool) -> Self {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        let live = Live {
            notices: Notices::with_outbox(outbox),
            require_device_email: require,
            ..Live::default()
        };
        Self::on_live(store, None, TwoStepParts::default(), live, |_| {}).await
    }

    async fn on_live(
        store: SqlStore,
        webauthn: Option<Arc<dyn kemlock_app::passkeys::WebAuthn>>,
        two_step: TwoStepParts,
        live: Live,
        tweak: impl FnOnce(&mut BwSettings),
    ) -> Self {
        let env = Arc::new(TestEnv {
            now: Mutex::new(datetime!(2026-11-21 12:00:00 UTC)),
        });
        let blobs = Arc::new(MemoryBlobStore::new());
        let events = Arc::new(Recorder::default());
        let mut settings = BwSettings::new(DOMAIN, true);
        // Fewer rounds, so a sign-in doesn't take a second.
        settings.password_iterations = 1_000;
        // The suites sign in far more often than a person does; the rate-limit tests set their own.
        settings.login_ratelimit_max_burst = 1_000_000;
        settings.unauthenticated_ratelimit_max_burst = 1_000_000;
        tweak(&mut settings);
        let app = App::new(AppParts {
            store: store.clone(),
            env: env.clone(),
            keys: keys(),
            seal: ServerSeal::new(&SERVER_KEY),
            blobs: blobs.clone(),
            two_step,
            settings,
            webauthn,
            sends: None,
            live: BwLive {
                events: events.clone(),
                relay: live.relay,
                notices: live.notices,
                require_device_email: live.require_device_email,
                erasure: Some(Arc::new(EraseAccount {
                    users: store.clone(),
                    eraser: store.clone(),
                    sends: NoSends,
                    files: NoFiles,
                    settings: store.clone(),
                    log: store.clone(),
                    env: TestPlatform(env.clone()),
                })),
            },
        });
        Harness {
            router: router(app),
            store,
            env,
            blobs,
            events,
        }
    }

    /// Sends a request and returns the status, headers and body bytes.
    pub(crate) async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Body,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(body).expect("a request"))
            .await
            .expect("the router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
            .await
            .expect("a body");
        (parts.status, parts.headers, bytes.to_vec())
    }

    /// A JSON request, optionally with a bearer token; the answer's body parsed as JSON, or null.
    pub(crate) async fn json(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut headers = vec![("content-type", "application/json")];
        if let Some(auth) = &auth {
            headers.push(("authorization", auth.as_str()));
        }
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let (status, _, bytes) = self.send(method, uri, &headers, body).await;
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    /// `POST /identity/connect/token` with a form.
    pub(crate) async fn token(&self, fields: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            form.append_pair(k, v);
        }
        let (status, _, bytes) = self
            .send(
                "POST",
                "/identity/connect/token",
                &[("content-type", "application/x-www-form-urlencoded")],
                Body::from(form.finish()),
            )
            .await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The fields of a password sign-in as the Kemlock app sends them.
    pub(crate) fn password_fields<'a>(email: &'a str, hash: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("grant_type", "password"),
            ("scope", "api offline_access"),
            ("client_id", "mobile"),
            ("username", email),
            ("password", hash),
            ("deviceType", "0"),
            ("deviceIdentifier", "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a"),
            ("deviceName", "Kemlock"),
        ]
    }

    /// Signs in and returns the answer; fails the test on anything but a 200.
    pub(crate) async fn login(&self, email: &str, hash: &str) -> Value {
        let (status, body) = self.token(&Self::password_fields(email, hash)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Makes a Compatible account straight in the store, with the keys of the Kemlock app's
    /// fixtures; returns its user id.
    pub(crate) async fn account(&self, email: &str, hash: &str) -> UserId {
        self.account_with(email, hash, USER_KEY, 0, 1_000, None, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn account_with(
        &self,
        email: &str,
        hash: &str,
        akey: &str,
        kdf_type: i32,
        kdf_iterations: i32,
        memory: Option<i32>,
        parallelism: Option<i32>,
    ) -> UserId {
        let now = self.env.time();
        let user = User {
            id: UserId(Uuid::new_v4()),
            email: Email::parse(email).expect("an email"),
            name: Some("Kemlock test".to_owned()),
            mode: AccountMode::Compatible,
            role: Role::User,
            kdf: KdfParams::new_account([1; 16]),
            opaque_record: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: 0,
            security_stamp: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        };
        UserRepo::insert(&self.store, &user).await.expect("a user");
        let salt = vec![9u8; 64];
        let account = BwAccount {
            user: user.id,
            password_hash: hash_password(hash.as_bytes(), &salt, 1_000),
            salt,
            password_iterations: 1_000,
            kdf_type,
            kdf_iterations,
            kdf_memory: memory,
            kdf_parallelism: parallelism,
            akey: akey.to_owned(),
            private_key: Some("2.private|key|mac".to_owned()),
            public_key: Some("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".to_owned()),
            password_hint: None,
            api_key: None,
            avatar_color: None,
            revision_ms: 1_000,
        };
        BwAccountRepo::insert(&self.store, &account)
            .await
            .expect("an account");
        user.id
    }

    /// A signed-in account: its access token and its user id.
    pub(crate) async fn signed_in(&self, email: &str) -> (String, UserId) {
        let user = self.account(email, HASH).await;
        let body = self.login(email, HASH).await;
        let token = body["access_token"].as_str().expect("a token").to_owned();
        (token, user)
    }
}

/// The access token's claims, checked against the shared key.
pub(crate) fn claims(token: &str, now: i64) -> LoginClaims {
    keys()
        .decode(token, &format!("{DOMAIN}|login"), now)
        .expect("a valid access token")
}

/// A cipher request the way the Kemlock app sends a Login.
pub(crate) fn login_request(user: UserId, name: &str) -> Value {
    json!({
        "encryptedFor": user.to_string(),
        "type": 1,
        "organizationId": null,
        "folderId": null,
        "name": name,
        "notes": null,
        "favorite": false,
        "reprompt": 0,
        "key": null,
        "login": {
            "username": "2.username",
            "password": "2.password",
            "totp": null,
            "uris": [{"uri": "2.uri", "match": null}]
        },
        "fields": null,
        "passwordHistory": null,
        "lastKnownRevisionDate": null
    })
}

/// What the server hands the move from Vaultwarden: the Bitwarden API's own blob store, so imported
/// files land where the API reads them.
#[derive(Debug)]
pub(crate) struct IntoBlobs(pub(crate) Arc<MemoryBlobStore>);

impl kemlock_store_sql::ImportFiles for IntoBlobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> kemlock_store_sql::ImportFilesFuture<'a> {
        Box::pin(async move {
            kemlock_api_bw::BlobStore::put(&*self.0, key, bytes)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> kemlock_store_sql::ImportFilesFuture<'a> {
        Box::pin(async move {
            kemlock_api_bw::BlobStore::delete(&*self.0, key)
                .await
                .map_err(|e| e.to_string())
        })
    }
}
