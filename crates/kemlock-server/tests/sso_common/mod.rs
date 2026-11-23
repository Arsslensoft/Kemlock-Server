//! What the SSO gate tests share: a temporary data folder, a phone (a DPoP key, nonces and the
//! router), the SSO sign-in steps with a pluggable "browser", and the client's side of a `kem1`
//! vault. The fake-provider gate and the Keycloak gate differ only in the browser.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use kemlock_api_kem::testing::{DpopSigner, ProofClaims};
use kemlock_app::b64url;
use kemlock_app::ports::Clock;
use kemlock_app::sso::{SsoSettings, SsoSettingsRepo};
use kemlock_crypto::keys::{ITEM_WRAP_LABEL, RootKey, SecretKey};
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_crypto::{hash, kem1, owner::Owner, rand};
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::{Built, Config, keys};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

pub(crate) const DOMAIN: &str = "https://kemlock.test";
pub(crate) const APP_STATE: &str = "gate-state-0123456789abcdef";
/// What a device seals its root key under, in place of the real trusted-device wrap.
pub(crate) const TRUSTED_DEVICE_PURPOSE: &str = "kemlock/v1/trusted-device-wrap";

pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-sso-{}-{name}-{nanos}",
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

pub(crate) fn config(data: &Path) -> Config {
    let data = data.display().to_string();
    Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some(DOMAIN.to_owned()),
            _ => None,
        },
        None,
    )
    .expect("a valid configuration")
}

/// What came back.
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

    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

/// A phone: a DPoP key, the nonce the server gave last, and the router.
pub(crate) struct Phone {
    router: Router,
    key: DpopSigner,
    nonce: Mutex<Option<String>>,
    jti: AtomicU64,
}

impl Phone {
    pub(crate) fn new(router: Router) -> Phone {
        Phone {
            router,
            key: DpopSigner::es256(),
            nonce: Mutex::new(None),
            jti: AtomicU64::new(1),
        }
    }

    fn unix_now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(0)
    }

    async fn once(
        &self,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Reply {
        let path = uri.split('?').next().unwrap_or(uri);
        let nonce = self.nonce.lock().expect("lock").clone();
        let jti = format!("jti-{}", self.jti.fetch_add(1, Ordering::Relaxed));
        let htu = format!("{DOMAIN}{path}");
        let proof = self.key.proof(&ProofClaims {
            method,
            htu: &htu,
            iat: Self::unix_now(),
            jti: &jti,
            access_token,
            nonce: nonce.as_deref(),
        });
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("dpop", proof);
        if let Some(token) = access_token {
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
        let reply = send(&self.router, request).await;
        if let Some(fresh) = reply
            .headers
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
        {
            *self.nonce.lock().expect("lock") = Some(fresh.to_owned());
        }
        reply
    }

    /// One request with a DPoP proof, retried once when the server asks for a nonce.
    pub(crate) async fn send(
        &self,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        let first = self
            .once(method, uri, access_token, extra, body.as_ref())
            .await;
        if first.status == StatusCode::UNAUTHORIZED
            && first.json()["type"] == "urn:kemlock:problem:use-dpop-nonce"
        {
            return self
                .once(method, uri, access_token, extra, body.as_ref())
                .await;
        }
        first
    }
}

async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router never fails");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a readable body");
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: bytes.to_vec(),
    }
}

/// A request without a proof: the browser's callback, the provider's logout post.
pub(crate) async fn plain(router: &Router, method: &str, uri: &str, form: Option<&str>) -> Reply {
    let builder = Request::builder().method(method).uri(uri);
    let request = match form {
        Some(form) => builder
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned())),
        None => builder.body(Body::empty()),
    }
    .expect("a valid request");
    send(router, request).await
}

/// Points the server at a provider the way the admin console would: the settings row, with the
/// client secret sealed under the server's own key.
pub(crate) async fn enable_sso(
    built: &Built,
    data: &Path,
    issuer: &str,
    client_id: &str,
    client_secret: &str,
    scopes: &[&str],
) {
    let key: [u8; 32] = std::fs::read(data.join(keys::SERVER_KEY_FILE))
        .expect("the server key is on disk")
        .try_into()
        .expect("32 bytes");
    let crypto = ServerCrypto::new(ServerSeal::new(&key), OpaqueServer::generate());
    let mut settings = SsoSettings::new(issuer, client_id, crypto.now());
    settings.set_client_secret(&crypto, client_secret);
    settings.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    built
        .store
        .put_sso_settings(&settings)
        .await
        .expect("the settings are stored");
}

/// The system browser: takes the provider's authorization URL, logs the person in, and returns
/// the address the provider redirects to (the server's callback, with a code and the state).
pub(crate) trait Browser {
    async fn login(&self, authorization_url: &str) -> String;
}

/// One SSO sign-in of a phone. Each makes a fresh PKCE verifier.
pub(crate) struct SignIn {
    pub(crate) verifier: String,
}

impl SignIn {
    pub(crate) fn new() -> SignIn {
        SignIn {
            verifier: b64url::encode(&rand::bytes::<32>()),
        }
    }

    pub(crate) fn start_body(&self) -> Value {
        json!({
            "challenge": b64url::encode(&hash::sha256(self.verifier.as_bytes())),
            "state": APP_STATE,
        })
    }

    /// `start`, the browser's login, the callback and `finish`: the reply to the last.
    pub(crate) async fn through<B: Browser>(
        &self,
        phone: &Phone,
        router: &Router,
        browser: &B,
    ) -> Reply {
        // 1. The phone asks for the provider's address.
        let started = phone
            .send(
                "POST",
                "/kem/v1/auth/sso/start",
                None,
                &[],
                Some(self.start_body()),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let url = started.json()["authorizationUrl"]
            .as_str()
            .expect("an authorization URL")
            .to_owned();

        // 2. The system browser: the provider logs the person in and redirects to the server.
        let redirect = browser.login(&url).await;
        let callback = redirect
            .strip_prefix(DOMAIN)
            .unwrap_or_else(|| panic!("the provider redirects to the server: {redirect}"));

        // 3. The server's callback ends the browser's trip at the app, with a one-time code.
        let code = one_time_code(&plain(router, "GET", callback, None).await);

        // 4. The phone finishes with the code, its verifier and its device key.
        phone
            .send(
                "POST",
                "/kem/v1/auth/sso/finish",
                None,
                &[],
                Some(json!({
                    "code": code,
                    "verifier": self.verifier,
                    "device": {"name": "Pixel", "kind": "kemlock-android"},
                })),
            )
            .await
    }
}

/// The code in the callback's redirect to the app.
pub(crate) fn one_time_code(callback: &Reply) -> String {
    assert_eq!(
        callback.status,
        StatusCode::SEE_OTHER,
        "{:?}",
        callback.body
    );
    let location = callback.header("location");
    assert!(location.starts_with("kemlock://sso?code="), "{location}");
    assert!(
        location.ends_with(&format!("&state={APP_STATE}")),
        "{location}"
    );
    location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("a code")
        .to_owned()
}

/// The client's side of a `kem1` vault, as `docs/crypto.md` fixes it.
pub(crate) struct Vault {
    wrap_key: SecretKey,
    user: [u8; 16],
}

impl Vault {
    pub(crate) fn open(root: &RootKey, user: &str) -> Vault {
        Vault {
            wrap_key: root
                .user_key()
                .expect("the user key derives")
                .child(ITEM_WRAP_LABEL)
                .expect("the item-wrap key derives"),
            user: *uuid::Uuid::parse_str(user).expect("a uuid").as_bytes(),
        }
    }

    fn owner(&self) -> Owner {
        Owner::user(self.user)
    }

    pub(crate) fn seal(&self, id: &str, plaintext: &str) -> Value {
        let id_bytes = *uuid::Uuid::parse_str(id).expect("a uuid").as_bytes();
        let item_key = SecretKey::generate();
        let ciphertext = kem1::seal_item(
            &item_key,
            &id_bytes,
            1,
            "login",
            &self.owner(),
            plaintext.as_bytes(),
        )
        .expect("the item seals");
        let wrapped = kem1::wrap_item_key(&self.wrap_key, &item_key, &id_bytes, &self.owner(), 1)
            .expect("the item key wraps");
        json!({
            "id": id,
            "owner": format!("user:{}", uuid::Uuid::from_bytes(self.user)),
            "kind": "login",
            "format": "kem1",
            "revision": 1,
            "keyVersion": 1,
            "ciphertext": b64url::encode(&ciphertext),
            "itemKey": b64url::encode(&wrapped),
            "deleted": false,
        })
    }

    pub(crate) fn read(&self, item: &Value) -> String {
        let id = *uuid::Uuid::parse_str(item["id"].as_str().expect("id"))
            .expect("a uuid")
            .as_bytes();
        let item_key = kem1::unwrap_item_key(
            &self.wrap_key,
            &b64url::decode(item["itemKey"].as_str().expect("itemKey")).expect("base64url"),
            &id,
            &self.owner(),
            1,
        )
        .expect("the item key unwraps");
        let plaintext = kem1::open_item(
            &item_key,
            &id,
            item["revision"].as_u64().expect("revision"),
            item["kind"].as_str().expect("kind"),
            &self.owner(),
            &b64url::decode(item["ciphertext"].as_str().expect("ciphertext")).expect("base64url"),
        )
        .expect("the item opens");
        String::from_utf8(plaintext.to_vec()).expect("UTF-8")
    }
}

/// The access token and the user id of a `signed_in` reply.
pub(crate) fn tokens_of(reply: &Reply) -> (String, String) {
    let json = reply.json();
    assert_eq!(json["status"], "signed_in", "{json}");
    (
        json["tokens"]["accessToken"]
            .as_str()
            .expect("accessToken")
            .to_owned(),
        json["tokens"]["userId"]
            .as_str()
            .expect("userId")
            .to_owned(),
    )
}

/// The device's side of "open the vault with no password" after a first SSO sign-in: makes the
/// root key, stores an item sealed under it, and wraps the root key under a key of the device's
/// own. Returns what the device keeps: the device key and the wrapped root key, and the item as
/// the server was given it.
pub(crate) async fn make_vault(
    phone: &Phone,
    access: &str,
    user_id: &str,
    secret: &str,
) -> (SecretKey, Vec<u8>, Value, String) {
    let root = RootKey::generate();
    let vault = Vault::open(&root, user_id);
    let item_id = kemlock_domain::ItemId::random().to_string();
    let item = vault.seal(&item_id, secret);
    let put = phone
        .send(
            "PUT",
            &format!("/kem/v1/items/{item_id}"),
            Some(access),
            &[("if-none-match", "*")],
            Some(item.clone()),
        )
        .await;
    assert_eq!(put.status, StatusCode::CREATED, "{:?}", put.json());

    let device_key = SecretKey::generate();
    let wrapped_root =
        ServerSeal::new(device_key.as_bytes()).seal(TRUSTED_DEVICE_PURPOSE, root.as_bytes());
    (device_key, wrapped_root, item, item_id)
}

/// Opens the vault on the device: its own key unwraps the root key, the root key opens the item
/// the server synced back. No password is involved.
pub(crate) async fn open_vault(
    phone: &Phone,
    access: &str,
    user_id: &str,
    device_key: &SecretKey,
    wrapped_root: &[u8],
    stored_item: &Value,
) -> String {
    let sync = phone
        .send("GET", "/kem/v1/sync", Some(access), &[], None)
        .await;
    assert_eq!(sync.status, StatusCode::OK, "{:?}", sync.json());
    let synced = sync.json();
    let items = synced["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(
        &items[0], stored_item,
        "the server returns the bytes it was given"
    );

    let unwrapped = ServerSeal::new(device_key.as_bytes())
        .open(TRUSTED_DEVICE_PURPOSE, wrapped_root)
        .expect("the device's key opens the wrapped root key");
    let root = RootKey::from_bytes(
        <&[u8; 64]>::try_from(unwrapped.as_slice()).expect("a 64-byte root key"),
    );
    Vault::open(&root, user_id).read(&items[0])
}
