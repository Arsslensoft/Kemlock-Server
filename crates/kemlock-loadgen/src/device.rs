//! One simulated device: an HTTP client with its own DPoP key, the server's nonce, and the calls
//! the harness needs (registration, OPAQUE sign-in, refresh, batch writes, sync).
//!
//! Shapes come from `kemlock-api-kem`'s `dto.rs`; proofs are made by the same `DpopSigner` the
//! server's own tests use.

use kemlock_api_kem::testing::{DpopSigner, ProofClaims};
use kemlock_app::b64url;
use kemlock_app::register::{FIRST_KEY_VERSION, WRAPPED_ROOT_KEY_LEN};
use reqwest::Method;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Result<T> = std::result::Result<T, BoxError>;

/// The server's current DPoP nonce. It is one value for the whole server (an HMAC of the five
/// minute window), so every device here shares it.
static NONCE: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn current_nonce() -> Option<String> {
    NONCE.lock().ok().and_then(|n| n.clone())
}

pub(crate) fn remember_nonce(nonce: &str) {
    if let Ok(mut slot) = NONCE.lock() {
        *slot = Some(nonce.to_owned());
    }
}

/// Where the server is and how proofs address it.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    /// Where requests go, such as `http://127.0.0.1:8080`.
    pub(crate) base_url: String,
    /// The server's `DOMAIN`: a proof's `htu` is this plus the path.
    pub(crate) domain: String,
    /// A header that carries a made-up client address. The server's sign-in and registration
    /// limits count per address, so the harness needs `IP_HEADER` set to the same name and
    /// `KEMLOCK_TRUSTED_PROXIES` to include the harness.
    pub(crate) ip_header: Option<String>,
}

impl Target {
    pub(crate) fn new(base_url: &str, domain: Option<&str>, ip_header: Option<&str>) -> Target {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let domain =
            domain.map_or_else(|| base_url.clone(), |d| d.trim_end_matches('/').to_owned());
        Target {
            base_url,
            domain,
            ip_header: ip_header.map(str::to_owned),
        }
    }
}

/// What the server answered.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    /// Request sent to body read, of the last attempt.
    pub(crate) elapsed: Duration,
}

impl Reply {
    pub(crate) fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).map_err(Into::into)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// An error naming the call, the status and the body.
    pub(crate) fn error(&self, what: &str) -> BoxError {
        format!("{what}: HTTP {}: {}", self.status, self.text()).into()
    }
}

/// The tokens of a sign-in or a refresh.
#[derive(Clone, Debug)]
pub(crate) struct Tokens {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) user_id: String,
    pub(crate) expires_in: u64,
}

fn text(value: &Value, name: &str) -> Result<String> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("the reply has no {name}").into())
}

impl Tokens {
    fn from_json(value: &Value) -> Result<Tokens> {
        Ok(Tokens {
            access_token: text(value, "accessToken")?,
            refresh_token: text(value, "refreshToken")?,
            user_id: text(value, "userId")?,
            expires_in: value["expiresIn"].as_u64().unwrap_or(600),
        })
    }
}

/// The password a loadgen account uses. OPAQUE takes the client's master key as its password;
/// the real client's Argon2id would be here, and runs before the clock starts, so a fixed
/// derivation stands in for its output.
pub(crate) fn account_password(email: &str) -> [u8; 32] {
    kemlock_crypto::hash::sha256(format!("kemlock-loadgen/v1/{email}").as_bytes())
}

/// A public-key bundle for `user` and its own signature, which the server checks. Every account
/// shares one signing key and filler exchange key: only the account id differs.
fn bundle(user: &Uuid) -> Result<(Vec<u8>, Vec<u8>)> {
    let signing = kemlock_crypto::sig1::SigningKey::from_bytes(&[0x5a; 64]);
    let bundle = kemlock_crypto::bundle::Bundle {
        account_id: *user.as_bytes(),
        key_version: FIRST_KEY_VERSION,
        kx1_public: kemlock_crypto::kx1::PublicKey::from_bytes(&[0x42; 1600])
            .map_err(|e| format!("a bundle's exchange key: {e}"))?,
        sig1_public: signing
            .public_key()
            .map_err(|e| format!("a bundle's signing key: {e}"))?,
    };
    let signature = bundle
        .sign(&signing)
        .map_err(|e| format!("signing a bundle: {e}"))?;
    Ok((bundle.to_bytes(), signature))
}

/// A made-up IPv4 address in 10.0.0.0/8 for the n-th device.
fn synthetic_ip(n: u32) -> String {
    format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[derive(Debug)]
pub(crate) struct Device {
    http: reqwest::Client,
    target: Target,
    key: DpopSigner,
    ip: String,
}

impl Device {
    /// A device with a new P-256 key. `ip_seed` picks its made-up address; use a different one
    /// for each device that should be counted separately by the rate limits.
    pub(crate) fn new(http: reqwest::Client, target: Target, ip_seed: u32) -> Device {
        Device {
            http,
            target,
            key: DpopSigner::es256(),
            ip: synthetic_ip(ip_seed.wrapping_add(1)),
        }
    }

    /// A proof for one request, with the server's last nonce.
    pub(crate) fn proof(&self, method: &str, path: &str, access_token: Option<&str>) -> String {
        let nonce = current_nonce();
        let jti = Uuid::new_v4().to_string();
        let htu = format!("{}{}", self.target.domain, path);
        self.key.proof(&ProofClaims {
            method,
            htu: &htu,
            iat: unix_now(),
            jti: &jti,
            access_token,
            nonce: nonce.as_deref(),
        })
    }

    /// Sends one request with a fresh proof; when the server asks for a new nonce, once more.
    /// `uri` is the path and query.
    pub(crate) async fn send(
        &self,
        method: Method,
        uri: &str,
        access_token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply> {
        let path = uri.split('?').next().unwrap_or(uri);
        let mut reply = self.once(&method, uri, path, access_token, body).await?;
        if reply.status == 401 && reply.text().contains("use-dpop-nonce") {
            reply = self.once(&method, uri, path, access_token, body).await?;
        }
        Ok(reply)
    }

    async fn once(
        &self,
        method: &Method,
        uri: &str,
        path: &str,
        access_token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply> {
        let proof = self.proof(method.as_str(), path, access_token);
        let mut request = self
            .http
            .request(method.clone(), format!("{}{}", self.target.base_url, uri))
            .header("dpop", proof);
        if let Some(token) = access_token {
            request = request.header("authorization", format!("DPoP {token}"));
        }
        if let Some(name) = &self.target.ip_header {
            request = request.header(name.as_str(), self.ip.as_str());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let started = Instant::now();
        let response = request.send().await?;
        let status = response.status().as_u16();
        if let Some(nonce) = response
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
        {
            remember_nonce(nonce);
        }
        let body = response.bytes().await?.to_vec();
        Ok(Reply {
            status,
            body,
            elapsed: started.elapsed(),
        })
    }

    /// OPAQUE registration, both messages. Returns the status of the last: 201 for a new
    /// account.
    pub(crate) async fn register(&self, email: &str, user: Uuid) -> Result<u16> {
        let password = account_password(email);
        let (state, request) = kemlock_crypto::opaque::client_registration_start(&password)
            .map_err(|e| format!("OPAQUE registration start: {e}"))?;
        let started = self
            .send(
                Method::POST,
                "/kem/v1/accounts/register/start",
                None,
                Some(&json!({"email": email, "request": b64url::encode(&request)})),
            )
            .await?;
        if started.status != 200 {
            return Err(started.error("register/start (is SIGNUPS_ALLOWED=true?)"));
        }
        let response = b64url::decode(&text(&started.json()?, "response")?)
            .ok_or("register/start sent bad base64url")?;
        let (upload, _export_key) =
            kemlock_crypto::opaque::client_registration_finish(state, &password, &response)
                .map_err(|e| format!("OPAQUE registration finish: {e}"))?;
        let (public_bundle, bundle_signature) = bundle(&user)?;
        let finish = json!({
            "userId": user.to_string(),
            "email": email,
            "name": "Load test",
            "upload": b64url::encode(&upload),
            "kdf": {
                "memoryKib": 65536,
                "iterations": 3,
                "parallelism": 4,
                "salt": b64url::encode(&[4u8; 16]),
            },
            "publicBundle": b64url::encode(&public_bundle),
            "bundleSignature": b64url::encode(&bundle_signature),
            "sealedPrivateKeys": b64url::encode(&[0x22u8; 64]),
            "wrappedRootKey": b64url::encode(&[0x33u8; WRAPPED_ROOT_KEY_LEN]),
        });
        let finished = self
            .send(
                Method::POST,
                "/kem/v1/accounts/register/finish",
                None,
                Some(&finish),
            )
            .await?;
        Ok(finished.status)
    }

    /// OPAQUE sign-in, both messages. Returns the tokens and the time the server took for the
    /// two requests, as the client saw it. The OPAQUE client work runs between them, outside
    /// either clock.
    pub(crate) async fn sign_in(&self, email: &str) -> Result<(Tokens, Duration)> {
        let password = account_password(email);
        let (state, request) = kemlock_crypto::opaque::client_login_start(&password)
            .map_err(|e| format!("OPAQUE login start: {e}"))?;
        let started = self
            .send(
                Method::POST,
                "/kem/v1/auth/opaque/start",
                None,
                Some(&json!({"email": email, "request": b64url::encode(&request)})),
            )
            .await?;
        if started.status != 200 {
            return Err(started.error("opaque/start"));
        }
        let started_json = started.json()?;
        let response = b64url::decode(&text(&started_json, "response")?)
            .ok_or("opaque/start sent bad base64url")?;
        let (finalization, _session_key, _export_key) =
            kemlock_crypto::opaque::client_login_finish(state, &password, &response)
                .map_err(|e| format!("OPAQUE login finish: {e}"))?;
        let finished = self
            .send(
                Method::POST,
                "/kem/v1/auth/opaque/finish",
                None,
                Some(&json!({
                    "email": email,
                    "loginState": text(&started_json, "loginState")?,
                    "finalization": b64url::encode(&finalization),
                    "device": {"name": "kemlock-loadgen", "kind": "kemlock-cli"},
                })),
            )
            .await?;
        if finished.status != 200 {
            return Err(finished.error("opaque/finish"));
        }
        let finished_json = finished.json()?;
        if finished_json["status"] != "signed_in" {
            return Err("the account asks for a second step; loadgen accounts have none".into());
        }
        let tokens = Tokens::from_json(&finished_json["tokens"])?;
        Ok((tokens, started.elapsed + finished.elapsed))
    }

    /// Trades a refresh token for new tokens. The old refresh token stops working.
    pub(crate) async fn refresh(&self, refresh_token: &str) -> Result<Tokens> {
        let reply = self
            .send(
                Method::POST,
                "/kem/v1/auth/token",
                None,
                Some(&json!({"grantType": "refresh_token", "refreshToken": refresh_token})),
            )
            .await?;
        if reply.status != 200 {
            return Err(reply.error("auth/token"));
        }
        Tokens::from_json(&reply.json()?)
    }

    /// `POST /kem/v1/items:batch`.
    pub(crate) async fn put_batch(&self, access_token: &str, writes: &[Value]) -> Result<()> {
        let reply = self
            .send(
                Method::POST,
                "/kem/v1/items:batch",
                Some(access_token),
                Some(&json!({ "writes": writes })),
            )
            .await?;
        if reply.status != 200 {
            return Err(reply.error("items:batch"));
        }
        Ok(())
    }

    /// Syncs to the end and returns the cursor, which a later `since` can use.
    pub(crate) async fn current_cursor(&self, access_token: &str) -> Result<String> {
        let mut since: Option<String> = None;
        loop {
            let uri = match &since {
                Some(cursor) => format!("/kem/v1/sync?limit=500&since={cursor}"),
                None => "/kem/v1/sync?limit=500".to_owned(),
            };
            let reply = self
                .send(Method::GET, &uri, Some(access_token), None)
                .await?;
            if reply.status != 200 {
                return Err(reply.error("sync"));
            }
            let page = reply.json()?;
            let cursor = text(&page, "cursor")?;
            if !page["more"].as_bool().unwrap_or(false) {
                return Ok(cursor);
            }
            since = Some(cursor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::register::{BUNDLE_LEN, BUNDLE_PREFIX, BUNDLE_SIGNATURE_LEN};

    #[test]
    fn synthetic_addresses_differ_per_seed() {
        assert_eq!(synthetic_ip(1), "10.0.0.1");
        assert_eq!(synthetic_ip(258), "10.0.1.2");
        assert_ne!(synthetic_ip(70_000), synthetic_ip(70_001));
    }

    #[test]
    fn the_bundle_has_the_layout_the_server_checks() {
        let user = Uuid::new_v4();
        let (b, signature) = bundle(&user).expect("a bundle");
        assert_eq!(b.len(), BUNDLE_LEN);
        assert_eq!(signature.len(), BUNDLE_SIGNATURE_LEN);
        kemlock_crypto::bundle::Bundle::from_bytes(&b)
            .expect("the layout parses")
            .verify_self_signature(&signature)
            .expect("the server checks this signature");
        assert!(b.starts_with(BUNDLE_PREFIX));
        assert_eq!(&b[17..33], user.as_bytes());
        assert_eq!(&b[33..37], &FIRST_KEY_VERSION.to_be_bytes());
    }

    #[test]
    fn a_password_depends_on_the_email() {
        assert_eq!(
            account_password("a@example.org"),
            account_password("a@example.org")
        );
        assert_ne!(
            account_password("a@example.org"),
            account_password("b@example.org")
        );
    }

    #[test]
    fn a_target_drops_trailing_slashes_and_defaults_the_domain() {
        let t = Target::new("http://127.0.0.1:8080/", None, None);
        assert_eq!(t.base_url, "http://127.0.0.1:8080");
        assert_eq!(t.domain, "http://127.0.0.1:8080");
        let t = Target::new(
            "http://127.0.0.1:8080",
            Some("https://v.example.org/"),
            Some("X-Forwarded-For"),
        );
        assert_eq!(t.domain, "https://v.example.org");
        assert_eq!(t.ip_header.as_deref(), Some("X-Forwarded-For"));
    }
}
