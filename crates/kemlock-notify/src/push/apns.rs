//! Apple push, sent by the server itself.
//!
//! The operator makes a key for the Apple Push Notification service in their own Apple developer
//! account and gives the server its `.p8` file, key id and team id. The server signs a short-lived
//! token with it (ES256, a JWT) and posts "sync now" to Apple's HTTP/2 API for each iPhone. Nothing
//! passes through Kemlock's servers. The push carries no content: `content-available` wakes the
//! app, which then syncs.
//!
//! Settings: `KEMLOCK_APNS_KEY_FILE`, `KEMLOCK_APNS_KEY_ID` and `KEMLOCK_APNS_TEAM_ID` (all three
//! or none), `KEMLOCK_APNS_TOPIC` (the app's bundle id, `com.kemlock.app`) and
//! `KEMLOCK_APNS_SANDBOX` (for development builds of the app).

use super::{SendOutcome, b64};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinSet;

/// Apple's production push host.
pub const PRODUCTION_HOST: &str = "https://api.push.apple.com";
/// Apple's sandbox push host, for development builds of the app.
pub const SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";
/// The Kemlock app's bundle id, which is the `apns-topic` unless `KEMLOCK_APNS_TOPIC` says
/// otherwise.
pub const DEFAULT_TOPIC: &str = "com.kemlock.app";

/// How long a signed token is reused. Apple refuses tokens older than an hour and asks that one
/// is not renewed more often than every 20 minutes.
const JWT_REUSE_SECONDS: i64 = 50 * 60;

/// How long Apple holds a push for a phone that is off, in seconds. A "sync now" that waited
/// longer is no use: the app syncs when it opens anyway.
const EXPIRATION_SECONDS: i64 = 60 * 60;

/// How many pushes go to Apple at once.
const PARALLEL: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApnsConfigError {
    #[error(
        "{0} is not set (KEMLOCK_APNS_KEY_FILE, KEMLOCK_APNS_KEY_ID and KEMLOCK_APNS_TEAM_ID go together)"
    )]
    Missing(&'static str),
    #[error("{0} is not valid: {1}")]
    Invalid(&'static str, String),
    #[error("couldn't set up the Apple push client: {0}")]
    Client(String),
}

/// The Apple push key. It signs the tokens; it never shows in `Debug` output or logs.
#[derive(Clone)]
pub struct ApnsKey(Arc<EcdsaKeyPair>);

impl std::fmt::Debug for ApnsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApnsKey(<redacted>)")
    }
}

impl ApnsKey {
    /// Reads the `.p8` file's text: a PEM `PRIVATE KEY` holding a PKCS#8 P-256 key.
    pub fn from_pem(pem: &str) -> Result<ApnsKey, String> {
        const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
        const END: &str = "-----END PRIVATE KEY-----";
        let start = pem
            .find(BEGIN)
            .ok_or("it is not a PEM file with a PRIVATE KEY (the .p8 Apple gave)")?
            + BEGIN.len();
        let stop = pem[start..]
            .find(END)
            .ok_or("it is not a PEM file with a PRIVATE KEY (the .p8 Apple gave)")?
            + start;
        let der = b64::decode(&pem[start..stop]).ok_or("the key text is not base64")?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| "it is not a P-256 private key (Apple's .p8 files are)")?;
        Ok(ApnsKey(Arc::new(pair)))
    }
}

/// What the server needs to push to iPhones itself.
#[derive(Clone)]
pub struct ApnsConfig {
    pub key: ApnsKey,
    /// The key's id, from the Apple developer account.
    pub key_id: String,
    /// The developer account's team id.
    pub team_id: String,
    /// The app's bundle id.
    pub topic: String,
    /// Push through Apple's sandbox, for development builds of the app.
    pub sandbox: bool,
}

impl std::fmt::Debug for ApnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsConfig")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .field("sandbox", &self.sandbox)
            .finish_non_exhaustive()
    }
}

fn identifier(name: &'static str, value: String) -> Result<String, ApnsConfigError> {
    if value.len() > 32 || !value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ApnsConfigError::Invalid(
            name,
            "expected the letters and digits Apple shows, as in 'ABC123DEFG'".to_owned(),
        ));
    }
    Ok(value)
}

impl ApnsConfig {
    /// Reads the settings through `get` (the environment, in the server). `Ok(None)` when none of
    /// `KEMLOCK_APNS_KEY_FILE`, `KEMLOCK_APNS_KEY_ID` and `KEMLOCK_APNS_TEAM_ID` is set: the
    /// server then has no Apple key.
    pub fn from_lookup(
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<ApnsConfig>, ApnsConfigError> {
        let non_empty = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let file = non_empty("KEMLOCK_APNS_KEY_FILE");
        let key_id = non_empty("KEMLOCK_APNS_KEY_ID");
        let team_id = non_empty("KEMLOCK_APNS_TEAM_ID");
        if file.is_none() && key_id.is_none() && team_id.is_none() {
            return Ok(None);
        }
        let file = file.ok_or(ApnsConfigError::Missing("KEMLOCK_APNS_KEY_FILE"))?;
        let key_id = key_id.ok_or(ApnsConfigError::Missing("KEMLOCK_APNS_KEY_ID"))?;
        let team_id = team_id.ok_or(ApnsConfigError::Missing("KEMLOCK_APNS_TEAM_ID"))?;
        let key_id = identifier("KEMLOCK_APNS_KEY_ID", key_id)?;
        let team_id = identifier("KEMLOCK_APNS_TEAM_ID", team_id)?;

        let topic = non_empty("KEMLOCK_APNS_TOPIC").unwrap_or_else(|| DEFAULT_TOPIC.to_owned());
        if topic.len() > 255 || topic.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ApnsConfigError::Invalid(
                "KEMLOCK_APNS_TOPIC",
                "expected the app's bundle id, as in 'com.kemlock.app'".to_owned(),
            ));
        }
        let sandbox = match non_empty("KEMLOCK_APNS_SANDBOX")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("false" | "0" | "no" | "off") => false,
            Some("true" | "1" | "yes" | "on") => true,
            Some(_) => {
                return Err(ApnsConfigError::Invalid(
                    "KEMLOCK_APNS_SANDBOX",
                    "expected true or false".to_owned(),
                ));
            }
        };

        let text = std::fs::read_to_string(&file).map_err(|e| {
            ApnsConfigError::Invalid("KEMLOCK_APNS_KEY_FILE", format!("can't read {file}: {e}"))
        })?;
        let key = ApnsKey::from_pem(&text)
            .map_err(|why| ApnsConfigError::Invalid("KEMLOCK_APNS_KEY_FILE", why))?;
        Ok(Some(ApnsConfig {
            key,
            key_id,
            team_id,
            topic,
            sandbox,
        }))
    }
}

/// A signed token and when it was made.
struct Cached {
    token: String,
    issued_at: i64,
}

struct Inner {
    http: reqwest::Client,
    config: ApnsConfig,
    base: String,
    jwt: Mutex<Option<Cached>>,
}

/// How one push to one device went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Accepted,
    /// Apple no longer knows the device token: forget it.
    Forget,
    /// This one failed; the others may go on.
    Failed,
    /// Apple pushed back (rate limit, a refused key): send no more this time.
    Stop,
}

#[derive(Deserialize)]
struct Reason {
    reason: String,
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A device token is hex; anything else can't be one and mustn't reach the URL.
fn device_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 200 && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// Sends "sync now" to iPhones through Apple's push service. Cheap to clone.
#[derive(Clone)]
pub struct ApnsSender {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ApnsSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsSender")
            .field("config", &self.inner.config)
            .field("base", &self.inner.base)
            .finish_non_exhaustive()
    }
}

impl ApnsSender {
    /// A sender to Apple's production host, or its sandbox when the config says so.
    pub fn new(config: ApnsConfig) -> Result<ApnsSender, ApnsConfigError> {
        let base = if config.sandbox {
            SANDBOX_HOST
        } else {
            PRODUCTION_HOST
        };
        ApnsSender::with_base(config, base)
    }

    /// A sender to another host (a test server).
    pub(super) fn with_base(config: ApnsConfig, base: &str) -> Result<ApnsSender, ApnsConfigError> {
        let mut http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("kemlock-server/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none());
        if base.starts_with("https://") {
            // Apple's API is HTTP/2 only.
            http = http.http2_prior_knowledge();
        }
        let http = http
            .build()
            .map_err(|e| ApnsConfigError::Client(e.to_string()))?;
        Ok(ApnsSender {
            inner: Arc::new(Inner {
                http,
                config,
                base: base.trim_end_matches('/').to_owned(),
                jwt: Mutex::new(None),
            }),
        })
    }

    /// Whether this sender pushes through Apple's sandbox.
    pub fn sandbox(&self) -> bool {
        self.inner.config.sandbox
    }

    /// The provider token for `now` (seconds since the epoch): the one signed in the last 50
    /// minutes, or a new one.
    pub(super) fn bearer_at(&self, now: i64) -> Result<String, ApnsConfigError> {
        let mut cached = self.inner.jwt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = cached.as_ref()
            && (0..JWT_REUSE_SECONDS).contains(&(now - current.issued_at))
        {
            return Ok(current.token.clone());
        }
        let token = self.sign(now)?;
        *cached = Some(Cached {
            token: token.clone(),
            issued_at: now,
        });
        Ok(token)
    }

    fn sign(&self, now: i64) -> Result<String, ApnsConfigError> {
        let config = &self.inner.config;
        let header = json!({"alg": "ES256", "kid": config.key_id});
        let claims = json!({"iss": config.team_id, "iat": now});
        let signing_input = format!(
            "{}.{}",
            b64::encode_url(header.to_string().as_bytes()),
            b64::encode_url(claims.to_string().as_bytes())
        );
        let signature = config
            .key
            .0
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| ApnsConfigError::Client("the key couldn't sign".to_owned()))?;
        Ok(format!(
            "{signing_input}.{}",
            b64::encode_url(signature.as_ref())
        ))
    }

    fn forget_bearer(&self) {
        *self.inner.jwt.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Sends "sync now" to these device tokens. A token Apple no longer knows (or that can't be
    /// one) comes back in `rejected`. A failure is logged and not retried, and Apple pushing back
    /// ends the sends of this call.
    pub async fn send_sync(&self, tokens: &[String]) -> SendOutcome {
        let mut outcome = SendOutcome::default();
        for chunk in tokens.chunks(PARALLEL) {
            let bearer = match self.bearer_at(now()) {
                Ok(bearer) => bearer,
                Err(error) => {
                    tracing::warn!(%error, "couldn't sign the Apple push token");
                    return outcome;
                }
            };
            let mut sends = JoinSet::new();
            for token in chunk {
                let (sender, token, bearer) = (self.clone(), token.clone(), bearer.clone());
                sends.spawn(async move {
                    let delivery = sender.send_one(&token, &bearer).await;
                    (token, delivery)
                });
            }
            let mut stop = false;
            while let Some(done) = sends.join_next().await {
                let Ok((token, delivery)) = done else {
                    continue;
                };
                match delivery {
                    Delivery::Accepted => outcome.accepted += 1,
                    Delivery::Forget => outcome.rejected.push(token),
                    Delivery::Failed => {}
                    Delivery::Stop => stop = true,
                }
            }
            if stop {
                break;
            }
        }
        outcome
    }

    async fn send_one(&self, token: &str, bearer: &str) -> Delivery {
        if !device_token(token) {
            return Delivery::Forget;
        }
        let inner = &self.inner;
        let response = inner
            .http
            .post(format!("{}/3/device/{token}", inner.base))
            .header("authorization", format!("bearer {bearer}"))
            .header("apns-topic", &inner.config.topic)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-expiration", (now() + EXPIRATION_SECONDS).to_string())
            // Pushes waiting for a phone that is off become one.
            .header("apns-collapse-id", "sync")
            .json(&json!({"aps": {"content-available": 1}}))
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, "couldn't reach Apple's push service");
                return Delivery::Failed;
            }
        };
        let status = response.status().as_u16();
        if status == 200 {
            return Delivery::Accepted;
        }
        let reason = response
            .json::<Reason>()
            .await
            .map(|r| r.reason)
            .unwrap_or_default();
        match (status, reason.as_str()) {
            (410, _) | (400, "BadDeviceToken" | "Unregistered") => Delivery::Forget,
            (403, "ExpiredProviderToken") => {
                // Sign a new one next time.
                self.forget_bearer();
                tracing::warn!("Apple says the push token expired; the server's clock may be off");
                Delivery::Stop
            }
            (403, _) => {
                tracing::warn!(
                    %reason,
                    "Apple refused the push key; check KEMLOCK_APNS_KEY_ID, KEMLOCK_APNS_TEAM_ID and that the key has push enabled"
                );
                Delivery::Stop
            }
            (429 | 503, _) => {
                tracing::warn!(status, %reason, "Apple asks to slow down; no more pushes now");
                Delivery::Stop
            }
            _ => {
                tracing::warn!(status, %reason, "Apple didn't take a push");
                Delivery::Failed
            }
        }
    }
}

/// A config with a fresh key, for the dispatch tests.
#[cfg(test)]
pub(super) fn test_config() -> ApnsConfig {
    let (pem, _) = tests::make_key();
    tests::config(&pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::serve;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;
    use std::collections::HashMap;

    /// A fresh key as the `.p8` text Apple gives, and its public half.
    pub(super) fn make_key() -> (String, Vec<u8>) {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("generates");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("loads");
        let body = b64::encode_standard(pkcs8.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        (pem, pair.public_key().as_ref().to_vec())
    }

    pub(super) fn config(pem: &str) -> ApnsConfig {
        ApnsConfig {
            key: ApnsKey::from_pem(pem).expect("key"),
            key_id: "KEY1234567".to_owned(),
            team_id: "TEAM123456".to_owned(),
            topic: "com.kemlock.app".to_owned(),
            sandbox: false,
        }
    }

    fn part(jwt: &str, index: usize) -> Value {
        let text = jwt.split('.').nth(index).expect("a part");
        serde_json::from_slice(&b64::decode(text).expect("base64")).expect("json")
    }

    #[test]
    fn the_token_has_apples_header_and_claims_and_a_good_signature() {
        let (pem, public) = make_key();
        let sender = ApnsSender::with_base(config(&pem), "http://127.0.0.1:1").expect("sender");
        let jwt = sender.bearer_at(1_800_000_000).expect("signs");
        assert_eq!(part(&jwt, 0), json!({"alg": "ES256", "kid": "KEY1234567"}));
        assert_eq!(
            part(&jwt, 1),
            json!({"iss": "TEAM123456", "iat": 1_800_000_000})
        );
        let (signing_input, signature) = jwt.rsplit_once('.').expect("three parts");
        let signature = b64::decode(signature).expect("base64");
        assert_eq!(signature.len(), 64, "r and s, not DER");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
            .verify(signing_input.as_bytes(), &signature)
            .expect("the key signed it");
        assert!(!jwt.contains(['=', '+', '/']));
    }

    #[test]
    fn the_token_is_reused_for_fifty_minutes_and_never_an_hour() {
        let (pem, _) = make_key();
        let sender = ApnsSender::with_base(config(&pem), "http://127.0.0.1:1").expect("sender");
        let first = sender.bearer_at(1_000).expect("signs");
        // ES256 signatures are randomised, so a new token differs from the old.
        assert_eq!(sender.bearer_at(1_000).expect("same"), first);
        assert_eq!(sender.bearer_at(1_000 + 49 * 60).expect("same"), first);
        let second = sender.bearer_at(1_000 + 50 * 60).expect("a new one");
        assert_ne!(second, first);
        assert_eq!(part(&second, 1)["iat"], 1_000 + 50 * 60);
        // Never past 60 minutes, whatever the cache says: it was renewed at 50.
        let third = sender.bearer_at(1_000 + 59 * 60).expect("same as second");
        assert_eq!(third, second);
        // A clock that went back is not trusted.
        assert_ne!(sender.bearer_at(10).expect("new"), second);
    }

    #[test]
    fn the_key_stays_out_of_debug_output_and_bad_keys_are_refused() {
        let (pem, _) = make_key();
        let config = config(&pem);
        let shown = format!("{config:?} {:?}", config.key);
        assert!(shown.contains("KEY1234567"));
        let body = pem.lines().nth(1).expect("a line");
        assert!(!shown.contains(body));
        assert!(ApnsKey::from_pem("hello").is_err());
        assert!(
            ApnsKey::from_pem("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----")
                .is_err()
        );
        // Valid base64 that is no key.
        assert!(
            ApnsKey::from_pem("-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----")
                .is_err()
        );
    }

    /// One request the fake Apple saw: the device token, the headers and the body.
    type Request = (String, HashMap<String, String>, Value);

    /// What the fake Apple saw.
    #[derive(Default)]
    struct Seen {
        requests: Mutex<Vec<Request>>,
    }

    async fn apple(
        State(seen): State<Arc<Seen>>,
        Path(token): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        let headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_owned()))
            .collect();
        seen.requests
            .lock()
            .expect("lock")
            .push((token.clone(), headers, body));
        match token.as_str() {
            "dead0410" => {
                (StatusCode::GONE, Json(json!({"reason": "Unregistered"}))).into_response()
            }
            "bad0400" => (
                StatusCode::BAD_REQUEST,
                Json(json!({"reason": "BadDeviceToken"})),
            )
                .into_response(),
            "other400" => (
                StatusCode::BAD_REQUEST,
                Json(json!({"reason": "PayloadEmpty"})),
            )
                .into_response(),
            "f00429" => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"reason": "TooManyRequests"})),
            )
                .into_response(),
            "f00500" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            "f00403" => (
                StatusCode::FORBIDDEN,
                Json(json!({"reason": "ExpiredProviderToken"})),
            )
                .into_response(),
            _ => StatusCode::OK.into_response(),
        }
    }

    async fn fake() -> (Arc<Seen>, ApnsSender) {
        let seen = Arc::new(Seen::default());
        let app = Router::new()
            .route("/3/device/{token}", post(apple))
            .with_state(seen.clone());
        let address = serve(app).await;
        let (pem, _) = make_key();
        let sender =
            ApnsSender::with_base(config(&pem), &format!("http://{address}")).expect("sender");
        (seen, sender)
    }

    fn tokens(list: &[&str]) -> Vec<String> {
        list.iter().map(|t| (*t).to_owned()).collect()
    }

    #[tokio::test]
    async fn a_push_is_apples_background_request_with_no_content() {
        let (seen, sender) = fake().await;
        let outcome = sender.send_sync(&tokens(&["c0ffee01"])).await;
        assert_eq!(outcome.accepted, 1);
        assert!(outcome.rejected.is_empty());
        let requests = seen.requests.lock().expect("lock");
        let (token, headers, body) = &requests[0];
        assert_eq!(token, "c0ffee01");
        assert_eq!(body, &json!({"aps": {"content-available": 1}}));
        assert_eq!(headers["apns-topic"], "com.kemlock.app");
        assert_eq!(headers["apns-push-type"], "background");
        assert_eq!(headers["apns-priority"], "5");
        let expiration: i64 = headers["apns-expiration"].parse().expect("a time");
        assert!((expiration - now() - EXPIRATION_SECONDS).abs() < 30);
        let bearer = headers["authorization"]
            .strip_prefix("bearer ")
            .expect("a bearer token");
        assert_eq!(part(bearer, 0)["kid"], "KEY1234567");
        assert_eq!(part(bearer, 1)["iss"], "TEAM123456");
    }

    #[tokio::test]
    async fn tokens_apple_does_not_know_are_forgotten() {
        let (_, sender) = fake().await;
        let outcome = sender
            .send_sync(&tokens(&["dead0410", "aa01", "bad0400", "other400"]))
            .await;
        assert_eq!(outcome.accepted, 1);
        let mut rejected = outcome.rejected;
        rejected.sort();
        assert_eq!(rejected, ["bad0400", "dead0410"]);
    }

    #[tokio::test]
    async fn a_token_that_cannot_be_apples_never_reaches_the_url() {
        let (seen, sender) = fake().await;
        let outcome = sender
            .send_sync(&tokens(&["../../x", "zz", "", "aa/bb", "aa?b"]))
            .await;
        assert_eq!(outcome.accepted, 0);
        assert_eq!(outcome.rejected.len(), 5);
        assert!(seen.requests.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_failure_is_not_retried_and_a_rate_limit_ends_the_sends() {
        let (seen, sender) = fake().await;
        // A 500 for one device does not stop the others.
        let outcome = sender.send_sync(&tokens(&["f00500", "aa02"])).await;
        assert_eq!(outcome.accepted, 1);
        assert_eq!(seen.requests.lock().expect("lock").len(), 2, "no retry");

        // Apple pushing back stops the rest: the second chunk of 16 is never sent.
        seen.requests.lock().expect("lock").clear();
        let mut many = vec!["f00429".to_owned()];
        many.extend((0..PARALLEL * 2).map(|i| format!("{:02x}", i + 1)));
        let outcome = sender.send_sync(&many).await;
        assert!(outcome.accepted < many.len());
        assert!(seen.requests.lock().expect("lock").len() <= PARALLEL);
    }

    #[tokio::test]
    async fn an_expired_provider_token_is_signed_again_next_time() {
        let (seen, sender) = fake().await;
        let first = sender.bearer_at(now()).expect("signs");
        sender.send_sync(&tokens(&["f00403"])).await;
        let second = sender.bearer_at(now()).expect("signs");
        assert_ne!(first, second);
        assert_eq!(seen.requests.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn an_unreachable_apple_is_a_failure_not_a_panic() {
        let (pem, _) = make_key();
        let address = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds");
            listener.local_addr().expect("address")
        };
        let sender =
            ApnsSender::with_base(config(&pem), &format!("http://{address}")).expect("sender");
        let outcome = sender.send_sync(&tokens(&["aa01"])).await;
        assert_eq!(outcome, SendOutcome::default());
    }

    #[test]
    fn sandbox_picks_apples_sandbox_host() {
        let (pem, _) = make_key();
        let mut sandbox = config(&pem);
        sandbox.sandbox = true;
        let sender = ApnsSender::new(sandbox).expect("sender");
        assert!(sender.sandbox());
        assert_eq!(sender.inner.base, SANDBOX_HOST);
        let sender = ApnsSender::new(config(&pem)).expect("sender");
        assert_eq!(sender.inner.base, PRODUCTION_HOST);
    }

    // ---- settings ----

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    /// A `.p8` on disk, removed with the guard.
    struct KeyFile(std::path::PathBuf);

    impl KeyFile {
        fn new(name: &str, text: &str) -> KeyFile {
            let path = std::env::temp_dir().join(format!(
                "kemlock-apns-{name}-{}.p8",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::write(&path, text).expect("writes");
            KeyFile(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("utf-8 path")
        }
    }

    impl Drop for KeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn no_apple_settings_means_no_apple_key() {
        assert_eq!(
            ApnsConfig::from_lookup(&lookup(&[]))
                .expect("ok")
                .map(|_| ()),
            None
        );
        // The topic and sandbox alone don't make a key.
        assert!(
            ApnsConfig::from_lookup(&lookup(&[
                ("KEMLOCK_APNS_TOPIC", "com.example"),
                ("KEMLOCK_APNS_SANDBOX", "true")
            ]))
            .expect("ok")
            .is_none()
        );
    }

    #[test]
    fn the_settings_are_read_with_their_defaults() {
        let (pem, _) = make_key();
        let file = KeyFile::new("ok", &pem);
        let config = ApnsConfig::from_lookup(&lookup(&[
            ("KEMLOCK_APNS_KEY_FILE", file.path()),
            ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
            ("KEMLOCK_APNS_TEAM_ID", " TEAM123456 "),
        ]))
        .expect("valid")
        .expect("on");
        assert_eq!(config.key_id, "KEY1234567");
        assert_eq!(config.team_id, "TEAM123456");
        assert_eq!(config.topic, "com.kemlock.app");
        assert!(!config.sandbox);

        let config = ApnsConfig::from_lookup(&lookup(&[
            ("KEMLOCK_APNS_KEY_FILE", file.path()),
            ("KEMLOCK_APNS_KEY_ID", "KEY1234567"),
            ("KEMLOCK_APNS_TEAM_ID", "TEAM123456"),
            ("KEMLOCK_APNS_TOPIC", "com.example.kemlock"),
            ("KEMLOCK_APNS_SANDBOX", "TRUE"),
        ]))
        .expect("valid")
        .expect("on");
        assert_eq!(config.topic, "com.example.kemlock");
        assert!(config.sandbox);
    }

    #[test]
    fn the_three_settings_come_all_or_none_and_a_bad_one_names_itself() {
        let (pem, _) = make_key();
        let file = KeyFile::new("bad", &pem);
        let key_file = ("KEMLOCK_APNS_KEY_FILE", file.path());
        let key_id = ("KEMLOCK_APNS_KEY_ID", "KEY1234567");
        let team = ("KEMLOCK_APNS_TEAM_ID", "TEAM123456");
        let read = |pairs: &[(&str, &str)]| ApnsConfig::from_lookup(&lookup(pairs));

        assert_eq!(
            read(&[key_file, key_id]).map(|_| ()),
            Err(ApnsConfigError::Missing("KEMLOCK_APNS_TEAM_ID"))
        );
        assert_eq!(
            read(&[key_id, team]).map(|_| ()),
            Err(ApnsConfigError::Missing("KEMLOCK_APNS_KEY_FILE"))
        );
        assert_eq!(
            read(&[team]).map(|_| ()),
            Err(ApnsConfigError::Missing("KEMLOCK_APNS_KEY_FILE"))
        );
        assert!(matches!(
            read(&[key_file, ("KEMLOCK_APNS_KEY_ID", "not valid!"), team]),
            Err(ApnsConfigError::Invalid("KEMLOCK_APNS_KEY_ID", _))
        ));
        assert!(matches!(
            read(&[key_file, key_id, ("KEMLOCK_APNS_TEAM_ID", "a b")]),
            Err(ApnsConfigError::Invalid("KEMLOCK_APNS_TEAM_ID", _))
        ));
        assert!(matches!(
            read(&[key_file, key_id, team, ("KEMLOCK_APNS_SANDBOX", "maybe")]),
            Err(ApnsConfigError::Invalid("KEMLOCK_APNS_SANDBOX", _))
        ));
        assert!(matches!(
            read(&[key_file, key_id, team, ("KEMLOCK_APNS_TOPIC", "has space")]),
            Err(ApnsConfigError::Invalid("KEMLOCK_APNS_TOPIC", _))
        ));
        assert!(matches!(
            read(&[("KEMLOCK_APNS_KEY_FILE", "/no/such/key.p8"), key_id, team]),
            Err(ApnsConfigError::Invalid("KEMLOCK_APNS_KEY_FILE", _))
        ));
        let not_a_key = KeyFile::new("junk", "this is not a key");
        let error = read(&[("KEMLOCK_APNS_KEY_FILE", not_a_key.path()), key_id, team])
            .map(|_| ())
            .expect_err("refused");
        assert!(matches!(
            error,
            ApnsConfigError::Invalid("KEMLOCK_APNS_KEY_FILE", _)
        ));
        assert!(
            !error.to_string().contains("this is not a key"),
            "the file's text is never repeated"
        );
        // The message names the setting, which is how the server's start reports it.
        assert!(error.to_string().starts_with("KEMLOCK_APNS_KEY_FILE"));
    }
}
