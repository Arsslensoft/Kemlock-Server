//! Duo's Universal Prompt (an OIDC flow with signed requests), behind `kemlock_app::two_step::Duo`,
//! as Vaultwarden 1.37.5's `duo_oidc.rs` does it.
//!
//! - Every request to Duo carries a JWT signed with HMAC-SHA512 under the integration's secret
//!   key: the health check's and the token request's `client_assertion`, and the `request`
//!   parameter of the authorization address.
//! - The person is sent to `https://<host>/oauth/v1/authorize` and comes back to
//!   `<DOMAIN>/duo-redirect-connector.html?client=<client>`, a page of the Bitwarden web vault that
//!   hands the `code` and `state` to the app.
//! - The nonce Duo signs into its ID token is the hex SHA-512/256 of the random nonce and the
//!   device's identifier, so an answer is good only for the device that asked.
//! - The ID token is checked: its signature (HS512 under the secret key), `exp`, `aud` (the
//!   integration key), `iss` (the token endpoint), `nonce` and `preferred_username`.

use aws_lc_rs::{digest, hmac};
use kemlock_app::b64url;
use kemlock_app::notices::BoxFuture;
use kemlock_app::two_step::{Duo, DuoError, DuoKeys, DuoPrompt};
use kemlock_crypto::rand;
use serde_json::{Value, json};
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;

/// The page of the Bitwarden clients Duo sends the person back to.
const REDIRECT_PAGE: &str = "duo-redirect-connector.html";
/// How long a JWT made for Duo is good: Vaultwarden's `JWT_VALIDITY_SECS`.
const JWT_VALIDITY_SECS: i64 = 300;
/// How far a clock may be off when Duo's ID token is checked.
const LEEWAY_SECS: i64 = 60;

/// Duo's API, as a client.
#[derive(Clone)]
pub struct DuoClient {
    http: reqwest13::Client,
    /// `DOMAIN`, which the redirect address is made from.
    domain: String,
    /// `https`; plain `http` only for tests that run a pretend Duo on this machine.
    scheme: &'static str,
}

impl std::fmt::Debug for DuoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuoClient")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl DuoClient {
    /// A client for the server at `domain` (`DOMAIN`).
    pub fn new(domain: &str) -> Result<Self, String> {
        Url::parse(&format!("{}/", domain.trim().trim_end_matches('/')))
            .map_err(|e| format!("DOMAIN isn't a URL: {e}"))?;
        let http = reqwest13::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("kemlock-server:Duo/2.0")
            // Duo answers directly; a redirect would carry the signed assertion elsewhere.
            .redirect(reqwest13::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(DuoClient {
            http,
            domain: domain.trim().trim_end_matches('/').to_owned(),
            scheme: "https",
        })
    }

    /// Talks plain `http` to Duo's host: for a pretend Duo on this machine in a test.
    #[must_use]
    pub fn over_plain_http(mut self) -> Self {
        self.scheme = "http";
        self
    }

    fn base(&self, host: &str) -> String {
        format!("{}://{host}", self.scheme)
    }

    /// The address Duo sends the person back to.
    fn redirect_uri(&self, client: &str) -> Result<String, DuoError> {
        let base = Url::parse(&format!("{}/", self.domain))
            .map_err(|e| DuoError::Unavailable(format!("DOMAIN isn't a URL: {e}")))?;
        let mut callback = base
            .join(REDIRECT_PAGE)
            .map_err(|e| DuoError::Unavailable(format!("the redirect address: {e}")))?;
        callback.query_pairs_mut().append_pair("client", client);
        Ok(callback.to_string())
    }

    /// A JWT for Duo's token and health endpoints: `aud` is the endpoint's address.
    fn client_assertion(&self, keys: &DuoKeys, audience: &str) -> String {
        let now = now();
        sign_jwt(
            &keys.sk,
            &json!({
                "iss": keys.ik,
                "sub": keys.ik,
                "aud": audience,
                "exp": now + JWT_VALIDITY_SECS,
                "jti": random_text(64),
                "iat": now,
            }),
        )
    }

    /// Duo's health check: the integration is set up and Duo is up.
    async fn health_check(&self, keys: &DuoKeys) -> Result<(), DuoError> {
        let url = format!("{}/oauth/v1/health_check", self.base(&keys.host));
        let assertion = self.client_assertion(keys, &url);
        let response = self
            .http
            .post(&url)
            .form(&[
                ("client_assertion", assertion.as_str()),
                ("client_id", keys.ik.as_str()),
            ])
            .send()
            .await
            .map_err(|e| DuoError::Unavailable(e.to_string()))?;
        let body: Value = serde_json::from_str(
            &response
                .text()
                .await
                .map_err(|e| DuoError::Unavailable(e.to_string()))?,
        )
        .map_err(|e| DuoError::Unavailable(format!("the health check isn't JSON: {e}")))?;
        match body.get("stat").and_then(Value::as_str) {
            Some("OK") => Ok(()),
            _ => Err(DuoError::Unavailable(format!(
                "the health check failed: {}",
                body.get("message_detail")
                    .or_else(|| body.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("no stat")
            ))),
        }
    }

    async fn start(&self, prompt: &DuoPrompt<'_>) -> Result<String, DuoError> {
        self.health_check(prompt.keys).await?;
        let now = now();
        let request = sign_jwt(
            &prompt.keys.sk,
            &json!({
                "response_type": "code",
                "scope": "openid",
                "exp": now + JWT_VALIDITY_SECS,
                "client_id": prompt.keys.ik,
                "redirect_uri": self.redirect_uri(prompt.client)?,
                "state": prompt.state,
                "duo_uname": prompt.username,
                "iss": prompt.keys.ik,
                "aud": self.base(&prompt.keys.host),
                "nonce": bound_nonce(prompt.nonce, prompt.device),
            }),
        );
        let mut url = Url::parse(&format!(
            "{}/oauth/v1/authorize",
            self.base(&prompt.keys.host)
        ))
        .map_err(|e| DuoError::Unavailable(format!("Duo's address: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &prompt.keys.ik)
            .append_pair("request", &request);
        Ok(url.to_string())
    }

    async fn finish(&self, prompt: &DuoPrompt<'_>, code: &str) -> Result<(), DuoError> {
        if code.is_empty() {
            return Err(DuoError::Rejected);
        }
        let keys = prompt.keys;
        self.health_check(keys).await?;
        let token_url = format!("{}/oauth/v1/token", self.base(&keys.host));
        let redirect = self.redirect_uri(prompt.client)?;
        let assertion = self.client_assertion(keys, &token_url);
        let response = self
            .http
            .post(&token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| DuoError::Unavailable(e.to_string()))?;
        if response.status().as_u16() != 200 {
            return Err(DuoError::Rejected);
        }
        let body: Value = serde_json::from_str(
            &response
                .text()
                .await
                .map_err(|e| DuoError::Unavailable(e.to_string()))?,
        )
        .map_err(|_| DuoError::Rejected)?;
        let id_token = body
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or(DuoError::Rejected)?;
        check_id_token(
            id_token,
            keys,
            &token_url,
            &bound_nonce(prompt.nonce, prompt.device),
            prompt.username,
            now(),
        )
    }

    /// Duo's `/auth/v2/check`, which an account's own keys are tried against before they are saved.
    async fn check(&self, keys: &DuoKeys) -> Result<(), DuoError> {
        let path = "/auth/v2/check";
        let date = httpdate_now();
        let canonical = ["GET", &keys.host, path, ""];
        // The Auth API signs the date, method, host, path and parameters, one to a line, with
        // HMAC-SHA1 and sends it as the Basic password.
        let signed = format!("{date}\n{}", canonical.join("\n"));
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, keys.sk.as_bytes());
        let signature = hex(hmac::sign(&key, signed.as_bytes()).as_ref());
        let response = self
            .http
            .get(format!("{}{path}", self.base(&keys.host)))
            .basic_auth(&keys.ik, Some(signature))
            .header("Date", date)
            .send()
            .await
            .map_err(|e| DuoError::Unavailable(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(DuoError::Rejected)
        }
    }
}

impl Duo for DuoClient {
    fn check_keys<'a>(&'a self, keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(self.check(keys))
    }

    fn auth_url<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
    ) -> BoxFuture<'a, Result<String, DuoError>> {
        Box::pin(self.start(prompt))
    }

    fn verify<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
        code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(self.finish(prompt, code))
    }
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// The date header Duo's Auth API wants and signs, RFC 2822: `Sun, 22 Nov 2026 10:00:00 +0000`.
fn httpdate_now() -> String {
    use time::format_description::well_known::Rfc2822;
    OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .unwrap_or_default()
}

/// The nonce Duo signs: the hex SHA-512/256 of the nonce and the device's identifier.
fn bound_nonce(nonce: &str, device: &str) -> String {
    hex(digest::digest(&digest::SHA512_256, format!("{nonce}{device}").as_bytes()).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_text(size: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(size);
    while out.len() < size {
        let mut buf = [0u8; 64];
        rand::fill(&mut buf);
        for byte in buf {
            if out.len() < size && byte < 248 {
                out.push(char::from(CHARSET[usize::from(byte) % CHARSET.len()]));
            }
        }
    }
    out
}

/// A JWT signed with HMAC-SHA512 under `secret`.
pub(crate) fn sign_jwt(secret: &str, claims: &Value) -> String {
    let header = b64url::encode(br#"{"typ":"JWT","alg":"HS512"}"#);
    let payload = b64url::encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let key = hmac::Key::new(hmac::HMAC_SHA512, secret.as_bytes());
    let signature = b64url::encode(hmac::sign(&key, signing_input.as_bytes()).as_ref());
    format!("{signing_input}.{signature}")
}

/// The claims of a JWT signed with HMAC-SHA512 under `secret`; `None` when it is not one, or the
/// signature doesn't check.
pub(crate) fn open_jwt(secret: &str, token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let head: Value = serde_json::from_slice(&b64url::decode(header)?).ok()?;
    if head.get("alg").and_then(Value::as_str) != Some("HS512") {
        return None;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA512, secret.as_bytes());
    hmac::verify(
        &key,
        format!("{header}.{payload}").as_bytes(),
        &b64url::decode(signature)?,
    )
    .ok()?;
    serde_json::from_slice(&b64url::decode(payload)?).ok()
}

/// Checks Duo's ID token for this prompt.
fn check_id_token(
    token: &str,
    keys: &DuoKeys,
    token_url: &str,
    nonce: &str,
    username: &str,
    now: i64,
) -> Result<(), DuoError> {
    let claims = open_jwt(&keys.sk, token).ok_or(DuoError::Rejected)?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(DuoError::Rejected)?;
    if exp + LEEWAY_SECS < now {
        return Err(DuoError::Rejected);
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => *aud == keys.ik,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(keys.ik.as_str())),
        _ => false,
    };
    let issuer_ok = claims.get("iss").and_then(Value::as_str) == Some(token_url);
    let nonce_ok = claims.get("nonce").and_then(Value::as_str) == Some(nonce);
    let user_ok = claims.get("preferred_username").and_then(Value::as_str) == Some(username);
    if audience_ok && issuer_ok && nonce_ok && user_ok {
        Ok(())
    } else {
        Err(DuoError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> DuoKeys {
        DuoKeys {
            host: "api-1234.duosecurity.com".to_owned(),
            ik: "DIXXXXXXXXXXXXXXXXXX".to_owned(),
            sk: "a-secret-key".to_owned(),
        }
    }

    #[test]
    fn a_jwt_round_trips_and_refuses_another_key_or_a_changed_body() {
        let token = sign_jwt("secret", &json!({"a": 1}));
        assert_eq!(open_jwt("secret", &token), Some(json!({"a": 1})));
        assert_eq!(open_jwt("other", &token), None);
        let forged = b64url::encode(br#"{"a":2}"#);
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = &forged;
        assert_eq!(open_jwt("secret", &parts.join(".")), None);
        assert_eq!(open_jwt("secret", "a.b"), None);
        assert_eq!(open_jwt("secret", "a.b.c.d"), None);
    }

    #[test]
    fn a_jwt_that_names_another_algorithm_is_refused() {
        let header = b64url::encode(br#"{"typ":"JWT","alg":"none"}"#);
        let payload = b64url::encode(br#"{"a":1}"#);
        assert_eq!(open_jwt("secret", &format!("{header}.{payload}.")), None);
        let signed = sign_jwt("secret", &json!({"a": 1}));
        let mut parts: Vec<&str> = signed.split('.').collect();
        parts[0] = &header;
        assert_eq!(open_jwt("secret", &parts.join(".")), None);
    }

    #[test]
    fn the_nonce_duo_signs_is_bound_to_the_device() {
        let a = bound_nonce("nonce", "device-1");
        assert_eq!(a.len(), 64);
        assert_eq!(a, bound_nonce("nonce", "device-1"));
        assert_ne!(a, bound_nonce("nonce", "device-2"));
        assert_ne!(a, bound_nonce("nonce2", "device-1"));
        // SHA-512/256 of the empty string.
        assert_eq!(
            bound_nonce("", ""),
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
    }

    #[test]
    fn the_redirect_address_is_the_connector_page_with_the_client() {
        let client = DuoClient::new("https://vault.example.org/").expect("a client");
        assert_eq!(
            client.redirect_uri("web").as_deref(),
            Ok("https://vault.example.org/duo-redirect-connector.html?client=web")
        );
        let sub = DuoClient::new("https://example.org/vault").expect("a client");
        assert_eq!(
            sub.redirect_uri("mobile").as_deref(),
            Ok("https://example.org/vault/duo-redirect-connector.html?client=mobile")
        );
        assert!(DuoClient::new("not a url").is_err());
    }

    fn token(claims: &Value) -> String {
        sign_jwt(&keys().sk, claims)
    }

    fn claims() -> Value {
        json!({
            "iss": "https://api-1234.duosecurity.com/oauth/v1/token",
            "aud": "DIXXXXXXXXXXXXXXXXXX",
            "exp": 2_000_000_000,
            "nonce": "N",
            "preferred_username": "ada@example.org",
        })
    }

    #[test]
    fn an_id_token_is_checked_against_the_prompt() {
        let url = "https://api-1234.duosecurity.com/oauth/v1/token";
        let check = |claims: &Value| {
            check_id_token(
                &token(claims),
                &keys(),
                url,
                "N",
                "ada@example.org",
                1_900_000_000,
            )
        };
        assert_eq!(check(&claims()), Ok(()));

        for (name, value) in [
            ("iss", json!("https://evil.example/oauth/v1/token")),
            ("aud", json!("DIOTHER")),
            ("nonce", json!("other")),
            ("preferred_username", json!("eve@example.org")),
            ("exp", json!(1_000_000_000)),
        ] {
            let mut changed = claims();
            changed[name] = value;
            assert_eq!(check(&changed), Err(DuoError::Rejected), "{name}");
        }
        // The audience may be a list.
        let mut listed = claims();
        listed["aud"] = json!(["x", "DIXXXXXXXXXXXXXXXXXX"]);
        assert_eq!(check(&listed), Ok(()));
        // Signed with another secret.
        assert_eq!(
            check_id_token(
                &sign_jwt("another", &claims()),
                &keys(),
                url,
                "N",
                "ada@example.org",
                1_900_000_000
            ),
            Err(DuoError::Rejected)
        );
    }
}
