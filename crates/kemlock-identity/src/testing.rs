//! Test support: an in-process OpenID Connect provider and a signer for test tokens.
//!
//! [`FakeProvider`] is a small axum app on a local port. It serves discovery and a JWKS, takes a
//! browser to a pretend login that signs a fixed test person in at once, redirects back with a
//! code, and exchanges that code, with PKCE, a nonce and a client secret checked as a real
//! provider checks them, for an ID token signed with a test ES256 key. Knobs make it misbehave:
//! rotate its key, sign with a key it doesn't publish, issue expired tokens, name another
//! audience. The scripted gate test in `kemlock-server` and this crate's tests use it.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use kemlock_app::b64url;
use kemlock_crypto::{hash, p256, rand};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

/// Signs JWTs with a P-256 key (ES256), and publishes the key as a JWK.
#[derive(Debug)]
pub struct Es256Signer {
    key: p256::SigningKey,
    kid: String,
}

impl Es256Signer {
    /// A new random key with the key id `kid`.
    pub fn new(kid: &str) -> Self {
        Es256Signer {
            key: p256::SigningKey::generate(),
            kid: kid.to_owned(),
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key as a JWK, as a provider's `jwks_uri` lists it.
    pub fn jwk(&self) -> Value {
        let (x, y) = self.key.public_xy();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
            "x": b64url::encode(&x),
            "y": b64url::encode(&y),
        })
    }

    /// A compact JWT with the usual header and these claims.
    pub fn sign(&self, claims: &Value) -> String {
        self.sign_with_header(
            &json!({"alg": "ES256", "typ": "JWT", "kid": self.kid}),
            claims,
        )
    }

    /// A compact JWT with any header, for building tokens that break a rule.
    pub fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            b64url::encode(header.to_string().as_bytes()),
            b64url::encode(claims.to_string().as_bytes())
        );
        let signature: [u8; 64] = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url::encode(&signature))
    }
}

/// The person the fake provider signs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeUser {
    pub subject: String,
    pub email: Option<String>,
    /// `None` leaves the claim out.
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub amr: Vec<String>,
    pub groups: Vec<String>,
    pub session_id: Option<String>,
}

impl FakeUser {
    /// A person with a verified email, no `amr` and no groups.
    pub fn new(subject: &str, email: &str) -> Self {
        FakeUser {
            subject: subject.to_owned(),
            email: Some(email.to_owned()),
            email_verified: Some(true),
            name: Some("Ada Lovelace".to_owned()),
            amr: Vec::new(),
            groups: Vec::new(),
            session_id: Some("provider-session-1".to_owned()),
        }
    }
}

struct Issued {
    redirect_uri: String,
    nonce: Option<String>,
    challenge: String,
    user: FakeUser,
}

struct Inner {
    user: FakeUser,
    signer: Es256Signer,
    /// When set, ID tokens are signed with this key, which the JWKS doesn't publish.
    rogue: Option<Es256Signer>,
    codes: HashMap<String, Issued>,
    id_token_lifetime: i64,
    audience: Option<String>,
    string_booleans: bool,
    token_requests: usize,
    discovery_requests: usize,
    keys_made: u32,
}

struct Shared {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    inner: Mutex<Inner>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("the provider lock isn't poisoned")
    }
}

/// An OpenID Connect provider on `127.0.0.1`, for tests. It stops when dropped.
pub struct FakeProvider {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeProvider")
            .field("issuer", &self.shared.issuer)
            .finish_non_exhaustive()
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeProvider {
    /// Starts a provider for `client_id` on a free local port. With a `client_secret` it demands
    /// the secret at the token endpoint (a confidential client); without, none (a public client).
    /// The signed-in person starts as `ada@example.org`.
    pub async fn start(client_id: &str, client_secret: Option<&str>) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let issuer = format!("http://{}", listener.local_addr()?);
        let shared = Arc::new(Shared {
            issuer,
            client_id: client_id.to_owned(),
            client_secret: client_secret.map(str::to_owned),
            inner: Mutex::new(Inner {
                user: FakeUser::new("sub-ada", "ada@example.org"),
                signer: Es256Signer::new("key-1"),
                rogue: None,
                codes: HashMap::new(),
                id_token_lifetime: 300,
                audience: None,
                string_booleans: false,
                token_requests: 0,
                discovery_requests: 0,
                keys_made: 1,
            }),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize_endpoint))
            .route("/token", post(token_endpoint))
            .with_state(Arc::clone(&shared));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(FakeProvider { shared, task })
    }

    /// The issuer URL: `http://127.0.0.1:<port>`, no trailing slash.
    pub fn issuer(&self) -> &str {
        &self.shared.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.shared.client_id
    }

    pub fn client_secret(&self) -> Option<&str> {
        self.shared.client_secret.as_deref()
    }

    /// Changes who the next login signs in.
    pub fn set_user(&self, user: FakeUser) {
        self.shared.lock().user = user;
    }

    pub fn user(&self) -> FakeUser {
        self.shared.lock().user.clone()
    }

    /// The browser's trip: "logs in" at the authorization URL and returns where the provider
    /// redirects to, `<redirect_uri>?code=...&state=...`. Does what `GET /authorize` does,
    /// without the network.
    pub fn approve(&self, authorization_url: &str) -> Result<String, String> {
        let url = url::Url::parse(authorization_url).map_err(|e| format!("not a URL: {e}"))?;
        let query: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        authorize(&self.shared, &query)
    }

    /// Replaces the signing key, and the JWKS with it, as a provider does when it rotates.
    pub fn rotate_key(&self) {
        let mut inner = self.shared.lock();
        inner.keys_made += 1;
        inner.signer = Es256Signer::new(&format!("key-{}", inner.keys_made));
    }

    /// Signs ID tokens with a key the JWKS doesn't publish, so their signatures can't verify.
    pub fn sign_ids_with_a_rogue_key(&self, on: bool) {
        self.shared.lock().rogue = on.then(|| Es256Signer::new("key-1"));
    }

    /// Seconds from issue to expiry of ID tokens; negative issues tokens already expired.
    pub fn set_id_token_lifetime(&self, secs: i64) {
        self.shared.lock().id_token_lifetime = secs;
    }

    /// Names this audience instead of the client.
    pub fn set_audience(&self, audience: Option<&str>) {
        self.shared.lock().audience = audience.map(str::to_owned);
    }

    /// Sends `email_verified` as the string `"true"`, as some providers do.
    pub fn set_string_booleans(&self, on: bool) {
        self.shared.lock().string_booleans = on;
    }

    /// How many times the discovery document has been asked for.
    pub fn discovery_requests(&self) -> usize {
        self.shared.lock().discovery_requests
    }

    /// How many token requests have come in.
    pub fn token_requests(&self) -> usize {
        self.shared.lock().token_requests
    }

    /// The claims of a valid back-channel logout token for the subject and/or session id.
    pub fn logout_claims(&self, subject: Option<&str>, session_id: Option<&str>) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut claims = json!({
            "iss": self.shared.issuer,
            "aud": self.shared.client_id,
            "iat": now,
            "exp": now + 120,
            "jti": random_text(),
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        });
        if let Some(subject) = subject {
            claims["sub"] = json!(subject);
        }
        if let Some(session_id) = session_id {
            claims["sid"] = json!(session_id);
        }
        claims
    }

    /// Signs claims with the provider's current key.
    pub fn sign(&self, claims: &Value) -> String {
        self.shared.lock().signer.sign(claims)
    }

    /// A valid back-channel logout token for the subject and/or session id.
    pub fn logout_token(&self, subject: Option<&str>, session_id: Option<&str>) -> String {
        self.sign(&self.logout_claims(subject, session_id))
    }
}

fn random_text() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    b64url::encode(&bytes)
}

/// Standard base64 with padding, for the `Authorization: Basic` header a client sends.
fn standard_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

async fn discovery(State(shared): State<Arc<Shared>>) -> Json<Value> {
    shared.lock().discovery_requests += 1;
    let issuer = &shared.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid", "email", "profile", "groups"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "iss", "email", "email_verified", "name", "amr", "groups", "sid"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    }))
}

async fn jwks(State(shared): State<Arc<Shared>>) -> Json<Value> {
    let jwk = shared.lock().signer.jwk();
    Json(json!({"keys": [jwk]}))
}

/// The authorization endpoint's work: checks the request, remembers the code, and returns the
/// redirect location.
fn authorize(shared: &Shared, query: &HashMap<String, String>) -> Result<String, String> {
    let get = |name: &str| query.get(name).map(String::as_str);
    if get("response_type") != Some("code") {
        return Err("response_type must be code".to_owned());
    }
    if get("client_id") != Some(shared.client_id.as_str()) {
        return Err("unknown client_id".to_owned());
    }
    let redirect_uri = get("redirect_uri").ok_or("redirect_uri is required")?;
    if !get("scope").is_some_and(|s| s.split(' ').any(|scope| scope == "openid")) {
        return Err("the openid scope is required".to_owned());
    }
    if get("code_challenge_method") != Some("S256") {
        return Err("PKCE with S256 is required".to_owned());
    }
    let challenge = get("code_challenge").ok_or("code_challenge is required")?;

    let code = random_text();
    let user = shared.lock().user.clone();
    shared.lock().codes.insert(
        code.clone(),
        Issued {
            redirect_uri: redirect_uri.to_owned(),
            nonce: get("nonce").map(str::to_owned),
            challenge: challenge.to_owned(),
            user,
        },
    );
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!("{redirect_uri}{separator}code={code}");
    if let Some(state) = get("state") {
        location.push_str("&state=");
        location.push_str(state);
    }
    Ok(location)
}

async fn authorize_endpoint(
    State(shared): State<Arc<Shared>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match authorize(&shared, &query) {
        Ok(location) => (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response(),
        Err(why) => (StatusCode::BAD_REQUEST, why).into_response(),
    }
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

async fn token_endpoint(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    shared.lock().token_requests += 1;

    // The client authenticates, by Basic header or in the form; a public client just names itself.
    let field = |name: &str| form.get(name).map(String::as_str);
    let authenticated = match &shared.client_secret {
        Some(secret) => {
            let basic = format!(
                "Basic {}",
                standard_base64(format!("{}:{secret}", shared.client_id).as_bytes())
            );
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some(basic.as_str())
                || (field("client_id") == Some(shared.client_id.as_str())
                    && field("client_secret") == Some(secret.as_str()))
        }
        None => field("client_id") == Some(shared.client_id.as_str()),
    };
    if !authenticated {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
    }
    if field("grant_type") != Some("authorization_code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "authorization_code only",
        );
    }

    // A code works once, whatever else is wrong with the request.
    let Some(issued) = field("code").and_then(|code| shared.lock().codes.remove(code)) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown or used code",
        );
    };
    if field("redirect_uri") != Some(issued.redirect_uri.as_str()) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }
    let Some(verifier) = field("code_verifier") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier is required",
        );
    };
    if b64url::encode(&hash::sha256(verifier.as_bytes())) != issued.challenge {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verifier mismatch",
        );
    }

    let id_token = id_token(&shared, &issued);
    Json(json!({
        "access_token": format!("at-{}", random_text()),
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    }))
    .into_response()
}

fn id_token(shared: &Shared, issued: &Issued) -> String {
    let inner = shared.lock();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let user = &issued.user;
    let audience = inner
        .audience
        .clone()
        .unwrap_or_else(|| shared.client_id.clone());
    let mut claims = json!({
        "iss": shared.issuer,
        "sub": user.subject,
        "aud": [audience],
        "exp": now + inner.id_token_lifetime,
        "iat": now,
    });
    if let Some(nonce) = &issued.nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(email) = &user.email {
        claims["email"] = json!(email);
    }
    if let Some(verified) = user.email_verified {
        claims["email_verified"] = if inner.string_booleans {
            json!(verified.to_string())
        } else {
            json!(verified)
        };
    }
    if let Some(name) = &user.name {
        claims["name"] = json!(name);
    }
    if !user.amr.is_empty() {
        claims["amr"] = json!(user.amr);
    }
    if !user.groups.is_empty() {
        claims["groups"] = json!(user.groups);
    }
    if let Some(sid) = &user.session_id {
        claims["sid"] = json!(sid);
    }
    inner.rogue.as_ref().unwrap_or(&inner.signer).sign(&claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_base64_matches_rfc4648() {
        assert_eq!(standard_base64(b""), "");
        assert_eq!(standard_base64(b"f"), "Zg==");
        assert_eq!(standard_base64(b"fo"), "Zm8=");
        assert_eq!(standard_base64(b"foo"), "Zm9v");
        assert_eq!(standard_base64(b"foob"), "Zm9vYg==");
        assert_eq!(standard_base64(b"kemlock:s3cret"), "a2VtbG9jazpzM2NyZXQ=");
    }

    #[test]
    fn a_signed_token_has_three_parts_and_a_published_key() {
        let signer = Es256Signer::new("k");
        let token = signer.sign(&json!({"a": 1}));
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(signer.jwk()["kid"], "k");
        assert_eq!(signer.jwk()["alg"], "ES256");
    }
}
