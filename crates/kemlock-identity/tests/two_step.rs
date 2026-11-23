//! The Yubico and Duo clients against pretend services on this machine, which check what the real
//! ones check: the signatures, the nonce, the code.

use aws_lc_rs::{digest, hmac};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kemlock_app::b64url;
use kemlock_app::two_step::{Duo, DuoError, DuoKeys, DuoPrompt, Yubico, YubicoError};
use kemlock_identity::{DuoClient, YubicoClient};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const DOMAIN: &str = "https://vault.test";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds a local port");
    let address = listener.local_addr().expect("an address").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    address
}

// ---------------------------------------------------------------------------------------------
// Yubico.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(STANDARD[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn unbase64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|c| *c != b'=') {
        let value = STANDARD.iter().position(|s| *s == c).expect("Base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

fn sha1_hmac(key: &[u8], data: &str) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    hmac::sign(&key, data.as_bytes()).as_ref().to_vec()
}

const API_KEY: [u8; 20] = [0x42; 20];
const OTP: &str = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";

/// How the pretend validation server answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A signed `OK` for the OTP and nonce asked about.
    Good,
    /// A signed `REPLAYED_OTP`.
    Replayed,
    /// An `OK` signed with another key.
    WrongKey,
    /// An `OK` for another nonce.
    WrongNonce,
    /// An HTTP 500.
    Broken,
}

struct YubicoServer {
    mode: Mutex<Mode>,
    asked: Mutex<Vec<String>>,
}

async fn validate(
    State(server): State<Arc<YubicoServer>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let mode = *server.mode.lock().expect("lock");
    server
        .asked
        .lock()
        .expect("lock")
        .push(query.get("otp").cloned().unwrap_or_default());
    // The request is signed in alphabetical order, without `h`.
    let sorted: BTreeMap<&str, &str> = query
        .iter()
        .filter(|(k, _)| k.as_str() != "h")
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let signed: Vec<String> = sorted.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let expected = base64(&sha1_hmac(&API_KEY, &signed.join("&")));
    if query.get("h") != Some(&expected) || query.get("id").map(String::as_str) != Some("12345") {
        return (StatusCode::OK, "status=BAD_SIGNATURE\r\n").into_response();
    }
    if mode == Mode::Broken {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let (status, key, nonce) = match mode {
        Mode::Replayed => ("REPLAYED_OTP", API_KEY, query["nonce"].clone()),
        Mode::WrongKey => ("OK", [0x43; 20], query["nonce"].clone()),
        Mode::WrongNonce => ("OK", API_KEY, "someone-elses-nonce".to_owned()),
        Mode::Good | Mode::Broken => ("OK", API_KEY, query["nonce"].clone()),
    };
    let fields = BTreeMap::from([
        ("nonce", nonce),
        ("otp", query["otp"].clone()),
        ("sl", "100".to_owned()),
        ("status", status.to_owned()),
        ("t", "2026-11-22T10:00:00Z0123".to_owned()),
    ]);
    let lines: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let signature = base64(&sha1_hmac(&key, &lines.join("&")));
    (
        StatusCode::OK,
        format!("h={signature}\r\n{}\r\n", lines.join("\r\n")),
    )
        .into_response()
}

async fn yubico(mode: Mode) -> (YubicoClient, Arc<YubicoServer>) {
    let server = Arc::new(YubicoServer {
        mode: Mutex::new(mode),
        asked: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/wsapi/2.0/verify", get(validate))
        .with_state(server.clone());
    let address = serve(app).await;
    let client = YubicoClient::new(
        "12345",
        &base64(&API_KEY),
        Some(&format!("http://{address}/wsapi/2.0/verify")),
    )
    .expect("a client");
    (client, server)
}

#[tokio::test]
async fn yubico_accepts_a_signed_ok_for_the_otp() {
    let (client, server) = yubico(Mode::Good).await;
    assert_eq!(client.verify(OTP).await, Ok(()));
    assert_eq!(server.asked.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn yubico_refuses_what_the_service_refuses_or_cannot_vouch_for() {
    for mode in [Mode::Replayed, Mode::WrongKey, Mode::WrongNonce] {
        let (client, _) = yubico(mode).await;
        assert_eq!(client.verify(OTP).await, Err(YubicoError::Rejected));
    }
    let (client, _) = yubico(Mode::Broken).await;
    assert!(matches!(
        client.verify(OTP).await,
        Err(YubicoError::Unavailable(_))
    ));
}

#[tokio::test]
async fn an_otp_that_cannot_be_one_never_leaves_the_server() {
    let (client, server) = yubico(Mode::Good).await;
    for otp in [
        "",
        "short",
        "has a space in it but is long enough to be one!!",
    ] {
        assert_eq!(
            client.verify(otp).await,
            Err(YubicoError::Rejected),
            "{otp}"
        );
    }
    assert!(server.asked.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn an_unreachable_validation_server_is_unavailable() {
    let client = YubicoClient::new(
        "12345",
        &base64(&API_KEY),
        Some("http://127.0.0.1:1/wsapi/2.0/verify"),
    )
    .expect("a client");
    assert!(matches!(
        client.verify(OTP).await,
        Err(YubicoError::Unavailable(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Duo.

const IK: &str = "DIXXXXXXXXXXXXXXXXXX";
const SK: &str = "the-duo-secret-key";

fn jwt_hs512(secret: &str, claims: &Value) -> String {
    let header = b64url::encode(br#"{"typ":"JWT","alg":"HS512"}"#);
    let payload = b64url::encode(claims.to_string().as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA512, secret.as_bytes());
    let signature =
        b64url::encode(hmac::sign(&key, format!("{header}.{payload}").as_bytes()).as_ref());
    format!("{header}.{payload}.{signature}")
}

fn claims_of(secret: &str, token: &str) -> Option<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts[..] else {
        return None;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA512, secret.as_bytes());
    hmac::verify(
        &key,
        format!("{header}.{payload}").as_bytes(),
        &b64url::decode(signature)?,
    )
    .ok()?;
    serde_json::from_slice(&b64url::decode(payload)?).ok()
}

/// What the pretend Duo knows about the prompt the person is sent to.
#[derive(Default)]
struct Prompted {
    nonce: String,
    username: String,
}

struct DuoServer {
    host: Mutex<String>,
    healthy: Mutex<bool>,
    prompted: Mutex<Prompted>,
}

async fn health(
    State(duo): State<Arc<DuoServer>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let url = format!(
        "http://{}/oauth/v1/health_check",
        duo.host.lock().expect("lock")
    );
    let claims = form.get("client_assertion").and_then(|t| claims_of(SK, t));
    let genuine = claims
        .as_ref()
        .is_some_and(|c| c["iss"] == IK && c["sub"] == IK && c["aud"] == url.as_str())
        && form.get("client_id").map(String::as_str) == Some(IK);
    if !genuine {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "bad", "message_detail": "no"})),
        )
            .into_response();
    }
    if *duo.healthy.lock().expect("lock") {
        Json(json!({"stat": "OK"})).into_response()
    } else {
        Json(json!({"message": "down", "message_detail": "maintenance"})).into_response()
    }
}

async fn token(
    State(duo): State<Arc<DuoServer>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let host = duo.host.lock().expect("lock").clone();
    let url = format!("http://{host}/oauth/v1/token");
    let asserted = form
        .get("client_assertion")
        .and_then(|t| claims_of(SK, t))
        .is_some_and(|c| c["aud"] == url.as_str() && c["iss"] == IK);
    let right = form.get("grant_type").map(String::as_str) == Some("authorization_code")
        && form.get("code").map(String::as_str) == Some("good-code")
        && form.get("redirect_uri").map(String::as_str)
            == Some("https://vault.test/duo-redirect-connector.html?client=web")
        && form.get("client_assertion_type").map(String::as_str)
            == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    if !(asserted && right) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let prompted = duo.prompted.lock().expect("lock");
    let id_token = jwt_hs512(
        SK,
        &json!({
            "iss": url,
            "aud": IK,
            "exp": now() + 3600,
            "nonce": prompted.nonce,
            "preferred_username": prompted.username,
        }),
    );
    Json(json!({
        "id_token": id_token,
        "access_token": "an-access-token",
        "expires_in": 3600,
        "token_type": "Bearer",
    }))
    .into_response()
}

async fn check(State(duo): State<Arc<DuoServer>>, headers: HeaderMap) -> Response {
    let host = duo.host.lock().expect("lock").clone();
    let date = headers
        .get(header::DATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .map(unbase64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let expected = format!(
        "{IK}:{}",
        hex(&sha1_hmac(
            SK.as_bytes(),
            &format!("{date}\nGET\n{host}\n/auth/v2/check\n")
        ))
    );
    if basic == expected {
        Json(json!({"stat": "OK", "response": {"time": 1}})).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn pretend_duo() -> (DuoClient, DuoKeys, Arc<DuoServer>) {
    let server = Arc::new(DuoServer {
        host: Mutex::new(String::new()),
        healthy: Mutex::new(true),
        prompted: Mutex::new(Prompted::default()),
    });
    let app = Router::new()
        .route("/oauth/v1/health_check", post(health))
        .route("/oauth/v1/token", post(token))
        .route("/auth/v2/check", get(check))
        .with_state(server.clone());
    let address = serve(app).await;
    *server.host.lock().expect("lock") = address.clone();
    let keys = DuoKeys {
        host: address,
        ik: IK.to_owned(),
        sk: SK.to_owned(),
    };
    let client = DuoClient::new(DOMAIN).expect("a client").over_plain_http();
    (client, keys, server)
}

fn prompt<'a>(keys: &'a DuoKeys, state: &'a str, nonce: &'a str) -> DuoPrompt<'a> {
    DuoPrompt {
        keys,
        username: "ada@example.org",
        client: "web",
        device: "device-1",
        state,
        nonce,
    }
}

/// The nonce the pretend Duo must see signed into the prompt for this device.
fn bound(nonce: &str, device: &str) -> String {
    hex(digest::digest(&digest::SHA512_256, format!("{nonce}{device}").as_bytes()).as_ref())
}

#[tokio::test]
async fn a_prompt_is_a_signed_request_to_duos_authorize_endpoint() {
    let (client, keys, _) = pretend_duo().await;
    let url = client
        .auth_url(&prompt(&keys, "the-state", "the-nonce"))
        .await
        .expect("a prompt starts");
    let parsed = url::Url::parse(&url).expect("an address");
    assert_eq!(parsed.path(), "/oauth/v1/authorize");
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], IK);
    let claims = claims_of(SK, &query["request"]).expect("signed under the secret key");
    assert_eq!(claims["state"], "the-state");
    assert_eq!(claims["duo_uname"], "ada@example.org");
    assert_eq!(claims["client_id"], IK);
    assert_eq!(claims["iss"], IK);
    assert_eq!(claims["scope"], "openid");
    assert_eq!(claims["response_type"], "code");
    assert_eq!(
        claims["redirect_uri"],
        "https://vault.test/duo-redirect-connector.html?client=web"
    );
    assert_eq!(claims["nonce"], bound("the-nonce", "device-1"));
    assert!(claims["exp"].as_i64().expect("an expiry") > now());
}

#[tokio::test]
async fn a_prompt_is_not_started_while_duo_is_down() {
    let (client, keys, server) = pretend_duo().await;
    *server.healthy.lock().expect("lock") = false;
    let result = client.auth_url(&prompt(&keys, "s", "n")).await;
    assert!(
        matches!(result, Err(DuoError::Unavailable(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn duos_answer_is_accepted_for_the_person_and_device_that_asked() {
    let (client, keys, server) = pretend_duo().await;
    // What Duo noted from the signed request: the person, and the nonce bound to the device.
    {
        let mut prompted = server.prompted.lock().expect("lock");
        prompted.nonce = bound("the-nonce", "device-1");
        prompted.username = "ada@example.org".to_owned();
    }
    let ask = prompt(&keys, "the-state", "the-nonce");
    assert_eq!(client.verify(&ask, "good-code").await, Ok(()));
    assert_eq!(
        client.verify(&ask, "wrong-code").await,
        Err(DuoError::Rejected)
    );
    assert_eq!(client.verify(&ask, "").await, Err(DuoError::Rejected));

    // Another device derives another nonce, so the ID token Duo made is no good to it.
    let other_device = DuoPrompt {
        device: "device-2",
        ..ask
    };
    assert_eq!(
        client.verify(&other_device, "good-code").await,
        Err(DuoError::Rejected)
    );
    // Nor to another person.
    let other_person = DuoPrompt {
        username: "eve@example.org",
        ..ask
    };
    assert_eq!(
        client.verify(&other_person, "good-code").await,
        Err(DuoError::Rejected)
    );
}

#[tokio::test]
async fn duo_keys_are_checked_with_the_auth_api() {
    let (client, keys, _) = pretend_duo().await;
    assert_eq!(client.check_keys(&keys).await, Ok(()));
    let wrong = DuoKeys {
        sk: "another-secret".to_owned(),
        ..keys
    };
    assert_eq!(client.check_keys(&wrong).await, Err(DuoError::Rejected));
}
