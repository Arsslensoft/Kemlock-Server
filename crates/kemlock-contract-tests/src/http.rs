//! A small HTTP/1.1 client, and a signed-in account on top of it.
//!
//! Plain `http` only: the server under test is on `127.0.0.1` or `localhost`. A failure to reach the
//! server panics with the request in the message, since no test can go on without an answer.

use crate::account::{Account, Kdf};
use crate::util::{jwt_parts, percent_encode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::time::Duration;

/// How long one request may take. Attachments of a megabyte and a hashed password both fit.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The `Bitwarden-Client-Version` that Kemlock's app sends today (`vw_api.dart:218`).
pub const KEMLOCK_APP_VERSION: &str = "1.1.0";

/// The `Bitwarden-Client-Version` Amethystora Vault sends (design, headers table).
pub const AMETHYSTORA_VERSION: &str = "2025.12.0";

/// Bitwarden's first server version with SSH key items (`vw_items.dart:44`).
pub const SSH_KEY_VERSION: &str = "2024.12.0";

/// What the server answered.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    /// The body as text, losing what is not UTF-8.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON, or `null` when it is not.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// A header's value, whatever the case of its name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The JSON of a successful answer. Anything else panics with `what` and the answer.
    pub fn ok_json(&self, what: &str) -> Value {
        assert!(
            self.is_success(),
            "{what}: expected a success, got {} {}",
            self.status,
            self.text()
        );
        self.json()
    }
}

/// A request being built.
#[derive(Debug, Clone)]
pub struct Call {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Call {
    /// Adds a header.
    pub fn header(mut self, name: &str, value: &str) -> Call {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Adds `Authorization: Bearer <token>`.
    pub fn bearer(self, token: &str) -> Call {
        self.header("Authorization", &format!("Bearer {token}"))
    }

    /// Sends `value` as the JSON body.
    pub fn json(self, value: &Value) -> Call {
        self.body("application/json", value.to_string().into_bytes())
    }

    /// Sends `pairs` as a form body, percent-encoded as the apps do (`vw_api.dart:613-615`).
    pub fn form(self, pairs: &[(String, String)]) -> Call {
        let text: Vec<String> = pairs
            .iter()
            .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
            .collect();
        self.body(
            "application/x-www-form-urlencoded; charset=utf-8",
            text.join("&").into_bytes(),
        )
    }

    /// Sends `bytes` as the body with the content type given.
    pub fn body(mut self, content_type: &str, bytes: Vec<u8>) -> Call {
        self.headers
            .push(("Content-Type".to_owned(), content_type.to_owned()));
        self.body = bytes;
        self
    }
}

/// A client for one server.
#[derive(Debug, Clone)]
pub struct Http {
    base: String,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl Http {
    /// A client for the server at `base` (`http://127.0.0.1:8080`, no trailing slash).
    pub fn new(base: &str) -> Http {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Http {
            base: base.trim_end_matches('/').to_owned(),
            client,
        }
    }

    /// The server's address as given.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `path` on the server; an address that is already absolute is kept.
    pub fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("{}{path}", self.base)
        }
    }

    /// A request to `path` with the headers the Kemlock app sends before it signs in.
    pub fn call(&self, method: &str, path: &str) -> Call {
        Call {
            method: method.to_owned(),
            url: self.url(path),
            headers: vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Bitwarden-Client-Name".to_owned(), "kemlock".to_owned()),
                (
                    "Bitwarden-Client-Version".to_owned(),
                    KEMLOCK_APP_VERSION.to_owned(),
                ),
            ],
            body: Vec::new(),
        }
    }

    /// A request to `path` with no headers of its own: not even `Accept`.
    pub fn bare(&self, method: &str, path: &str) -> Call {
        Call {
            method: method.to_owned(),
            url: self.url(path),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Sends the request and reads the whole answer.
    pub async fn send(&self, call: Call) -> Reply {
        let label = format!("{} {}", call.method, call.url);
        let uri: hyper::Uri = call
            .url
            .parse()
            .unwrap_or_else(|e| panic!("{label}: not an address: {e}"));
        let mut builder = hyper::Request::builder()
            .method(call.method.as_str())
            .uri(uri);
        for (name, value) in &call.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::from(call.body)))
            .unwrap_or_else(|e| panic!("{label}: not a request: {e}"));
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(request))
            .await
            .unwrap_or_else(|_| panic!("{label}: no answer in {REQUEST_TIMEOUT:?}"))
            .unwrap_or_else(|e| panic!("{label}: the request failed: {e}"));
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("{label}: reading the answer failed: {e}"))
            .to_bytes()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    // ─── Accounts ──────────────────────────────────────────────────────────

    /// Registers a new account through the routes the web vault and the apps' tests use
    /// (`mobile/test/vaultwarden_server/server_kit.dart:57-90`): a verification token, then
    /// `register/finish`. Returns the account and the answer to `register/finish`, which a test
    /// of the KDF bounds reads.
    pub async fn register(&self, kdf: Kdf) -> (Account, Reply) {
        let account = Account::new(kdf);
        let verify = self
            .send(
                self.call(
                    "POST",
                    "/identity/accounts/register/send-verification-email",
                )
                .json(&json!({
                    "email": account.email,
                    "name": "Kemlock contract",
                    "receiveMarketingEmails": false,
                })),
            )
            .await;
        assert!(
            verify.status == 200,
            "send-verification-email: Vaultwarden (with SIGNUPS_VERIFY=false) answers 200 and the \
             token as a JSON string; got {} {}",
            verify.status,
            verify.text()
        );
        let token = verify.json();
        let token = token.as_str().unwrap_or_else(|| {
            panic!(
                "send-verification-email: the answer is the token as a JSON string, got {}",
                verify.text()
            )
        });
        let finish = self
            .send(
                self.call("POST", "/identity/accounts/register/finish")
                    .json(&account.register_body(token)),
            )
            .await;
        (account, finish)
    }

    /// [`Http::register`], and it must succeed.
    pub async fn register_ok(&self, kdf: Kdf) -> Account {
        let (account, finish) = self.register(kdf).await;
        assert!(
            finish.is_success(),
            "register/finish: Vaultwarden takes this account (kdf {:?}); got {} {}",
            account.kdf,
            finish.status,
            finish.text()
        );
        account
    }

    // ─── Tokens ────────────────────────────────────────────────────────────

    /// `POST /identity/connect/token` with the form given and the Kemlock app's headers.
    pub async fn token(&self, form: &[(String, String)]) -> Reply {
        self.send(self.call("POST", "/identity/connect/token").form(form))
            .await
    }

    /// The same with exactly the headers given: none of the app's.
    pub async fn token_with_headers(
        &self,
        form: &[(String, String)],
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut call = self.bare("POST", "/identity/connect/token");
        for (name, value) in headers {
            call = call.header(name, value);
        }
        self.send(call.form(form)).await
    }

    /// Signs in as the Kemlock app does (password grant, `client_id` `mobile`, device type 0) and
    /// reads the session. A refusal panics.
    pub async fn login(&self, account: &Account) -> Session {
        let device_id = crate::account::device_id();
        let reply = self.token(&account.login_form(&device_id)).await;
        let body = reply.ok_json("password grant");
        Session::from_token(self.clone(), account, &device_id, &body)
    }
}

/// One signed-in account on one server.
#[derive(Debug, Clone)]
pub struct Session {
    pub http: Http,
    pub account: Account,
    pub access: String,
    pub refresh: Option<String>,
    pub user_id: String,
    pub device_id: String,
    /// The `Bitwarden-Client-Version` sent with [`Session::call`].
    pub version: String,
}

impl Session {
    /// Reads a successful token answer.
    pub fn from_token(http: Http, account: &Account, device_id: &str, body: &Value) -> Session {
        let access = body["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("the token answer has no access_token: {body}"))
            .to_owned();
        let (_, claims) = jwt_parts(&access)
            .unwrap_or_else(|| panic!("the access token is not a three-part JWT: {access}"));
        let user_id = claims["sub"]
            .as_str()
            .unwrap_or_else(|| panic!("the access token has no sub claim: {claims}"))
            .to_owned();
        Session {
            http,
            account: account.clone(),
            access,
            refresh: body["refresh_token"]
                .as_str()
                .filter(|token| !token.is_empty())
                .map(str::to_owned),
            user_id,
            device_id: device_id.to_owned(),
            version: AMETHYSTORA_VERSION.to_owned(),
        }
    }

    /// A signed-in request without a `Bitwarden-Client-Version`.
    pub fn call_without_version(&self, method: &str, path: &str) -> Call {
        self.http
            .bare(method, path)
            .header("Accept", "application/json")
            .header("Bitwarden-Client-Name", "kemlock")
            .bearer(&self.access)
    }

    /// A signed-in request with this session's `Bitwarden-Client-Version`.
    pub fn call(&self, method: &str, path: &str) -> Call {
        self.call_without_version(method, path)
            .header("Bitwarden-Client-Version", &self.version)
    }

    /// Sends a request.
    pub async fn send(&self, call: Call) -> Reply {
        self.http.send(call).await
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.send(self.call("GET", path)).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Reply {
        self.send(self.call("POST", path).json(body)).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Reply {
        self.send(self.call("PUT", path).json(body)).await
    }

    /// A `PUT` with no body, as the app's trash and restore calls are
    /// (`vw_api.dart:370-377`).
    pub async fn put_empty(&self, path: &str) -> Reply {
        self.send(self.call("PUT", path)).await
    }

    pub async fn delete(&self, path: &str) -> Reply {
        self.send(self.call("DELETE", path)).await
    }

    /// `GET /api/accounts/revision-date`, epoch milliseconds (`vw_api.dart:331-337`).
    pub async fn revision_date(&self) -> i64 {
        let reply = self.get("/api/accounts/revision-date").await;
        let value = reply.ok_json("revision-date");
        value
            .as_i64()
            .unwrap_or_else(|| panic!("revision-date: expected a bare number, got {value}"))
    }

    /// `GET /api/sync?excludeDomains=true` as a client of the version given; `None` sends no
    /// `Bitwarden-Client-Version` at all (`vw_api.dart:343-353`).
    pub async fn sync_as(&self, version: Option<&str>) -> Reply {
        let path = "/api/sync?excludeDomains=true";
        let call = match version {
            Some(version) => self
                .call_without_version("GET", path)
                .header("Bitwarden-Client-Version", version),
            None => self.call_without_version("GET", path),
        };
        self.send(call).await
    }

    /// The whole vault as a client new enough for SSH key items.
    pub async fn sync(&self) -> Value {
        self.sync_as(Some(SSH_KEY_VERSION))
            .await
            .ok_json("/api/sync")
    }

    /// One cipher of [`Session::sync`], or `None`.
    pub async fn synced_cipher(&self, id: &str) -> Option<Value> {
        let sync = self.sync().await;
        sync["ciphers"]
            .as_array()?
            .iter()
            .find(|cipher| cipher["id"] == id)
            .cloned()
    }

    /// `POST /api/folders` with an encrypted name; the folder as the server keeps it.
    pub async fn create_folder(&self, name: &str) -> Value {
        self.post("/api/folders", &json!({"name": crate::enc::enc(name)}))
            .await
            .ok_json("POST /api/folders")
    }

    /// `POST /api/ciphers`; the cipher as the server keeps it. A refusal panics.
    pub async fn create_cipher(&self, body: &Value) -> Value {
        self.post("/api/ciphers", body)
            .await
            .ok_json("POST /api/ciphers")
    }

    /// `PUT /api/ciphers/{id}`.
    pub async fn update_cipher(&self, id: &str, body: &Value) -> Reply {
        self.put(&format!("/api/ciphers/{id}"), body).await
    }

    /// `GET /api/ciphers/{id}`.
    pub async fn get_cipher(&self, id: &str) -> Reply {
        self.get(&format!("/api/ciphers/{id}")).await
    }
}
