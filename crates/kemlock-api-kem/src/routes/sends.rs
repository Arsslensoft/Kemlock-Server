//! Sends: `/kem/v1/sends` for the owner and `/kem/v1/send-access/{accessId}` for anyone with a
//! link.
//!
//! The owner's routes are DPoP-authenticated like the item routes: `POST /sends` makes a Send,
//! `GET /sends` lists them, `GET`, `PUT` and `DELETE /sends/{id}` read, change and delete one, and
//! `PUT /sends/{id}/file` streams a file Send's bytes (`Content-Length` required).
//!
//! The byte format of a Send is docs/crypto.md's "Sends". The client chooses the Send's id (a UUID
//! version 4), because the seals bind it, and the server checks only what it can without the key:
//! the id, the kind, that `meta` and `payload` are at least a nonce and a tag, that `sealedKey` is
//! 64 bytes, that a password proof is 32 bytes and that a file's announced size is a `KMA1` length.
//!
//! The public routes take no account. `POST /send-access/{accessId}` opens a Send and answers with
//! ciphertext only (plus the dates and, unless hidden, the sender's email); `POST
//! /send-access/{accessId}/file` streams a file Send's bytes. The body may carry `{"password":
//! "<proof>"}`, the value the client derived from the password, in base64url. Wrong proofs are
//! counted, 10 a minute per Send, then doubling delays. A Send that is off, expired, deleted, out of
//! views or still waiting for its file is a plain 404.
//!
//! The key to a Send is in the link's fragment and never reaches any of these routes. Binary values
//! are base64url without padding, ids are UUIDs and times are Unix seconds.
//!
//! These routes need a Send repository, blob storage and the owner's policies besides the API's
//! own state, so they are a router of their own, [`sends_router`], merged by the server. Merge it
//! under the longer file timeout: an upload takes as long as the connection does.

use super::view::MaybeView;
use crate::dto::decode;
use crate::extract::{Authed, Body, ClientIp, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::{Limiter, ip_key};
use crate::state::{Api, Crypto, Store};
use axum::body::{Body as HttpBody, BodyDataStream, Bytes};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use futures_util::StreamExt;
use kemlock_app::files::{BodyError, BodySource};
use kemlock_app::ports::TokenSigner;
use kemlock_app::sends::{
    AccessSend, CreateSend, CreateSendInput, DeleteSend, GetSend, ListSends, SendBlobs,
    SendPolicies, SendRepo, SendsConfig, SendsError, UpdateSend, UpdateSendInput, UploadSendFile,
    access_id, parse_access_id,
};
use kemlock_crypto::{kma1, send as format};
use kemlock_domain::sends::{NewSend, SendFileFormat, SendId, SendKind, SendOptions, SendRecord};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

// ---- wire types ----

/// A file Send's bytes, announced when the Send is made.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewFileDto {
    /// The exact length in bytes of the `KMA1` file the client will upload, header and tags
    /// included.
    pub size: u64,
}

/// `POST /sends`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSendRequest {
    /// The Send's id: a UUID version 4 the client chooses, because the seals bind it
    /// (docs/crypto.md, Sends). An id that is taken is a 409.
    pub id: Uuid,
    /// `text` or `file`.
    pub kind: String,
    /// The owner's name and notes, sealed under the meta key: HKDF of the owner's item-wrap child
    /// key, the Send id and the key version, never the link key (docs/crypto.md "Sends";
    /// base64url, at least 28 bytes).
    pub meta: String,
    /// The link key sealed under the owner's item-wrap key: `u32be(key version)` and the seal,
    /// exactly 64 bytes (base64url).
    pub sealed_key: String,
    /// What a recipient opens with the key from the link: the note, or the file's name and size,
    /// sealed under the payload key (base64url, at least 28 bytes).
    pub payload: String,
    /// For a file Send.
    pub file: Option<NewFileDto>,
    /// How many times it may be opened; absent for no limit.
    pub max_access: Option<u32>,
    #[serde(default)]
    pub hide_email: bool,
    #[serde(default)]
    pub disabled: bool,
    /// When the link stops working (Unix seconds); absent for never before deletion.
    pub expires_at: Option<i64>,
    /// When the Send is deleted (Unix seconds): up to 30 days ahead.
    pub deletion_at: i64,
    /// The password proof, exactly 32 bytes (base64url); absent for no password.
    pub password: Option<String>,
}

/// `PUT /sends/{id}`: the settings an owner may change. The Send's key, file and view count never
/// change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSendRequest {
    pub meta: String,
    /// New content, for a note.
    pub payload: Option<String>,
    pub max_access: Option<u32>,
    #[serde(default)]
    pub hide_email: bool,
    #[serde(default)]
    pub disabled: bool,
    pub expires_at: Option<i64>,
    pub deletion_at: i64,
    /// A new password proof, exactly 32 bytes; absent keeps the password.
    pub password: Option<String>,
    /// Takes the password away. Not together with `password`.
    #[serde(default)]
    pub remove_password: bool,
    /// The account's key version the client sealed `meta` and `payload` for. A change for a version
    /// that is no longer the account's is refused with `409 key-version-stale`; absent (an old
    /// client) is accepted without the check.
    pub key_version: Option<u32>,
}

/// A file Send's bytes, as the owner sees them.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendFileDto {
    pub size: u64,
    /// Whether the bytes have arrived. A file Send that is not ready can't be opened.
    pub ready: bool,
}

/// A Send as its owner sees it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendDto {
    pub id: Uuid,
    /// The id the link carries.
    pub access_id: String,
    pub kind: String,
    pub meta: String,
    pub sealed_key: String,
    pub payload: String,
    pub file: Option<SendFileDto>,
    pub has_password: bool,
    pub max_access: Option<u32>,
    pub access_count: u32,
    pub hide_email: bool,
    pub disabled: bool,
    pub expires_at: Option<i64>,
    pub deletion_at: i64,
    pub created_at: i64,
    pub revised_at: i64,
    /// Where to `PUT` a file Send's bytes; only in the answer that makes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_url: Option<String>,
}

fn b64(bytes: &[u8]) -> String {
    kemlock_app::b64url::encode(bytes)
}

impl SendDto {
    fn of(send: &SendRecord) -> SendDto {
        SendDto {
            id: send.id.0,
            access_id: access_id(send.id),
            kind: send.kind.as_str().to_owned(),
            meta: b64(&send.meta),
            sealed_key: b64(&send.sealed_key),
            payload: b64(&send.payload),
            file: send.file.map(|f| SendFileDto {
                size: f.size,
                ready: f.ready,
            }),
            has_password: send.has_password(),
            max_access: send.max_access,
            access_count: send.access_count,
            hide_email: send.hide_email,
            disabled: send.disabled,
            expires_at: send.expires_at.map(OffsetDateTime::unix_timestamp),
            deletion_at: send.deletion_at.unix_timestamp(),
            created_at: send.created_at.unix_timestamp(),
            revised_at: send.revised_at.unix_timestamp(),
            upload_url: None,
        }
    }
}

/// The optional body of an access: a password proof.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessRequest {
    /// The value the client derived from the password (base64url), for a Send that has one.
    pub password: Option<String>,
}

/// What a recipient gets: ciphertext and dates.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessDto {
    /// The access id.
    pub id: String,
    pub kind: String,
    /// The note, or the file's name and size, sealed under the Send's key (base64url).
    pub payload: String,
    /// A file Send's size in bytes; `POST …/file` streams them.
    pub file_size: Option<u64>,
    pub expires_at: Option<i64>,
    pub deletion_at: i64,
    /// The sender's email, unless they hid it.
    pub sender_email: Option<String>,
}

// ---- errors ----

fn problem(config: &SendsConfig, error: SendsError) -> Problem {
    match error {
        SendsError::Invalid(detail) => Problem::bad_request(detail),
        SendsError::TooLarge => Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file-too-large",
            "The file is larger than this server allows",
        )
        .with("maxSize", json!(config.limits.max_file_size)),
        SendsError::Quota(refusal) => super::files::quota_problem(refusal, refusal.send_message()),
        SendsError::NotFound => Problem::not_found(),
        SendsError::Policy(detail) => Problem::new(
            StatusCode::FORBIDDEN,
            "send-policy",
            "A policy of one of your spaces forbids this",
        )
        .detail(detail),
        SendsError::PasswordRequired => Problem::new(
            StatusCode::UNAUTHORIZED,
            "send-password-required",
            "This Send needs a password",
        )
        .header(header::WWW_AUTHENTICATE, "KemlockSend"),
        SendsError::WrongPassword => Problem::new(
            StatusCode::UNAUTHORIZED,
            "send-wrong-password",
            "The password is wrong",
        )
        .header(header::WWW_AUTHENTICATE, "KemlockSend"),
        SendsError::Duplicate => Problem::new(
            StatusCode::CONFLICT,
            "already-exists",
            "That already exists",
        ),
        SendsError::StaleKeyVersion { current } => Problem::new(
            StatusCode::CONFLICT,
            "key-version-stale",
            "The account's keys changed since this device unlocked",
        )
        .with("currentKeyVersion", json!(current)),
        SendsError::AlreadyUploaded => Problem::new(
            StatusCode::CONFLICT,
            "already-uploaded",
            "The file was uploaded already",
        ),
        SendsError::LengthMismatch => Problem::new(
            StatusCode::BAD_REQUEST,
            "length-mismatch",
            "The body isn't the size announced when the Send was made",
        ),
        SendsError::NotKma1(why) => Problem::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "not-kma1",
            "The bytes are not a KMA1 file",
        )
        .detail(why),
        SendsError::Interrupted => Problem::new(
            StatusCode::BAD_REQUEST,
            "upload-interrupted",
            "The upload broke off before its end",
        ),
        SendsError::Store(message) | SendsError::Blob(message) => {
            tracing::error!(%message, "a Send operation failed");
            Problem::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Something went wrong on the server",
            )
        }
    }
}

fn time_from(secs: i64, what: &'static str) -> Result<OffsetDateTime, Problem> {
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|_| Problem::bad_request(format!("{what} isn't a valid time")))
}

fn parse_id(text: &str) -> Result<SendId, Problem> {
    text.parse()
        .map_err(|_| Problem::bad_request("the Send id isn't a UUID"))
}

fn options_from(
    max_access: Option<u32>,
    hide_email: bool,
    disabled: bool,
    expires_at: Option<i64>,
    deletion_at: i64,
) -> Result<SendOptions, Problem> {
    Ok(SendOptions {
        max_access,
        hide_email,
        disabled,
        expires_at: expires_at.map(|s| time_from(s, "expiresAt")).transpose()?,
        deletion_at: time_from(deletion_at, "deletionAt")?,
    })
}

/// The request's `Content-Length`. A body of unknown length is refused, because the upload must
/// match the size announced and the cap is checked against it before any byte is read.
fn content_length(headers: &HeaderMap) -> Result<u64, Problem> {
    let length_required = || {
        Problem::new(
            StatusCode::LENGTH_REQUIRED,
            "length-required",
            "Content-Length is required",
        )
        .detail("send the file with its Content-Length, not chunked")
    };
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(length_required());
    }
    let value = headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(length_required)?;
    value
        .to_str()
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(|| Problem::bad_request("Content-Length isn't a number"))
}

/// A sealed meta or payload: base64url of at least a nonce and a tag. What is inside is the
/// client's; the server can't open it and checks no more than its length.
fn sealed_part(field: &str, text: &str) -> Result<Vec<u8>, Problem> {
    let bytes = decode(field, text)?;
    if bytes.len() < format::MIN_SEALED_LEN {
        return Err(Problem::bad_request(format!(
            "{field} is shorter than a sealed value ({} bytes)",
            format::MIN_SEALED_LEN
        )));
    }
    Ok(bytes)
}

/// A sealed link key: exactly `u32be(key version)`, a nonce, the 32-byte key and a tag.
fn sealed_key_part(text: &str) -> Result<Vec<u8>, Problem> {
    let bytes = decode("sealedKey", text)?;
    if bytes.len() != format::SEALED_KEY_LEN {
        return Err(Problem::bad_request(format!(
            "sealedKey must be {} bytes",
            format::SEALED_KEY_LEN
        )));
    }
    Ok(bytes)
}

/// A password proof: the 32 bytes of the client's Argon2id.
fn proof_part(text: &str) -> Result<Vec<u8>, Problem> {
    let bytes = decode("password", text)?;
    if bytes.len() != format::PROOF_LEN {
        return Err(Problem::bad_request(format!(
            "password must be a {}-byte proof",
            format::PROOF_LEN
        )));
    }
    Ok(bytes)
}

/// The password proof of an access, from its optional body.
fn proof_of(body: &Body) -> Result<Option<Vec<u8>>, Problem> {
    if body.0.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let request: AccessRequest = body.json()?;
    request
        .password
        .as_deref()
        .map(|p| decode("password", p))
        .transpose()
}

/// The request body as the use case reads it: chunk by chunk, never whole.
struct RequestBody(BodyDataStream);

impl BodySource for RequestBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, BodyError> {
        loop {
            match self.0.next().await {
                Some(Ok(chunk)) if chunk.is_empty() => {}
                Some(Ok(chunk)) => return Ok(Some(chunk)),
                Some(Err(_)) => return Err(BodyError),
                None => return Ok(None),
            }
        }
    }
}

// ---- state ----

struct SendsInner<S, P, K, R, B, Q> {
    api: Api<S, P, K>,
    sends: R,
    blobs: B,
    policies: Q,
    config: SendsConfig,
    /// Password tries: 10 a minute per Send, then doubling delays (design, "Rate limits").
    password_limit: Limiter,
    /// Password proofs per client address: 30 a minute, then doubling delays, whatever the ids.
    source_limit: Limiter,
}

/// The state of the Send routes: the API's own state, the Send repository, blob storage, the
/// owner's policies and the Send settings. Cheap to clone.
pub struct SendsApi<S, P, K, R, B, Q>(Arc<SendsInner<S, P, K, R, B, Q>>);

impl<S, P, K, R, B, Q> Clone for SendsApi<S, P, K, R, B, Q> {
    fn clone(&self) -> Self {
        SendsApi(Arc::clone(&self.0))
    }
}

impl<S, P, K, R, B, Q> std::fmt::Debug for SendsApi<S, P, K, R, B, Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendsApi").finish_non_exhaustive()
    }
}

/// Wrong tries allowed per Send per minute.
const PASSWORD_TRIES_PER_MINUTE: u32 = 10;

/// Password proofs one client address may send a minute, to any Sends.
const PROOFS_PER_ADDRESS_PER_MINUTE: u32 = 30;

impl<S, P, K, R, B, Q> SendsApi<S, P, K, R, B, Q> {
    pub fn new(api: Api<S, P, K>, sends: R, blobs: B, policies: Q, config: SendsConfig) -> Self {
        SendsApi(Arc::new(SendsInner {
            api,
            sends,
            blobs,
            policies,
            config,
            password_limit: Limiter::new(PASSWORD_TRIES_PER_MINUTE, 60),
            source_limit: Limiter::new(PROOFS_PER_ADDRESS_PER_MINUTE, 60),
        }))
    }
}

/// An authenticated request, checked by the API's own extractor against the API's own state.
pub(crate) struct SendAuthed(Authed);

impl<S, P, K, R, B, Q> FromRequestParts<SendsApi<S, P, K, R, B, Q>> for SendAuthed
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: Send + Sync + 'static,
    B: Send + Sync + 'static,
    Q: Send + Sync + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        sends: &SendsApi<S, P, K, R, B, Q>,
    ) -> Result<Self, Problem> {
        <Authed as FromRequestParts<Api<S, P, K>>>::from_request_parts(parts, &sends.0.api)
            .await
            .map(SendAuthed)
    }
}

/// The client's address, checked by the API's own extractor against the API's own state.
pub(crate) struct SendClientIp(IpAddr);

impl<S, P, K, R, B, Q> FromRequestParts<SendsApi<S, P, K, R, B, Q>> for SendClientIp
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: Send + Sync + 'static,
    B: Send + Sync + 'static,
    Q: Send + Sync + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        sends: &SendsApi<S, P, K, R, B, Q>,
    ) -> Result<Self, Problem> {
        <ClientIp as FromRequestParts<Api<S, P, K>>>::from_request_parts(parts, &sends.0.api)
            .await
            .map(|ClientIp(ip)| SendClientIp(ip))
    }
}

/// Every response carries the current DPoP nonce, as the other routes do.
async fn nonce_header<S, P, K>(
    State(api): State<Api<S, P, K>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&api.dpop.current_nonce(api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

impl<S, P, K, R, B, Q> SendsApi<S, P, K, R, B, Q>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SendRepo + Clone + 'static,
    B: SendBlobs + Clone + 'static,
    Q: SendPolicies + Clone + 'static,
{
    fn create(&self) -> CreateSend<R, Q, S, P> {
        CreateSend {
            sends: self.0.sends.clone(),
            policies: self.0.policies.clone(),
            events: self.0.api.store.clone(),
            env: self.0.api.crypto.clone(),
            config: SendsConfig {
                quota: self.0.api.live.send_limit(),
                ..self.0.config
            },
        }
    }

    fn update(&self) -> UpdateSend<R, Q, S, P> {
        UpdateSend {
            sends: self.0.sends.clone(),
            policies: self.0.policies.clone(),
            events: self.0.api.store.clone(),
            env: self.0.api.crypto.clone(),
        }
    }

    fn list(&self) -> ListSends<R> {
        ListSends {
            sends: self.0.sends.clone(),
        }
    }

    fn get(&self) -> GetSend<R> {
        GetSend {
            sends: self.0.sends.clone(),
        }
    }

    fn delete(&self) -> DeleteSend<R, B, S, P> {
        DeleteSend {
            sends: self.0.sends.clone(),
            blobs: self.0.blobs.clone(),
            events: self.0.api.store.clone(),
            clock: self.0.api.crypto.clone(),
        }
    }

    fn upload(&self) -> UploadSendFile<R, B, S, P> {
        UploadSendFile {
            sends: self.0.sends.clone(),
            blobs: self.0.blobs.clone(),
            events: self.0.api.store.clone(),
            clock: self.0.api.crypto.clone(),
            config: SendsConfig {
                quota: self.0.api.live.send_limit(),
                ..self.0.config
            },
        }
    }

    fn access(&self) -> AccessSend<R, S, B, P> {
        AccessSend {
            sends: self.0.sends.clone(),
            users: self.0.api.store.clone(),
            blobs: self.0.blobs.clone(),
            env: self.0.api.crypto.clone(),
        }
    }

    fn problem(&self, error: SendsError) -> Problem {
        problem(&self.0.config, error)
    }

    /// A Send with a view limit is opened at its home only: a replica that counted views of its
    /// own would allow the whole limit again. Says where to go, and that it can be tried again
    /// when the home is back. A Send without a limit, or on a server that isn't a replica, passes.
    async fn refuse_if_limited_elsewhere(
        &self,
        view: Option<kemlock_app::federation_view::SharedView>,
        access_id: &str,
    ) -> Result<(), Problem> {
        let Some(view) = view else { return Ok(()) };
        let Some(id) = parse_access_id(access_id) else {
            return Ok(());
        };
        let send = self
            .0
            .sends
            .send_by_id(id)
            .await
            .map_err(|e| self.problem(SendsError::from(e)))?;
        let Some(send) = send.filter(|s| s.max_access.is_some()) else {
            return Ok(());
        };
        let home = view
            .limited_send_home(send.owner)
            .await
            .map_err(|e| self.problem(SendsError::from(e)))?;
        match home {
            None => Ok(()),
            Some(home) => Err(Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "send-home-unavailable",
                "This link has a view limit, so only its home server can open it",
            )
            .detail(format!("Try again when the home server is back: {home}"))
            .with("home", json!(home))),
        }
    }

    /// This server's own URL of a file Send's upload.
    fn upload_url(&self, id: SendId) -> String {
        format!(
            "{}/kem/v1/sends/{id}/file",
            self.0.api.config.domain.trim_end_matches('/')
        )
    }

    /// Counts one password try against the Send, when the request carries a proof: a 429 when it
    /// is over. A request without a proof reveals nothing and costs nothing, so it isn't counted.
    ///
    /// Two counts. Each address (a /56 for IPv6) takes only so many proofs a minute, whatever
    /// the ids. Then the Send itself counts the tries, keyed by its id, and only once the id
    /// parses and names an open Send that has a password: a flood of made-up ids can't push the
    /// counter of a real Send out of the limiter, because made-up ids are never counted there.
    async fn count_try(
        &self,
        access_id: &str,
        proof: &Option<Vec<u8>>,
        ip: IpAddr,
    ) -> Result<(), Problem> {
        if proof.is_none() {
            return Ok(());
        }
        let now = self.0.api.now();
        self.0
            .source_limit
            .check(&ip_key(ip), now)
            .map_err(rate_limited)?;
        let Some(id) = parse_access_id(access_id) else {
            return Ok(());
        };
        let send = self
            .0
            .sends
            .send_by_id(id)
            .await
            .map_err(|e| self.problem(SendsError::from(e)))?;
        if !send.is_some_and(|s| s.has_password() && s.is_open(self.0.api.crypto.now())) {
            return Ok(());
        }
        self.0
            .password_limit
            .check(&format!("send:{id}"), now)
            .map_err(rate_limited)
    }

    /// Forgets the Send's wrong tries, after a right password.
    fn clear_tries(&self, access_id: &str) {
        if let Some(id) = parse_access_id(access_id) {
            self.0.password_limit.clear(&format!("send:{id}"));
        }
    }

    /// `POST /kem/v1/sends`.
    pub(crate) async fn handle_create(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
        body: Body,
    ) -> Result<Response, Problem> {
        let request: CreateSendRequest = body.json()?;
        let kind = SendKind::parse(&request.kind)
            .ok_or_else(|| Problem::bad_request("the kind must be text or file"))?;
        if request.id.get_version_num() != 4 {
            return Err(Problem::bad_request("the Send id must be a version 4 UUID"));
        }
        if let Some(file) = &request.file {
            kma1::check_len(file.size)
                .map_err(|_| Problem::bad_request("file.size isn't the length of any KMA1 file"))?;
        }
        let file = request.file.map(|f| (f.size, SendFileFormat::Kma1));
        let new = NewSend {
            id: SendId(request.id),
            kind,
            meta: sealed_part("meta", &request.meta)?,
            sealed_key: sealed_key_part(&request.sealed_key)?,
            payload: sealed_part("payload", &request.payload)?,
            file,
            options: options_from(
                request.max_access,
                request.hide_email,
                request.disabled,
                request.expires_at,
                request.deletion_at,
            )?,
        };
        let password_proof = request.password.as_deref().map(proof_part).transpose()?;
        let send = sends
            .create()
            .execute(
                &authed.actor,
                CreateSendInput {
                    send: new,
                    password_proof,
                },
            )
            .await
            .map_err(|e| sends.problem(e))?;
        let mut dto = SendDto::of(&send);
        let file_upload = send.file.is_some();
        if file_upload {
            dto.upload_url = Some(sends.upload_url(send.id));
        }
        let mut response = (StatusCode::CREATED, Json(dto)).into_response();
        if let Ok(location) = HeaderValue::from_str(&format!("/kem/v1/sends/{}", send.id)) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    }

    /// `GET /kem/v1/sends`.
    pub(crate) async fn handle_list(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
    ) -> Result<Json<Vec<SendDto>>, Problem> {
        let listed = sends
            .list()
            .execute(&authed.actor)
            .await
            .map_err(|e| sends.problem(e))?;
        Ok(Json(listed.iter().map(SendDto::of).collect()))
    }

    /// `GET /kem/v1/sends/{id}`.
    pub(crate) async fn handle_get(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
        Path(id): Path<String>,
    ) -> Result<Json<SendDto>, Problem> {
        let send = sends
            .get()
            .execute(&authed.actor, parse_id(&id)?)
            .await
            .map_err(|e| sends.problem(e))?;
        Ok(Json(SendDto::of(&send)))
    }

    /// `PUT /kem/v1/sends/{id}`.
    pub(crate) async fn handle_update(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<Json<SendDto>, Problem> {
        let request: UpdateSendRequest = body.json()?;
        if request.remove_password && request.password.is_some() {
            return Err(Problem::bad_request(
                "give a new password or remove it, not both",
            ));
        }
        let password_proof = if request.remove_password {
            Some(None)
        } else {
            request
                .password
                .as_deref()
                .map(|p| proof_part(p).map(Some))
                .transpose()?
        };
        let input = UpdateSendInput {
            meta: sealed_part("meta", &request.meta)?,
            payload: request
                .payload
                .as_deref()
                .map(|p| sealed_part("payload", p))
                .transpose()?,
            options: options_from(
                request.max_access,
                request.hide_email,
                request.disabled,
                request.expires_at,
                request.deletion_at,
            )?,
            password_proof,
        };
        let send = sends
            .update()
            .execute_at(&authed.actor, parse_id(&id)?, input, request.key_version)
            .await
            .map_err(|e| sends.problem(e))?;
        Ok(Json(SendDto::of(&send)))
    }

    /// `DELETE /kem/v1/sends/{id}`.
    pub(crate) async fn handle_delete(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
        Path(id): Path<String>,
    ) -> Result<StatusCode, Problem> {
        sends
            .delete()
            .execute(&authed.actor, parse_id(&id)?)
            .await
            .map_err(|e| sends.problem(e))?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `PUT /kem/v1/sends/{id}/file`: the file's bytes, streamed. `Content-Length` is required and
    /// must be the size announced. Bytes that don't start like a `KMA1` file are refused with 415.
    pub(crate) async fn handle_upload(
        State(sends): State<Self>,
        SendAuthed(authed): SendAuthed,
        Path(id): Path<String>,
        headers: HeaderMap,
        body: HttpBody,
    ) -> Result<Json<SendDto>, Problem> {
        let id = parse_id(&id)?;
        let length = content_length(&headers)?;
        let mut source = RequestBody(body.into_data_stream());
        let send = sends
            .upload()
            .execute(&authed.actor, id, length, &mut source)
            .await
            .map_err(|e| sends.problem(e))?;
        Ok(Json(SendDto::of(&send)))
    }

    /// `POST /kem/v1/send-access/{accessId}`: opens a Send. Public.
    pub(crate) async fn handle_access(
        State(sends): State<Self>,
        Path(access_id): Path<String>,
        MaybeView(view): MaybeView,
        SendClientIp(ip): SendClientIp,
        body: Body,
    ) -> Result<Response, Problem> {
        let proof = proof_of(&body)?;
        sends.count_try(&access_id, &proof, ip).await?;
        sends.refuse_if_limited_elsewhere(view, &access_id).await?;
        let opened = sends
            .access()
            .execute(&access_id, proof.as_deref())
            .await
            .map_err(|e| sends.problem(e))?;
        if proof.is_some() {
            sends.clear_tries(&access_id);
        }
        let dto = AccessDto {
            id: access_id,
            kind: opened.kind.as_str().to_owned(),
            payload: b64(&opened.payload),
            file_size: opened.file_size,
            expires_at: opened.expires_at.map(OffsetDateTime::unix_timestamp),
            deletion_at: opened.deletion_at.unix_timestamp(),
            sender_email: opened.sender_email,
        };
        let mut response = Json(dto).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        Ok(response)
    }

    /// `POST /kem/v1/send-access/{accessId}/file`: a file Send's bytes, streamed. Public.
    pub(crate) async fn handle_download(
        State(sends): State<Self>,
        Path(access_id): Path<String>,
        MaybeView(view): MaybeView,
        SendClientIp(ip): SendClientIp,
        body: Body,
    ) -> Result<Response, Problem> {
        let proof = proof_of(&body)?;
        sends.count_try(&access_id, &proof, ip).await?;
        sends.refuse_if_limited_elsewhere(view, &access_id).await?;
        let downloaded = sends
            .access()
            .download(&access_id, proof.as_deref())
            .await
            .map_err(|e| sends.problem(e))?;
        if proof.is_some() {
            sends.clear_tries(&access_id);
        }
        let size = downloaded.read.size;
        let mut response = Response::new(HttpBody::from_stream(downloaded.read.body));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        Ok(response)
    }
}

/// The Send routes. Merge them into the `/kem/v1` router under a timeout of their own: an upload
/// takes as long as the connection does.
///
/// ```text
/// POST, GET  /kem/v1/sends                           make one, list mine
/// GET, PUT, DELETE /kem/v1/sends/{id}                read, change, delete one
/// PUT        /kem/v1/sends/{id}/file                 stream a file Send's bytes
/// POST       /kem/v1/send-access/{accessId}          open a Send (public)
/// POST       /kem/v1/send-access/{accessId}/file     stream a file Send's bytes (public)
/// ```
pub fn sends_router<S, P, K, R, B, Q>(
    api: Api<S, P, K>,
    sends: R,
    blobs: B,
    policies: Q,
    config: SendsConfig,
) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SendRepo + Clone + 'static,
    B: SendBlobs + Clone + 'static,
    Q: SendPolicies + Clone + 'static,
{
    type A<S, P, K, R, B, Q> = SendsApi<S, P, K, R, B, Q>;
    let state = SendsApi::new(api.clone(), sends, blobs, policies, config);
    Router::new()
        .route(
            "/kem/v1/sends",
            post(A::<S, P, K, R, B, Q>::handle_create).get(A::<S, P, K, R, B, Q>::handle_list),
        )
        .route(
            "/kem/v1/sends/{id}",
            axum::routing::get(A::<S, P, K, R, B, Q>::handle_get)
                .put(A::<S, P, K, R, B, Q>::handle_update)
                .delete(A::<S, P, K, R, B, Q>::handle_delete),
        )
        .route(
            "/kem/v1/sends/{id}/file",
            put(A::<S, P, K, R, B, Q>::handle_upload),
        )
        .route(
            "/kem/v1/send-access/{access_id}",
            post(A::<S, P, K, R, B, Q>::handle_access),
        )
        .route(
            "/kem/v1/send-access/{access_id}/file",
            post(A::<S, P, K, R, B, Q>::handle_download),
        )
        .layer(middleware::from_fn_with_state(api, nonce_header::<S, P, K>))
        .with_state(state)
}

// ---- OpenAPI ----

#[utoipa::path(
    post, path = "/kem/v1/sends", tag = "sends",
    security(("dpop" = [])),
    request_body = CreateSendRequest,
    responses(
        (status = 201, description = "Made; a file Send is closed until its bytes arrive", body = SendDto),
        (status = 409, description = "`key-version-stale`: the sealed key (create) or `keyVersion` (edit) is for another key version than the account's (`currentKeyVersion`)", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "A policy of one of the owner's spaces forbids it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 413, description = "The file is larger than the server allows (`maxSize`)", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_create() {}

#[utoipa::path(
    get, path = "/kem/v1/sends", tag = "sends",
    security(("dpop" = [])),
    responses((status = 200, description = "The account's Sends, newest first", body = Vec<SendDto>))
)]
#[allow(dead_code)]
fn doc_list() {}

#[utoipa::path(
    get, path = "/kem/v1/sends/{id}", tag = "sends",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The Send's id")),
    responses(
        (status = 200, description = "The Send", body = SendDto),
        (status = 404, description = "No such Send of this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_get() {}

#[utoipa::path(
    put, path = "/kem/v1/sends/{id}", tag = "sends",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The Send's id")),
    request_body = UpdateSendRequest,
    responses(
        (status = 200, description = "Changed", body = SendDto),
        (status = 409, description = "`key-version-stale`: the sealed key (create) or `keyVersion` (edit) is for another key version than the account's (`currentKeyVersion`)", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "A policy of one of the owner's spaces forbids it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such Send of this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_update() {}

#[utoipa::path(
    delete, path = "/kem/v1/sends/{id}", tag = "sends",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The Send's id")),
    responses(
        (status = 204, description = "Deleted, a file's bytes included"),
        (status = 404, description = "No such Send of this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_delete() {}

#[utoipa::path(
    put, path = "/kem/v1/sends/{id}/file", tag = "sends",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The Send's id"),
        ("Content-Length" = u64, Header, description = "Required; the size announced when the Send was made"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The KMA1 file"),
    responses(
        (status = 200, description = "Stored; the Send is open", body = SendDto),
        (status = 400, description = "The body isn't the size announced", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "Uploaded already", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 411, description = "No Content-Length", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 415, description = "Not a KMA1 file", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_upload() {}

#[utoipa::path(
    post, path = "/kem/v1/send-access/{access_id}", tag = "sends",
    params(("access_id" = String, Path, description = "The id in the link")),
    request_body(content = Option<AccessRequest>, description = "Optional: the password proof; no body opens a Send without a password"),
    responses(
        (status = 200, description = "Ciphertext and dates; the key is in the link's fragment", body = AccessDto),
        (status = 401, description = "`send-password-required` or `send-wrong-password`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such Send, or one that is closed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many password tries for this Send", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_access() {}

#[utoipa::path(
    post, path = "/kem/v1/send-access/{access_id}/file", tag = "sends",
    params(("access_id" = String, Path, description = "The id in the link")),
    request_body(content = Option<AccessRequest>, description = "Optional: the password proof; no body opens a Send without a password"),
    responses(
        (status = 200, description = "The file's bytes, which count as a view"),
        (status = 401, description = "`send-password-required` or `send-wrong-password`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such file Send, or one that is closed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many password tries for this Send", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_download() {}

/// The Send routes' part of the OpenAPI document; a server that serves them can `merge` it into
/// the API's own.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_create,
        doc_list,
        doc_get,
        doc_update,
        doc_delete,
        doc_upload,
        doc_access,
        doc_download
    ),
    components(schemas(
        NewFileDto,
        CreateSendRequest,
        UpdateSendRequest,
        SendFileDto,
        SendDto,
        AccessRequest,
        AccessDto
    ))
)]
pub struct SendsDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_is_read_and_refused_as_for_files() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("65680"));
        assert_eq!(content_length(&headers), Ok(65_680));
        assert_eq!(
            content_length(&HeaderMap::new())
                .expect_err("refused")
                .status,
            StatusCode::LENGTH_REQUIRED
        );
        let mut chunked = HeaderMap::new();
        chunked.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert_eq!(
            content_length(&chunked).expect_err("refused").status,
            StatusCode::LENGTH_REQUIRED
        );
    }

    #[test]
    fn an_empty_access_body_has_no_password() {
        assert_eq!(proof_of(&Body(Bytes::new())), Ok(None));
        assert_eq!(proof_of(&Body(Bytes::from_static(b" \n"))), Ok(None));
        assert_eq!(proof_of(&Body(Bytes::from_static(b"{}"))), Ok(None));
        assert_eq!(
            proof_of(&Body(Bytes::from_static(br#"{"password":"AQID"}"#))),
            Ok(Some(vec![1, 2, 3]))
        );
    }

    #[test]
    fn a_bad_proof_or_body_is_a_400() {
        let bad_bodies: [&[u8]; 3] = [br#"{"password":"not base64!"}"#, b"[]", br#"{"nope":1}"#];
        for bad in bad_bodies {
            let refused = proof_of(&Body(Bytes::copy_from_slice(bad))).expect_err("refused");
            assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn the_errors_have_the_statuses_the_routes_document() {
        let config = SendsConfig::default();
        let status = |e| problem(&config, e).status;
        assert_eq!(status(SendsError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(
            status(SendsError::PasswordRequired),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status(SendsError::WrongPassword), StatusCode::UNAUTHORIZED);
        assert_eq!(status(SendsError::Policy("no")), StatusCode::FORBIDDEN);
        assert_eq!(status(SendsError::TooLarge), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(status(SendsError::AlreadyUploaded), StatusCode::CONFLICT);
        assert_eq!(
            status(SendsError::NotKma1("x")),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(SendsError::Store("secret detail".to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // A wrong password and a missing one carry a challenge, and the 500 hides its cause.
        let required = problem(&config, SendsError::PasswordRequired);
        assert_eq!(required.headers.len(), 1);
        let hidden = problem(&config, SendsError::Blob("/var/data/ab/cd".to_owned()));
        assert!(!hidden.to_json().to_string().contains("/var/data"));
    }

    #[test]
    fn times_and_ids_are_checked() {
        assert!(time_from(1_800_000_000, "t").is_ok());
        assert_eq!(
            time_from(i64::MAX, "t").expect_err("refused").status,
            StatusCode::BAD_REQUEST
        );
        assert!(parse_id("7f3c4b1e-0000-4000-8000-000000000000").is_ok());
        assert_eq!(
            parse_id("nope").expect_err("refused").status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn the_document_names_every_send_route() {
        let json = serde_json::to_value(SendsDoc::openapi()).expect("serialises");
        for (path, method) in [
            ("/kem/v1/sends", "post"),
            ("/kem/v1/sends", "get"),
            ("/kem/v1/sends/{id}", "get"),
            ("/kem/v1/sends/{id}", "put"),
            ("/kem/v1/sends/{id}", "delete"),
            ("/kem/v1/sends/{id}/file", "put"),
            ("/kem/v1/send-access/{access_id}", "post"),
            ("/kem/v1/send-access/{access_id}/file", "post"),
        ] {
            assert!(
                json["paths"][path][method].is_object(),
                "{method} {path} is documented"
            );
        }
        assert!(json["components"]["schemas"]["SendDto"].is_object());
    }
}
