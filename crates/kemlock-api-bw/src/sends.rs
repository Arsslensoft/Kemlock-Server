// Ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/api/core/sends.rs (handler and helper structure, update order, SEND_INACCESSIBLE_MSG,
//   SIZE_525_MB).
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! Sends, as Vaultwarden 1.37.5's `sends.rs` answers them.
//!
//! The wire layer is all here: the routes, what a request may say, the shapes of the answers, the
//! access checks and counts. What it stores goes through [`SendStore`], a small port of this
//! crate's own over a Bitwarden-shaped [`SendRecord`]; [`MemorySends`] keeps them in memory.
//!
//! Vaultwarden 1.37.5 hands a recipient a short-lived access token: `POST /identity/connect/token`
//! with `grant_type=send_access` (see [`send_access_token`]), then `POST /api/sends/access` and
//! `POST /api/sends/access/file/{file_id}` with that token as the bearer. The file itself is
//! downloaded from `GET /api/sends/{id}/{file_id}?t=…`, a link good for two minutes.

use crate::app::{App, Authed, BwStore};
use crate::blob::BoxFuture;
use crate::cipher::{display_size, lcase_keys};
use crate::dates::{format_date, parse_date};
use crate::env::{random_bytes, random_hex, random_uuid};
use crate::error::{BwError, BwResult};
use crate::fed_view::MaybeView;
use crate::orgs::policy;
use crate::password::{hash_password, verify_password};
use crate::routes::{EmptyResult, JsonResult, header_text, ok, parse};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use kemlock_app::b64url;
use kemlock_app::bw_events::Change;
use kemlock_app::ports::UserRepo;
use kemlock_app::quota::check;
use kemlock_domain::{DeviceKind, UserId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";
/// The most a file Send may hold: Bitwarden clients' 525 MB and 5% more, as Vaultwarden has it.
const SIZE_525_MB: i64 = 550_502_400;
/// A file upload is up to that, plus the multipart framing.
const UPLOAD_BODY_LIMIT: usize = 551 * 1024 * 1024;
/// Rounds of the password hash of a Send, as Vaultwarden's.
pub const SEND_PASSWORD_ITERATIONS: u32 = 100_000;
const TYPE_TEXT: i32 = 0;
const TYPE_FILE: i32 = 1;

// --- the port -------------------------------------------------------------------------------

/// A failed call to the Send store; the message is for logs, never for clients.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("send store failure: {0}")]
pub struct SendError(pub String);

impl From<SendError> for BwError {
    fn from(e: SendError) -> Self {
        BwError::Server(e.to_string())
    }
}

/// The password of a Send: PBKDF2-HMAC-SHA-256 of the client's password hash text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPassword {
    pub hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

/// One Send, as Vaultwarden's `sends` row holds it. Names, notes, keys and the text or file data
/// are the client's encrypted strings; the server never opens them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecord {
    pub id: Uuid,
    /// The account that owns it. (Vaultwarden has organization Sends in the schema and never makes
    /// one.)
    pub user: Option<UserId>,
    pub organization: Option<Uuid>,
    /// 0 text, 1 file.
    pub kind: i32,
    pub name: String,
    pub notes: Option<String>,
    /// The Send's key, encrypted for its owner.
    pub key: String,
    /// The text or file object as a JSON string. A file's has `id`, `size` and `sizeName` added.
    pub data: String,
    pub password: Option<SendPassword>,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub created_at: OffsetDateTime,
    pub revised_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub deleted_at: OffsetDateTime,
    pub disabled: bool,
    pub hide_email: Option<bool>,
}

impl SendRecord {
    /// Within its validity window: not disabled, not past its expiration, not past its deletion
    /// date. The access count and the password are checked apart.
    pub fn is_accessible(&self, now: OffsetDateTime) -> bool {
        if self.disabled {
            return false;
        }
        if self.expires_at.is_some_and(|at| now >= at) {
            return false;
        }
        now < self.deleted_at
    }

    /// The id a recipient's link carries: the UUID's 16 bytes as unpadded base64url.
    pub fn access_id(&self) -> String {
        b64url::encode(self.id.as_bytes())
    }

    /// The file id of a file Send, from its data.
    fn file_id(&self) -> Option<String> {
        serde_json::from_str::<Value>(&self.data)
            .ok()
            .and_then(|d| d.get("id").and_then(Value::as_str).map(str::to_owned))
    }
}

/// Where Sends are kept.
///
/// `kemlock-server` passes `bw_sends::SqlSends` (over the SQL Sends table) as `AppParts::sends`, so
/// Sends survive a restart; [`MemorySends`] is the default and what the tests use. Every method is
/// cancel-safe; futures are boxed so the trait can be held as `dyn SendStore`.
pub trait SendStore: Send + Sync + 'static {
    /// The Send with this id.
    fn get(&self, id: Uuid) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>>;

    /// The account's Sends, oldest first.
    fn list_by_user(&self, user: UserId) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>>;

    /// Inserts the Send, or replaces the one with its id.
    fn put(&self, send: SendRecord) -> BoxFuture<'_, Result<(), SendError>>;

    /// Removes the Send; whether there was one.
    fn delete(&self, id: Uuid) -> BoxFuture<'_, Result<bool, SendError>>;

    /// Counts one access, atomically: adds one to `access_count` and moves the revision date to
    /// `at` only while the count is below `max_access_count` (or there is none). Returns the Send
    /// as it is now, or `None` when the limit was already reached or there is no such Send, so two
    /// recipients racing for the last access can't both have it.
    fn register_access(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>>;

    /// The Sends whose deletion date is before `before`, for the purge job.
    fn past_deletion(
        &self,
        before: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>>;
}

/// Sends in memory: the default, and what the tests use.
#[derive(Debug, Default)]
pub struct MemorySends {
    sends: Mutex<HashMap<Uuid, SendRecord>>,
}

impl MemorySends {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, SendRecord>>, SendError> {
        self.sends
            .lock()
            .map_err(|_| SendError("poisoned".to_owned()))
    }
}

impl SendStore for MemorySends {
    fn get(&self, id: Uuid) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>> {
        Box::pin(async move { Ok(self.lock()?.get(&id).cloned()) })
    }

    fn list_by_user(&self, user: UserId) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>> {
        Box::pin(async move {
            let mut out: Vec<SendRecord> = self
                .lock()?
                .values()
                .filter(|s| s.user == Some(user))
                .cloned()
                .collect();
            out.sort_by_key(|s| (s.created_at, s.id));
            Ok(out)
        })
    }

    fn put(&self, send: SendRecord) -> BoxFuture<'_, Result<(), SendError>> {
        Box::pin(async move {
            self.lock()?.insert(send.id, send);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> BoxFuture<'_, Result<bool, SendError>> {
        Box::pin(async move { Ok(self.lock()?.remove(&id).is_some()) })
    }

    fn register_access(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>> {
        Box::pin(async move {
            let mut sends = self.lock()?;
            let Some(send) = sends.get_mut(&id) else {
                return Ok(None);
            };
            if send
                .max_access_count
                .is_some_and(|max| send.access_count >= max)
            {
                return Ok(None);
            }
            send.access_count += 1;
            send.revised_at = at;
            Ok(Some(send.clone()))
        })
    }

    fn past_deletion(
        &self,
        before: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>> {
        Box::pin(async move {
            Ok(self
                .lock()?
                .values()
                .filter(|s| s.deleted_at < before)
                .cloned()
                .collect())
        })
    }
}

/// The blob key of a file Send's bytes.
fn blob_key(send: Uuid, file: &str) -> String {
    format!("sends/{send}/{file}")
}

/// Removes the Sends past their deletion date, and the files of the file Sends. Meant for a
/// background job (Vaultwarden's `purge_sends`); returns how many went.
pub async fn purge_sends(
    store: &dyn SendStore,
    blobs: &dyn crate::blob::BlobStore,
    now: OffsetDateTime,
) -> Result<u64, SendError> {
    let mut purged = 0;
    for send in store.past_deletion(now).await? {
        if send.kind == TYPE_FILE
            && let Some(file) = send.file_id()
            && let Err(e) = blobs.delete(&blob_key(send.id, &file)).await
        {
            tracing::warn!(error = %e, "couldn't remove a Send file");
        }
        if store.delete(send.id).await? {
            purged += 1;
        }
    }
    Ok(purged)
}

// --- shapes ---------------------------------------------------------------------------------

/// The text or file object as clients read it: keys lower-cased at the first letter, and a file's
/// size as text, which mobile clients expect.
fn data_json(send: &SendRecord) -> Value {
    let mut data = serde_json::from_str::<Value>(&send.data)
        .map(lcase_keys)
        .unwrap_or_default();
    if let Some(size) = data.get("size").and_then(Value::as_i64) {
        data["size"] = Value::String(size.to_string());
    }
    data
}

fn date_or_null(at: Option<OffsetDateTime>) -> Value {
    at.map_or(Value::Null, |t| Value::String(format_date(t)))
}

/// `Send::to_json`.
fn send_json(send: &SendRecord) -> Value {
    let data = data_json(send);
    json!({
        "id": send.id.to_string(),
        "accessId": send.access_id(),
        "type": send.kind,

        "name": send.name,
        "notes": send.notes,
        "text": if send.kind == TYPE_TEXT { data.clone() } else { Value::Null },
        "file": if send.kind == TYPE_FILE { data } else { Value::Null },

        "key": send.key,
        "maxAccessCount": send.max_access_count,
        "accessCount": send.access_count,
        "password": send.password.as_ref().map(|p| b64url::encode(&p.hash)),
        // 0 would be email verification, which isn't supported.
        "authType": if send.password.is_some() { 1 } else { 2 },
        "disabled": send.disabled,
        "hideEmail": send.hide_email.unwrap_or(false),

        "revisionDate": format_date(send.revised_at),
        "expirationDate": date_or_null(send.expires_at),
        "deletionDate": format_date(send.deleted_at),
        "object": "send",
    })
}

/// `Send::to_json_access`: what a recipient sees.
async fn access_json<S: BwStore>(app: &App<S>, send: &SendRecord) -> BwResult<Value> {
    let data = data_json(send);
    let creator = if send.hide_email == Some(true) {
        None
    } else if let Some(user) = send.user {
        UserRepo::by_id(&app.store, user)
            .await?
            .map(|u| u.email.as_str().to_owned())
    } else {
        None
    };
    Ok(json!({
        "id": send.access_id(),
        "type": send.kind,

        "name": send.name,
        "text": if send.kind == TYPE_TEXT { data.clone() } else { Value::Null },
        "file": if send.kind == TYPE_FILE { data } else { Value::Null },

        "expirationDate": date_or_null(send.expires_at),
        "creatorIdentifier": creator,
        "object": "send-access",
    }))
}

fn list_json(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })
}

/// The `sends` list of `/api/sync`.
pub(crate) async fn sync_json<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Value> {
    let sends = app.sends.list_by_user(user).await?;
    Ok(Value::Array(sends.iter().map(send_json).collect()))
}

// --- requests -------------------------------------------------------------------------------

/// A number or a string, as Vaultwarden's `NumberOrString`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NumberOrString {
    Number(i64),
    Text(String),
}

impl NumberOrString {
    fn to_i32(&self) -> BwResult<i32> {
        match self {
            NumberOrString::Number(n) => {
                i32::try_from(*n).map_err(|_| BwError::msg("Number does not fit in i32"))
            }
            NumberOrString::Text(s) => s
                .parse()
                .map_err(|_| BwError::msg("Can't convert to number")),
        }
    }

    fn to_i64(&self) -> BwResult<i64> {
        match self {
            NumberOrString::Number(n) => Ok(*n),
            NumberOrString::Text(s) => s
                .parse()
                .map_err(|_| BwError::msg("Can't convert to number")),
        }
    }
}

/// `SendData`. Dates arrive as RFC 3339 text and are read in the handler.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendData {
    r#type: i32,
    key: String,
    password: Option<String>,
    max_access_count: Option<NumberOrString>,
    expiration_date: Option<String>,
    deletion_date: String,
    disabled: bool,
    hide_email: Option<bool>,
    emails: Option<String>,

    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
    file_length: Option<NumberOrString>,
}

fn unprocessable() -> BwError {
    BwError::status(StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable Entity")
}

/// A date the client sent; one that isn't RFC 3339 is a 422, as a body of the wrong shape is.
fn date_of(text: &str) -> BwResult<OffsetDateTime> {
    parse_date(text).ok_or_else(unprocessable)
}

/// The Send's password, hashed fresh with a random salt; `None` takes it away.
fn hashed<S: BwStore>(app: &App<S>, password: Option<&str>) -> Option<SendPassword> {
    password.map(|password| {
        let salt = random_bytes::<64>(app.env.as_ref()).to_vec();
        SendPassword {
            hash: hash_password(password.as_bytes(), &salt, SEND_PASSWORD_ITERATIONS),
            salt,
            iterations: SEND_PASSWORD_ITERATIONS,
        }
    })
}

fn password_matches(send: &SendRecord, password: &str) -> bool {
    send.password
        .as_ref()
        .is_some_and(|p| verify_password(password.as_bytes(), &p.salt, &p.hash, p.iterations))
}

const TOO_FAR: &str = "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.";

/// Enforces the Disable Send policy: whoever it applies to may delete Sends and nothing else.
async fn enforce_disable_send_policy<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<()> {
    if policy::disable_send_applies(app, user).await? {
        return Err(BwError::msg(
            "Due to an Enterprise Policy, you are only able to delete an existing Send.",
        ));
    }
    Ok(())
}

/// Enforces the Send Options policy's ban on hiding the sender's email.
async fn enforce_disable_hide_email_policy<S: BwStore>(
    app: &App<S>,
    user: UserId,
    data: &SendData,
) -> BwResult<()> {
    if data.hide_email.unwrap_or(false) && policy::hide_email_disabled(app, user).await? {
        return Err(BwError::msg(
            "Due to an Enterprise Policy, you are not allowed to hide your email address \
              from recipients when creating or editing a Send.",
        ));
    }
    Ok(())
}

/// The text or file object of a request, without the `response` key web clients add.
fn type_data(data: &mut SendData) -> BwResult<String> {
    let value = match data.r#type {
        TYPE_TEXT => data.text.take(),
        TYPE_FILE => data.file.take(),
        _ => return Err(BwError::msg("Invalid Send type")),
    };
    let Some(mut value) = value else {
        return Err(BwError::msg("Send data not provided"));
    };
    if let Some(object) = value.as_object_mut() {
        object.remove("response");
    }
    serde_json::to_string(&value).map_err(|e| BwError::Server(e.to_string()))
}

/// `create_send`.
fn create_send<S: BwStore>(app: &App<S>, mut data: SendData, user: UserId) -> BwResult<SendRecord> {
    let stored = type_data(&mut data)?;
    let now = app.now();
    let deleted_at = date_of(&data.deletion_date)?;
    if deleted_at > now + Duration::days(31) {
        return Err(BwError::msg(TOO_FAR));
    }
    if data.emails.is_some() {
        return Err(BwError::msg(
            "Sends with email verification is not supported",
        ));
    }
    let max_access_count = match &data.max_access_count {
        Some(m) => Some(m.to_i32()?),
        None => None,
    };
    let expires_at = match &data.expiration_date {
        Some(text) => Some(date_of(text)?),
        None => None,
    };
    Ok(SendRecord {
        id: random_uuid(app.env.as_ref()),
        user: Some(user),
        organization: None,
        kind: data.r#type,
        name: data.name,
        notes: data.notes,
        key: data.key,
        data: stored,
        password: hashed(app, data.password.as_deref()),
        max_access_count,
        access_count: 0,
        created_at: now,
        revised_at: now,
        expires_at,
        deleted_at,
        disabled: data.disabled,
        hide_email: data.hide_email,
    })
}

/// Stores a Send as its next revision and moves the owner's revision date.
async fn save<S: BwStore>(app: &App<S>, mut send: SendRecord) -> BwResult<SendRecord> {
    send.revised_at = app.now();
    app.sends.put(send.clone()).await?;
    if let Some(user) = send.user {
        app.touch(user).await?;
    }
    Ok(send)
}

fn parse_send_id(text: &str) -> BwResult<Uuid> {
    Uuid::parse_str(text).map_err(|_| BwError::NotFound)
}

/// A Send of the account, by id.
async fn owned<S: BwStore>(
    app: &App<S>,
    user: UserId,
    id: &str,
    message: &str,
) -> BwResult<SendRecord> {
    let id = parse_send_id(id)?;
    match app.sends.get(id).await? {
        Some(send) if send.user == Some(user) => Ok(send),
        _ => Err(BwError::msg(message)),
    }
}

// --- the owner's routes ---------------------------------------------------------------------

async fn get_sends<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    let sends = app.sends.list_by_user(authed.user.id).await?;
    ok(list_json(sends.iter().map(send_json).collect()))
}

async fn get_send<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(send_json(
        &owned(&app, authed.user.id, &id, "Send not found").await?,
    ))
}

async fn post_send<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let user = authed.user.id;
    enforce_disable_send_policy(&app, user).await?;
    let data: SendData = parse(&body)?;
    enforce_disable_hide_email_policy(&app, user, &data).await?;
    if data.r#type == TYPE_FILE {
        return Err(BwError::msg("File sends should use /api/sends/file/v2"));
    }
    let send = save(&app, create_send(&app, data, user)?).await?;
    app.send_changed(
        Some(&authed),
        user,
        Change::Created,
        send.id,
        send.revised_at,
    );
    ok(send_json(&send))
}

/// The bytes the account's file Sends take, as their data says, for the quota on them.
async fn file_send_bytes<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<u64> {
    let mut total = 0u64;
    for send in app.sends.list_by_user(user).await? {
        if send.kind != TYPE_FILE {
            continue;
        }
        let size = serde_json::from_str::<Value>(&send.data)
            .ok()
            .and_then(|data| data.get("size").and_then(Value::as_u64))
            .unwrap_or(0);
        total = total.saturating_add(size);
    }
    Ok(total)
}

/// `POST /api/sends/file/v2`: makes the file Send and says where its bytes go.
async fn post_send_file_v2<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let user = authed.user.id;
    enforce_disable_send_policy(&app, user).await?;
    let data: SendData = parse(&body)?;
    if data.r#type != TYPE_FILE {
        return Err(BwError::msg("Send content is not a file"));
    }
    enforce_disable_hide_email_policy(&app, user, &data).await?;

    let Some(length) = &data.file_length else {
        return Err(BwError::msg("Invalid send length"));
    };
    let file_length = length.to_i64()?;
    if file_length < 0 {
        return Err(BwError::msg("Send size can't be negative"));
    }
    // The sum and the Send it admits are one step: no other announce reads between them.
    let _gate = app.quota_gate.lock().await;
    // `USER_SEND_LIMIT`: what the account's file Sends hold already counts against it.
    if let Some(limit) = app.settings.live.as_ref().and_then(|l| l.send_limit()) {
        let used = file_send_bytes(&app, user).await?;
        let size = u64::try_from(file_length).unwrap_or(0);
        check(Some(limit), used, size).map_err(|refusal| BwError::msg(refusal.send_message()))?;
    }
    if file_length > SIZE_525_MB {
        return Err(BwError::msg("Send storage limit exceeded with this file"));
    }

    let mut send = create_send(&app, data, user)?;
    let file_id = random_hex::<32>(app.env.as_ref());
    let mut file: Value =
        serde_json::from_str(&send.data).map_err(|e| BwError::Server(e.to_string()))?;
    let Some(object) = file.as_object_mut() else {
        return Err(BwError::msg("Invalid Send file data"));
    };
    object.insert("id".to_owned(), Value::String(file_id.clone()));
    object.insert("size".to_owned(), json!(file_length));
    object.insert(
        "sizeName".to_owned(),
        Value::String(display_size(file_length)),
    );
    send.data = serde_json::to_string(&file).map_err(|e| BwError::Server(e.to_string()))?;
    let send = save(&app, send).await?;

    ok(json!({
        "fileUploadType": 0,
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{file_id}", send.id),
        "sendResponse": send_json(&send),
    }))
}

/// What a file Send's data says about its file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendFileData {
    id: String,
    size: u64,
    file_name: String,
}

/// `POST /api/sends/{id}/file/{file_id}`: the file's bytes, as the `data` part of a form.
async fn post_send_file_v2_data<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((send_id, file_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> EmptyResult {
    let mut part = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| BwError::msg(e.to_string()))?
    {
        if field.name() == Some("data") {
            let name = field.file_name().map(str::to_owned);
            let bytes = field
                .bytes()
                .await
                .map_err(|e| BwError::msg(e.to_string()))?;
            part = Some((name, bytes));
        }
    }
    let Some((uploaded_name, bytes)) = part else {
        return Err(unprocessable());
    };

    let user = authed.user.id;
    enforce_disable_send_policy(&app, user).await?;
    let send = owned(
        &app,
        user,
        &send_id,
        "Send not found. Unable to save the file.",
    )
    .await?;
    if send.kind != TYPE_FILE {
        return Err(BwError::msg("Send is not a file type send."));
    }
    let Ok(file) = serde_json::from_str::<SendFileData>(&send.data) else {
        return Err(BwError::msg("Unable to decode send data as json."));
    };

    match uploaded_name {
        Some(name) => {
            // The command-line client names the part more loosely.
            let cli = authed.device.kind == DeviceKind::KemlockCli;
            if name != file.file_name && !(cli && file.file_name.ends_with(&name)) {
                return Err(BwError::msg("Send file name does not match."));
            }
        }
        None => {
            return Err(BwError::msg(
                "Send file name does not match or is not provided.",
            ));
        }
    }
    if file_id != file.id {
        return Err(BwError::msg("Send file does not match send data."));
    }
    if u64::try_from(bytes.len()).ok() != Some(file.size) {
        return Err(BwError::msg("Send file size does not match."));
    }

    app.blobs
        .put(&blob_key(send.id, &file.id), bytes.to_vec())
        .await
        .map_err(|e| BwError::Server(e.to_string()))?;
    app.touch(user).await?;
    app.send_changed(Some(&authed), user, Change::Created, send.id, app.now());
    Ok(StatusCode::OK)
}

async fn put_send<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let user = authed.user.id;
    enforce_disable_send_policy(&app, user).await?;
    let mut data: SendData = parse(&body)?;
    enforce_disable_hide_email_policy(&app, user, &data).await?;
    let mut send = owned(&app, user, &id, "Send not found").await?;
    if data.emails.is_some() {
        return Err(BwError::msg(
            "Sends with email verification is not supported",
        ));
    }

    // `update_send_from_data`.
    if send.kind != data.r#type {
        return Err(BwError::msg("Sends can't change type"));
    }
    let deleted_at = date_of(&data.deletion_date)?;
    if deleted_at > app.now() + Duration::days(31) {
        return Err(BwError::msg(TOO_FAR));
    }
    // A file Send's file can't change, so its request carries nulls there.
    if data.r#type == TYPE_TEXT {
        send.data = type_data(&mut data)?;
    }
    send.name = data.name;
    send.key = data.key;
    send.deleted_at = deleted_at;
    send.notes = data.notes;
    send.max_access_count = match &data.max_access_count {
        Some(m) => Some(m.to_i32()?),
        None => None,
    };
    send.expires_at = match &data.expiration_date {
        Some(text) => Some(date_of(text)?),
        None => None,
    };
    send.hide_email = data.hide_email;
    send.disabled = data.disabled;
    // Only a password that is there changes it.
    if let Some(password) = &data.password {
        send.password = hashed(&app, Some(password));
    }
    let send = save(&app, send).await?;
    app.send_changed(
        Some(&authed),
        user,
        Change::Updated,
        send.id,
        send.revised_at,
    );
    ok(send_json(&send))
}

async fn delete_send<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    let user = authed.user.id;
    let send = owned(&app, user, &id, "Send not found").await?;
    if send.kind == TYPE_FILE
        && let Some(file) = send.file_id()
        && let Err(e) = app.blobs.delete(&blob_key(send.id, &file)).await
    {
        tracing::warn!(error = %e, "couldn't remove a Send file");
    }
    app.sends.delete(send.id).await?;
    app.touch(user).await?;
    app.send_changed(Some(&authed), user, Change::Deleted, send.id, app.now());
    Ok(StatusCode::OK)
}

async fn put_remove_password<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let user = authed.user.id;
    enforce_disable_send_policy(&app, user).await?;
    let mut send = owned(&app, user, &id, "Send not found").await?;
    send.password = None;
    let send = save(&app, send).await?;
    app.send_changed(
        Some(&authed),
        user,
        Change::Updated,
        send.id,
        send.revised_at,
    );
    ok(send_json(&send))
}

// --- the recipient's routes -----------------------------------------------------------------

/// The claims of a Send token, as Vaultwarden's `BasicJwtClaims`.
#[derive(Debug, Serialize, Deserialize)]
struct SendClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    sub: String,
}

/// A token good for two minutes with `sub` as its subject.
fn send_token<S: BwStore>(app: &App<S>, sub: String) -> BwResult<(String, i64)> {
    let now = app.now_secs();
    let claims = SendClaims {
        nbf: now,
        exp: now + 120,
        iss: app.settings.issuer("send"),
        sub,
    };
    let token = app
        .keys
        .encode(&claims)
        .map_err(|e| BwError::Server(e.to_string()))?;
    Ok((token, 120))
}

/// `SendHeaders`: the Send a bearer token names, or a 401.
fn token_subject<S: BwStore>(app: &App<S>, headers: &HeaderMap) -> BwResult<String> {
    let value = header_text(headers, "authorization").ok_or(BwError::Unauthorized)?;
    let token = value.rsplit("Bearer ").next().unwrap_or(value);
    let claims: SendClaims = app
        .keys
        .decode(token, &app.settings.issuer("send"), app.now_secs())
        .map_err(|_| BwError::Unauthorized)?;
    Ok(claims.sub)
}

fn inaccessible() -> BwError {
    BwError::status(StatusCode::NOT_FOUND, SEND_INACCESSIBLE_MSG)
}

/// The Send a recipient's token names, if it can still be reached.
async fn reachable<S: BwStore>(app: &App<S>, headers: &HeaderMap) -> BwResult<SendRecord> {
    let sub = token_subject(app, headers)?;
    let id = Uuid::parse_str(&sub).map_err(|_| inaccessible())?;
    let Some(send) = app.sends.get(id).await? else {
        return Err(inaccessible());
    };
    if !send.is_accessible(app.now()) {
        return Err(inaccessible());
    }
    Ok(send)
}

/// A Send with a view limit is opened at its home only: a replica counting views of its own would
/// allow the whole limit again. Answered as an unavailable Send, as Vaultwarden does, so the app
/// shows its usual "does not exist or is no longer available" and the recipient tries the home.
async fn refuse_if_limited_elsewhere(
    view: Option<kemlock_app::federation_view::SharedView>,
    send: &SendRecord,
) -> BwResult<()> {
    let (Some(view), true, Some(owner)) = (view, send.max_access_count.is_some(), send.user)
    else {
        return Ok(());
    };
    match view.limited_send_home(owner).await {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(inaccessible()),
        Err(e) => Err(BwError::from(SendError(e.to_string()))),
    }
}

async fn post_access<S: BwStore>(
    State(app): State<App<S>>,
    MaybeView(view): MaybeView,
    headers: HeaderMap,
) -> JsonResult {
    let mut send = reachable(&app, &headers).await?;
    refuse_if_limited_elsewhere(view, &send).await?;
    // A file's access is counted when its link is asked for.
    if send.kind == TYPE_TEXT {
        send = app
            .sends
            .register_access(send.id, app.now())
            .await?
            .ok_or_else(inaccessible)?;
        touch_owner(&app, &send).await;
    }
    ok(access_json(&app, &send).await?)
}

/// A recipient's access moves the owner's revision date and tells their clients, as Vaultwarden's
/// does (the message names no device: the recipient is not one of the owner's).
async fn touch_owner<S: BwStore>(app: &App<S>, send: &SendRecord) {
    let Some(user) = send.user else {
        return;
    };
    match app.touch(user).await {
        Ok(()) => app.send_changed(None, user, Change::Updated, send.id, send.revised_at),
        Err(e) => tracing::warn!(error = ?e, "couldn't move a revision date"),
    }
}

async fn post_access_file<S: BwStore>(
    State(app): State<App<S>>,
    Path(file_id): Path<String>,
    MaybeView(view): MaybeView,
    headers: HeaderMap,
) -> JsonResult {
    let send = reachable(&app, &headers).await?;
    refuse_if_limited_elsewhere(view, &send).await?;
    if send.kind != TYPE_FILE {
        return Err(BwError::msg("Send is not a file type send."));
    }
    if send.file_id().as_deref() != Some(file_id.as_str()) {
        return Err(inaccessible());
    }
    let send = app
        .sends
        .register_access(send.id, app.now())
        .await?
        .ok_or_else(inaccessible)?;
    touch_owner(&app, &send).await;
    let (token, _) = send_token(&app, format!("{}/{file_id}", send.id))?;
    ok(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": format!("{}/api/sends/{}/{file_id}?t={token}", app.host(), send.id),
    }))
}

/// `GET /api/sends/{id}/{file_id}?t=…`: the file, for a link this server made.
async fn download_send<S: BwStore>(
    State(app): State<App<S>>,
    Path((send_id, file_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(token) = query.get("t") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let claims: Result<SendClaims, _> =
        app.keys
            .decode(token, &app.settings.issuer("send"), app.now_secs());
    let Ok(claims) = claims else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if claims.sub != format!("{send_id}/{file_id}") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(id) = Uuid::parse_str(&send_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match app.blobs.get(&blob_key(id, &file_id)).await {
        Ok(Some(bytes)) => {
            ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The `send_access` grant of `POST /identity/connect/token`: a short-lived bearer token for a
/// Send, given its access id (`send_id`) and, when it has a password, `password_hash_b64`. The
/// answers and their statuses are `SendTokens::generate_tokens`'s.
///
/// The token route lives in `routes.rs` and `identity.rs`; they call this for `grant_type`
/// `send_access`.
pub(crate) async fn send_access_token<S: BwStore>(
    app: &App<S>,
    send_id: &str,
    password_hash_b64: Option<&str>,
) -> Response {
    let invalid = |kind: &str| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "kind": "expected_server",
                "error": "invalid_grant",
                "send_access_error_type": kind,
            })),
        )
            .into_response()
    };
    let Some(id) = b64url::decode(send_id).and_then(|b| Uuid::from_slice(&b).ok()) else {
        return invalid("send_id_invalid");
    };
    let send = match app.sends.get(id).await {
        Ok(Some(send)) => send,
        Ok(None) => return invalid("send_id_invalid"),
        Err(e) => return BwError::from(e).into_response(),
    };
    if send
        .max_access_count
        .is_some_and(|max| send.access_count >= max)
    {
        return invalid("send_id_invalid");
    }
    if !send.is_accessible(app.now()) {
        return invalid("send_id_invalid");
    }
    if send.password.is_some() {
        match password_hash_b64 {
            Some(p) => {
                // The design's "Password-protected Send access: 10 a minute, per Send": every
                // password tried counts, whoever sends it, so the password can't be guessed
                // at the speed the server answers.
                if let Err(wait) = app.send_limit.attempt(send.id, app.now_secs()) {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, wait.to_string())],
                        Json(json!({
                            "kind": "expected_server",
                            "error": "invalid_request",
                            "error_description": "Too many attempts at this Send. Try again later.",
                        })),
                    )
                        .into_response();
                }
                if !password_matches(&send, p) {
                    return invalid("password_hash_b64_invalid");
                }
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "kind": "expected_server",
                        "error": "invalid_request",
                        "send_access_error_type": "password_hash_b64_required",
                    })),
                )
                    .into_response();
            }
        }
    }
    match send_token(app, send.id.to_string()) {
        Ok((token, expires_in)) => Json(json!({
            "access_token": token,
            "expires_in": expires_in,
            "token_type": "Bearer",
            "scope": "api.send.access",
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/api/sends", get(get_sends::<S>).post(post_send::<S>))
        .route("/api/sends/file/v2", post(post_send_file_v2::<S>))
        .route("/api/sends/access", post(post_access::<S>))
        .route(
            "/api/sends/access/file/{file_id}",
            post(post_access_file::<S>),
        )
        .route(
            "/api/sends/{id}",
            get(get_send::<S>)
                .put(put_send::<S>)
                .delete(delete_send::<S>),
        )
        .route(
            "/api/sends/{id}/remove-password",
            put(put_remove_password::<S>),
        )
        .route(
            "/api/sends/{id}/file/{file_id}",
            post(post_send_file_v2_data::<S>).layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route("/api/sends/{id}/{file_id}", get(download_send::<S>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn send(kind: i32, data: &str) -> SendRecord {
        SendRecord {
            id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            user: Some(UserId::random()),
            organization: None,
            kind,
            name: "2.name".to_owned(),
            notes: None,
            key: "2.key".to_owned(),
            data: data.to_owned(),
            password: None,
            max_access_count: Some(2),
            access_count: 0,
            created_at: datetime!(2026-11-21 12:00:00 UTC),
            revised_at: datetime!(2026-11-21 12:00:00 UTC),
            expires_at: None,
            deleted_at: datetime!(2026-11-28 12:00:00 UTC),
            disabled: false,
            hide_email: None,
        }
    }

    #[test]
    fn a_send_has_vaultwardens_json_keys() {
        let mut record = send(TYPE_TEXT, r#"{"Text":"2.t","Hidden":false}"#);
        let json = send_json(&record);
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "accessCount",
                "accessId",
                "authType",
                "deletionDate",
                "disabled",
                "expirationDate",
                "file",
                "hideEmail",
                "id",
                "key",
                "maxAccessCount",
                "name",
                "notes",
                "object",
                "password",
                "revisionDate",
                "text",
                "type"
            ]
        );
        assert_eq!(json["object"], "send");
        assert_eq!(json["authType"], 2);
        assert_eq!(json["text"]["text"], "2.t");
        assert_eq!(json["text"]["hidden"], false);
        assert!(json["file"].is_null());
        assert_eq!(json["revisionDate"], "2026-11-21T12:00:00.000000Z");
        assert_eq!(
            json["accessId"],
            b64url::encode(record.id.as_bytes()).as_str()
        );

        record.password = Some(SendPassword {
            hash: vec![1, 2, 3],
            salt: vec![4],
            iterations: 1,
        });
        let json = send_json(&record);
        assert_eq!(json["authType"], 1);
        assert_eq!(json["password"], b64url::encode(&[1, 2, 3]).as_str());
    }

    #[test]
    fn a_file_size_is_text_for_mobile_clients() {
        let record = send(
            TYPE_FILE,
            r#"{"fileName":"2.f","id":"abc","size":17,"sizeName":"17.00 bytes"}"#,
        );
        let json = send_json(&record);
        assert_eq!(json["file"]["size"], "17");
        assert_eq!(json["file"]["id"], "abc");
        assert!(json["text"].is_null());
    }

    #[test]
    fn a_send_is_reachable_only_inside_its_window() {
        let mut record = send(TYPE_TEXT, "{}");
        let inside = datetime!(2026-11-22 12:00:00 UTC);
        assert!(record.is_accessible(inside));
        assert!(!record.is_accessible(datetime!(2026-11-28 12:00:00 UTC)));
        record.expires_at = Some(datetime!(2026-11-22 00:00:00 UTC));
        assert!(!record.is_accessible(inside));
        record.expires_at = None;
        record.disabled = true;
        assert!(!record.is_accessible(inside));
    }

    #[tokio::test]
    async fn the_last_access_goes_to_one_recipient() {
        let store = MemorySends::default();
        let record = send(TYPE_TEXT, "{}");
        let id = record.id;
        store.put(record).await.expect("put");
        let at = datetime!(2026-11-22 12:00:00 UTC);
        assert_eq!(
            store
                .register_access(id, at)
                .await
                .expect("count")
                .map(|s| s.access_count),
            Some(1)
        );
        assert!(
            store
                .register_access(id, at)
                .await
                .expect("count")
                .is_some()
        );
        assert!(
            store
                .register_access(id, at)
                .await
                .expect("count")
                .is_none()
        );
        assert_eq!(
            store.get(id).await.expect("get").map(|s| s.access_count),
            Some(2)
        );
    }

    #[tokio::test]
    async fn the_purge_removes_sends_past_their_deletion_date_and_their_files() {
        let store = MemorySends::default();
        let blobs = crate::blob::MemoryBlobStore::new();
        let record = send(TYPE_FILE, r#"{"id":"f1","size":1}"#);
        let id = record.id;
        store.put(record).await.expect("put");
        crate::blob::BlobStore::put(&blobs, &blob_key(id, "f1"), vec![1])
            .await
            .expect("a file");

        let early = datetime!(2026-11-22 12:00:00 UTC);
        assert_eq!(purge_sends(&store, &blobs, early).await, Ok(0));
        let late = datetime!(2026-12-01 12:00:00 UTC);
        assert_eq!(purge_sends(&store, &blobs, late).await, Ok(1));
        assert!(store.get(id).await.expect("get").is_none());
        assert!(blobs.is_empty());
    }
}
