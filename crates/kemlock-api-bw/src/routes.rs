//! The routes: `/identity`, `/api` and the attachment download link, as Vaultwarden's routing
//! table lays them out. Handlers parse the request, call the functions in the other modules and
//! answer in Vaultwarden's shapes.

use crate::account;
use crate::app::{App, Authed, BwStore};
use crate::attachments::{self, AttachmentRequest};
use crate::cipher::CipherData;
use crate::dates::format_date;
use crate::error::{BwError, BwResult};
use crate::identity::{self, Caller, ConnectData};
use crate::vault::{self, FolderData, IdsData, ImportData, MoveData, PartialData};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, FromRequestParts, Multipart, Path, Query, State,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use kemlock_app::privacy::ClientAddr;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The server version Vaultwarden claims in `/api/config`, which clients use to decide what the
/// server supports.
pub const CLAIMED_SERVER_VERSION: &str = "2026.6.0";

/// JSON bodies up to 64 MiB: an import of a large vault is one body.
const JSON_BODY_LIMIT: usize = 64 * 1024 * 1024;
/// The most a request with no sign-in may send: a password sign-in, a registration (whose keys are
/// a few KiB) and the like. The server buffers a body before it can know who sent it, so these
/// routes take no more than this, where the signed-in ones take up to the JSON limit above.
pub(crate) const UNAUTHENTICATED_BODY_LIMIT: usize = 32 * 1024;
/// An attachment upload is up to Vaultwarden's 525 MB, plus the multipart framing.
const UPLOAD_BODY_LIMIT: usize = 551 * 1024 * 1024;

/// The client's address: the one the server's request layer settled ([`ClientAddr`], which looks
/// through a trusted proxy), else the peer's, else `0.0.0.0` when the server wasn't started to
/// tell us.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Peer(pub(crate) IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        let settled = parts.extensions.get::<ClientAddr>().map(|a| a.0);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        Ok(Peer(
            settled
                .or(peer)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ))
    }
}

/// Parses a JSON body the way Rocket's `Json` guard does: a body that is JSON of the wrong shape
/// is a 422, one that isn't JSON a 400.
pub(crate) fn parse<T: DeserializeOwned>(body: &[u8]) -> BwResult<T> {
    serde_json::from_slice(body).map_err(|e| {
        if e.classify() == serde_json::error::Category::Data {
            BwError::status(StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable Entity")
        } else {
            BwError::status(StatusCode::BAD_REQUEST, "Bad Request")
        }
    })
}

pub(crate) type JsonResult = Result<Json<Value>, BwError>;
pub(crate) type EmptyResult = Result<StatusCode, BwError>;

pub(crate) fn ok(v: Value) -> JsonResult {
    Ok(Json(v))
}

/// A JSON answer that carries a secret (an invitation link accepts for its account), so no cache
/// keeps it.
pub(crate) type SecretJsonResult =
    Result<([(header::HeaderName, &'static str); 1], Json<Value>), BwError>;

pub(crate) fn ok_no_store(v: Value) -> SecretJsonResult {
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(v)))
}

pub(crate) fn empty(r: BwResult<()>) -> EmptyResult {
    r.map(|()| StatusCode::OK)
}

pub(crate) fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

// --- identity -------------------------------------------------------------------------------

#[derive(Deserialize)]
struct PreloginData {
    email: String,
}

async fn prelogin<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    body: Bytes,
) -> JsonResult {
    // The KDF settings are what tells a real account from an invented answer (an account whose
    // settings are not one of the six common ones is known by them), so asking is limited by address.
    app.prelogin_limit
        .check(ip, app.now_secs())
        .map_err(|_| BwError::status(StatusCode::TOO_MANY_REQUESTS, "Too many requests"))?;
    let data: PreloginData = parse(&body)?;
    ok(account::prelogin(&app, &data.email).await?)
}

async fn connect_token<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BwError> {
    let data = ConnectData::from_form(&body)
        .ok_or_else(|| BwError::status(StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable Entity"))?;
    if data.grant_type == "send_access" {
        if data.client_id.is_none() {
            return Err(BwError::msg("client_id cannot be blank"));
        }
        let Some(send_id) = data.send_id.as_deref() else {
            return Err(BwError::msg("send_id cannot be blank"));
        };
        return Ok(crate::sends::send_access_token(
            &app,
            send_id,
            data.password_hash_b64.as_deref(),
        )
        .await);
    }
    let caller = Caller {
        device_type_header: header_text(&headers, "device-type").map(str::to_owned),
        ip,
    };
    Ok(Json(identity::token(&app, data, caller).await?).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationData {
    email: String,
    name: Option<String>,
    /// A server invitation's token (Kemlock's own field).
    invite_token: Option<String>,
}

/// Rocket sends JSON back only when the client's preferred type is exactly `application/json`.
fn prefers_json(headers: &HeaderMap) -> bool {
    header_text(headers, "accept")
        .and_then(|a| a.split(',').next())
        .and_then(|first| first.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

async fn register_send_verification<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BwError> {
    let data: VerificationData = parse(&body)?;
    let token = account::verification_token(
        &app,
        &data.email,
        data.name,
        data.invite_token.as_deref(),
        ip,
    )
    .await?;
    // Where the server verifies sign-ups the token went to the address, and the answer is empty.
    let Some(token) = token else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    Ok(if prefers_json(&headers) {
        Json(Value::String(token)).into_response()
    } else {
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], token).into_response()
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClickedData {
    email: String,
    email_verification_token: String,
}

async fn register_verification_clicked<S: BwStore>(
    State(app): State<App<S>>,
    body: Bytes,
) -> EmptyResult {
    let data: ClickedData = parse(&body)?;
    empty(account::verification_clicked(&app, &data.email, &data.email_verification_token).await)
}

async fn register_finish<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    body: Bytes,
) -> JsonResult {
    let value: Value = parse(&body)?;
    let request = account::parse_registration(&value)?;
    account::register(&app, request, ip).await?;
    ok(json!({ "object": "registerFinish" }))
}

// --- account and meta -----------------------------------------------------------------------

fn config_json<S: BwStore>(app: &App<S>) -> Value {
    let domain = &app.settings.domain;
    json!({
        // Clients use this version to decide what the server supports: it is Bitwarden's, never
        // Kemlock Server's own.
        "version": CLAIMED_SERVER_VERSION,
        "gitHash": null,
        "server": {
            "name": "Vaultwarden",
            "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": !app.settings.signups_allowed(),
            "suppressOnboardingInterstitials": false
        },
        "environment": {
            "vault": domain,
            "api": format!("{domain}/api"),
            "identity": format!("{domain}/identity"),
            "notifications": format!("{domain}/notifications"),
            "sso": "",
            "cloudRegion": null,
            "fillAssistRules": null
        },
        "push": {
            "pushTechnology": 0,
            "vapidPublicKey": null
        },
        "featureStates": { "pm-19148-innovation-archive": true },
        "communication": null,
        // Tells a client that this server also speaks the Kemlock API.
        "kemlock": {
            "api": format!("{domain}/kem/v1"),
            "versions": ["v1"]
        },
        "object": "config",
    })
}

async fn config<S: BwStore>(State(app): State<App<S>>) -> Json<Value> {
    Json(config_json(&app))
}

async fn now<S: BwStore>(State(app): State<App<S>>) -> Json<Value> {
    Json(Value::String(format_date(app.now())))
}

async fn version() -> Json<Value> {
    Json(Value::String(env!("CARGO_PKG_VERSION").to_owned()))
}

/// The revision date: the one thing that decides whether a client syncs. The token's account is
/// read fresh for every request, so this is what the last change left.
async fn revision_date<S: BwStore>(_: State<App<S>>, authed: Authed) -> JsonResult {
    ok(json!(authed.account.revision_ms))
}

async fn profile<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    ok(account::profile_json(&app, &authed.user, &authed.account).await?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordOrOtp {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

async fn api_key_route<S: BwStore>(
    app: App<S>,
    authed: Authed,
    body: Bytes,
    rotate: bool,
) -> JsonResult {
    let data: PasswordOrOtp = parse(&body)?;
    // The password or a mailed one-time code, which a right entry uses up.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        true,
    )
    .await?;
    ok(account::api_key(&app, &authed.account, rotate).await?)
}

/// `DELETE /api/accounts` and `POST /api/accounts/delete`.
async fn delete_account<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: PasswordOrOtp = parse(&body)?;
    // The password or a mailed one-time code, which a right entry uses up.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        true,
    )
    .await?;
    empty(account::delete_account(&app, authed.user.id).await)
}

async fn post_api_key<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    api_key_route(app, authed, body, false).await
}

async fn rotate_api_key<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    api_key_route(app, authed, body, true).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserKeyIdData {
    #[serde(alias = "UserKeyId")]
    user_key_id: String,
}

async fn post_user_key_id<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: UserKeyIdData = parse(&body)?;
    // A malformed id fails as Vaultwarden's `KeyId` fails to deserialize: a 422.
    if !account::is_key_id(&data.user_key_id) {
        return Err(BwError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Entity",
        ));
    }
    empty(account::record_user_key_id(&app, authed.user.id, &data.user_key_id).await)
}

async fn post_kdf<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: crate::kdf_change::ChangeKdfData = parse(&body)?;
    empty(crate::kdf_change::change_kdf(&app, &authed, data).await)
}

async fn known_device<S: BwStore>(State(app): State<App<S>>, headers: HeaderMap) -> JsonResult {
    // The email comes as unpadded base64url in `X-Request-Email`; padding some clients add is dropped.
    let email = header_text(&headers, "x-request-email")
        .map(|v| v.trim_end_matches('='))
        .and_then(kemlock_app::b64url::decode)
        .and_then(|b| String::from_utf8(b).ok());
    let identifier = header_text(&headers, "x-device-identifier");
    let known = match (email, identifier) {
        (Some(email), Some(identifier)) => identity::known_device(&app, &email, identifier).await?,
        _ => false,
    };
    ok(json!(known))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailLoginData {
    #[serde(alias = "Email")]
    email: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
}

async fn send_email_login<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    body: Bytes,
) -> EmptyResult {
    let data: SendEmailLoginData = parse(&body)?;
    empty(
        identity::send_email_login(
            &app,
            ip,
            data.email.as_deref(),
            data.master_password_hash.as_deref(),
        )
        .await,
    )
}

// --- sync, folders and ciphers --------------------------------------------------------------

/// Rocket's bool form values.
pub(crate) fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "on" | "yes" | "1"
    )
}

async fn sync<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> JsonResult {
    let exclude = query.get("excludeDomains").is_some_and(|v| truthy(v));
    ok(vault::sync(
        &app,
        &authed,
        exclude,
        header_text(&headers, "bitwarden-client-version"),
    )
    .await?)
}

async fn list_folders<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    ok(vault::list_folders(&app, &authed).await?)
}

async fn get_folder<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(vault::get_folder(&app, &authed, &id).await?)
}

async fn create_folder<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: FolderData = parse(&body)?;
    ok(vault::create_folder(&app, &authed, data).await?)
}

async fn update_folder<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: FolderData = parse(&body)?;
    ok(vault::update_folder(&app, &authed, &id, data).await?)
}

async fn delete_folder<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    empty(vault::delete_folder(&app, &authed, &id).await)
}

async fn list_ciphers<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    ok(vault::list_ciphers(&app, &authed).await?)
}

async fn get_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(vault::get_cipher(&app, &authed, &id).await?)
}

async fn create_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: CipherData = parse(&body)?;
    ok(vault::create_cipher(&app, &authed, data).await?)
}

#[derive(Deserialize)]
struct ShareCipherData {
    #[serde(alias = "Cipher")]
    cipher: CipherData,
    /// The collections of an organization cipher.
    #[serde(default, rename = "collectionIds", alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

/// `POST /api/ciphers/create`: the body wraps the cipher, which clients use when cloning one.
async fn create_cipher_wrapped<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: ShareCipherData = parse(&body)?;
    if data.cipher.organization_id.is_some() {
        if data.cipher.encrypted_for != authed.user.id.to_string() {
            return Err(BwError::status(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid user cipher",
            ));
        }
        return ok(crate::orgs::ciphers::create_in_org(
            &app,
            &authed,
            data.cipher,
            &data.collection_ids,
        )
        .await?);
    }
    ok(vault::create_cipher(&app, &authed, data.cipher).await?)
}

async fn update_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: CipherData = parse(&body)?;
    ok(vault::update_cipher(&app, &authed, &id, data).await?)
}

async fn partial_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: PartialData = parse(&body)?;
    ok(vault::partial_cipher(&app, &authed, &id, data).await?)
}

/// `DELETE` and `POST …/delete` are permanent; only `PUT …/delete` is the trash.
async fn delete_cipher_hard<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    empty(vault::delete_cipher(&app, &authed, &id, false).await)
}

async fn delete_cipher_soft<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    empty(vault::delete_cipher(&app, &authed, &id, true).await)
}

async fn restore_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(vault::restore_cipher(&app, &authed, &id).await?)
}

async fn delete_ciphers_hard<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: IdsData = parse(&body)?;
    empty(vault::delete_ciphers(&app, &authed, &data.ids, false).await)
}

async fn delete_ciphers_soft<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: IdsData = parse(&body)?;
    empty(vault::delete_ciphers(&app, &authed, &data.ids, true).await)
}

async fn restore_ciphers<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: IdsData = parse(&body)?;
    ok(vault::restore_ciphers(&app, &authed, &data.ids).await?)
}

async fn move_ciphers<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: MoveData = parse(&body)?;
    empty(vault::move_ciphers(&app, &authed, data).await)
}

async fn archive_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(vault::archive_cipher(&app, &authed, &id, true).await?)
}

async fn unarchive_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(vault::archive_cipher(&app, &authed, &id, false).await?)
}

async fn archive_ciphers<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: IdsData = parse(&body)?;
    ok(vault::archive_ciphers(&app, &authed, &data.ids, true).await?)
}

async fn unarchive_ciphers<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: IdsData = parse(&body)?;
    ok(vault::archive_ciphers(&app, &authed, &data.ids, false).await?)
}

async fn import<S: BwStore>(State(app): State<App<S>>, authed: Authed, body: Bytes) -> EmptyResult {
    let data: ImportData = parse(&body)?;
    empty(vault::import(&app, &authed, data).await)
}

// --- attachments ----------------------------------------------------------------------------

async fn create_attachment<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(cipher): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: AttachmentRequest = parse(&body)?;
    ok(attachments::create_attachment(&app, &authed, &cipher, data).await?)
}

async fn upload_attachment<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((cipher, attachment)): Path<(String, String)>,
    mut multipart: Multipart,
) -> EmptyResult {
    let mut data = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| BwError::msg(e.to_string()))?
    {
        if field.name() == Some("data") {
            let bytes = field
                .bytes()
                .await
                .map_err(|e| BwError::msg(e.to_string()))?;
            data = Some(bytes.to_vec());
        }
    }
    let Some(data) = data else {
        return Err(BwError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Entity",
        ));
    };
    empty(attachments::upload_attachment(&app, &authed, &cipher, &attachment, data).await)
}

async fn get_attachment<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((cipher, attachment)): Path<(String, String)>,
) -> JsonResult {
    ok(attachments::get_attachment(&app, &authed, &cipher, &attachment).await?)
}

async fn delete_attachment<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((cipher, attachment)): Path<(String, String)>,
) -> JsonResult {
    ok(attachments::delete_attachment(&app, &authed, &cipher, &attachment).await?)
}

/// The download link: no bearer token, one query value that is a token this server signed.
async fn download_attachment<S: BwStore>(
    State(app): State<App<S>>,
    Path((cipher, attachment)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(token) = query.get("token") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match attachments::download(&app, &cipher, &attachment, token).await {
        Some(bytes) => {
            ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The Bitwarden router: every route Vaultwarden has that Kemlock and Amethystora Vault use, and
/// the web vault's registration routes. It has no fallback, so it merges with other routers;
/// with `KEMLOCK_BITWARDEN_COMPAT` off it has no routes at all and every Bitwarden path is a 404.
pub fn router<S: BwStore>(app: App<S>) -> Router {
    if !app.settings.compat {
        return Router::new();
    }
    Router::new()
        // identity
        .route(
            "/identity/accounts/prelogin",
            post(prelogin::<S>).layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        .route(
            "/identity/accounts/prelogin/password",
            post(prelogin::<S>).layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        .route(
            "/identity/connect/token",
            post(connect_token::<S>).layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        .route(
            "/identity/accounts/register/send-verification-email",
            post(register_send_verification::<S>)
                .layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        .route(
            "/identity/accounts/register/verification-email-clicked",
            post(register_verification_clicked::<S>)
                .layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        .route(
            "/identity/accounts/register/finish",
            post(register_finish::<S>).layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        // account and meta
        .route("/api/config", get(config::<S>))
        .route("/api/alive", get(now::<S>))
        .route("/api/now", get(now::<S>))
        .route("/api/version", get(version))
        .route("/api/accounts/revision-date", get(revision_date::<S>))
        .route("/api/accounts/profile", get(profile::<S>))
        .route("/api/accounts", axum::routing::delete(delete_account::<S>))
        .route("/api/accounts/delete", post(delete_account::<S>))
        .route("/api/accounts/api-key", post(post_api_key::<S>))
        .route("/api/accounts/rotate-api-key", post(rotate_api_key::<S>))
        .route("/api/accounts/kdf", post(post_kdf::<S>))
        .route(
            "/api/accounts/key-management/user-key-id",
            post(post_user_key_id::<S>),
        )
        .route("/api/devices/knowndevice", get(known_device::<S>))
        .route(
            "/api/two-factor/send-email-login",
            post(send_email_login::<S>).layer(DefaultBodyLimit::max(UNAUTHENTICATED_BODY_LIMIT)),
        )
        // sync
        .route("/api/sync", get(sync::<S>))
        // folders
        .route(
            "/api/folders",
            get(list_folders::<S>).post(create_folder::<S>),
        )
        .route(
            "/api/folders/{id}",
            get(get_folder::<S>)
                .put(update_folder::<S>)
                .post(update_folder::<S>)
                .delete(delete_folder::<S>),
        )
        .route("/api/folders/{id}/delete", post(delete_folder::<S>))
        // ciphers
        .route(
            "/api/ciphers",
            get(list_ciphers::<S>)
                .post(create_cipher::<S>)
                .delete(delete_ciphers_hard::<S>),
        )
        .route("/api/ciphers/create", post(create_cipher_wrapped::<S>))
        .route("/api/ciphers/admin", post(create_cipher_wrapped::<S>))
        .route("/api/ciphers/import", post(import::<S>))
        .route(
            "/api/ciphers/delete",
            post(delete_ciphers_hard::<S>).put(delete_ciphers_soft::<S>),
        )
        .route("/api/ciphers/restore", put(restore_ciphers::<S>))
        .route(
            "/api/ciphers/move",
            post(move_ciphers::<S>).put(move_ciphers::<S>),
        )
        .route("/api/ciphers/archive", put(archive_ciphers::<S>))
        .route("/api/ciphers/unarchive", put(unarchive_ciphers::<S>))
        .route(
            "/api/ciphers/{id}",
            get(get_cipher::<S>)
                .put(update_cipher::<S>)
                .post(update_cipher::<S>)
                .delete(delete_cipher_hard::<S>),
        )
        .route("/api/ciphers/{id}/details", get(get_cipher::<S>))
        .route("/api/ciphers/{id}/admin", get(get_cipher::<S>))
        .route(
            "/api/ciphers/{id}/partial",
            put(partial_cipher::<S>).post(partial_cipher::<S>),
        )
        .route(
            "/api/ciphers/{id}/delete",
            put(delete_cipher_soft::<S>).post(delete_cipher_hard::<S>),
        )
        .route("/api/ciphers/{id}/restore", put(restore_cipher::<S>))
        .route("/api/ciphers/{id}/archive", put(archive_cipher::<S>))
        .route("/api/ciphers/{id}/unarchive", put(unarchive_cipher::<S>))
        // attachments
        .route(
            "/api/ciphers/{id}/attachment/v2",
            post(create_attachment::<S>),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            get(get_attachment::<S>)
                .delete(delete_attachment::<S>)
                .post(upload_attachment::<S>)
                .layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete",
            post(delete_attachment::<S>),
        )
        // the admin forms of the same delete, which the organization web vault calls
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete-admin",
            post(delete_attachment::<S>),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/admin",
            axum::routing::delete(delete_attachment::<S>),
        )
        .route(
            "/attachments/{cipher_id}/{attachment_id}",
            get(download_attachment::<S>),
        )
        .merge(crate::webauthn::routes::<S>())
        .merge(crate::authenticator::routes::<S>())
        .merge(crate::two_step::routes::<S>())
        .merge(crate::orgs::routes::<S>())
        .merge(crate::public::routes::<S>())
        .merge(crate::emergency::routes::<S>())
        .merge(crate::sends::routes::<S>())
        .merge(crate::events::routes::<S>())
        .merge(crate::domains::routes::<S>())
        .merge(crate::protected::routes::<S>())
        .merge(crate::device_push::routes::<S>())
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT))
        .with_state(app)
}
