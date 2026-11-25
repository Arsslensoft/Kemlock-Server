//! Your data: `GET /kem/v1/account/export` and `DELETE /kem/v1/account` (GDPR Art. 15 and 17, CCPA
//! right to know and delete).
//!
//! The export is the server's record of the account as JSON plus its encrypted vault as stored.
//! The deletion needs proof it is the owner: the body carries either the last two messages of a
//! fresh OPAQUE login (`POST /kem/v1/auth/opaque/start` first, with the same device key), or
//! `proof`, a fresh code of the kind turning a second step off takes (the code mailed by
//! `POST /kem/v1/account/two-factor/proof`, an authenticator code or the recovery code). A stolen
//! access token alone can't erase an account. Both call the use cases the admin console calls for
//! a request.
//!
//! These routes need a store that also keeps the privacy tables, which `SqlStore` does and the
//! shared [`Store`] bound doesn't say, so they have a router of their own, merged beside the main
//! one like the spaces router.

use super::guard;
use super::two_step::require_proof_via_api;
use crate::dto::decode;
use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::{Limiter, ip_key};
use crate::replay::Full;
use crate::state::{Api, Crypto, Store};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use kemlock_app::AppError;
use kemlock_app::ports::{TokenSigner, UserRepo};
use kemlock_app::privacy::{
    AccountData, AccountEraser, EraseAccount, Erasure, ErasureFiles, ExportAccount, PrivacyLog,
    PrivacySettings, Reauthenticate, Requester, SendEraser,
};
use kemlock_app::sign_in::credential_id;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};

/// Exports per account an hour: each reads the whole vault.
const EXPORTS_PER_HOUR: u32 = 5;

/// What the account routes need beyond the API's own store: the privacy tables, the Sends and the
/// files. `SqlStore` is the first; the server supplies the others.
pub trait AccountServices:
    AccountData + AccountEraser + PrivacyLog + PrivacySettings + Clone + 'static
{
}

impl<T> AccountServices for T where
    T: AccountData + AccountEraser + PrivacyLog + PrivacySettings + Clone + 'static
{
}

struct Env<S, P, K, A, X, F> {
    api: Api<S, P, K>,
    privacy: A,
    sends: X,
    files: F,
    exports: Arc<Limiter>,
}

impl<S, P, K, A: Clone, X: Clone, F: Clone> Clone for Env<S, P, K, A, X, F> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            privacy: self.privacy.clone(),
            sends: self.sends.clone(),
            files: self.files.clone(),
            exports: self.exports.clone(),
        }
    }
}

/// An authenticated request: `Authed`, extracted from this router's state.
struct Caller(Authed);

impl<S, P, K, A, X, F> FromRequestParts<Env<S, P, K, A, X, F>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    A: AccountServices,
    X: SendEraser + Clone + 'static,
    F: ErasureFiles + Clone + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        env: &Env<S, P, K, A, X, F>,
    ) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(Caller)
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EraseRequest {
    /// What `POST /auth/opaque/start` answered, unread. Goes with `finalization`.
    login_state: Option<String>,
    /// The client's OPAQUE `CredentialFinalization`.
    finalization: Option<String>,
    /// Instead of the password: the code mailed by `POST /kem/v1/account/two-factor/proof`, a
    /// current code of the authenticator app, or the recovery code. A code works once.
    proof: Option<String>,
}

/// How the request proves the owner.
enum Proof {
    Password {
        login_state: String,
        finalization: String,
    },
    Code(String),
}

impl EraseRequest {
    fn proof(self) -> Result<Proof, Problem> {
        match self {
            EraseRequest {
                login_state: Some(login_state),
                finalization: Some(finalization),
                proof: None,
            } => Ok(Proof::Password {
                login_state,
                finalization,
            }),
            EraseRequest {
                login_state: None,
                finalization: None,
                proof: Some(proof),
            } if !proof.trim().is_empty() => Ok(Proof::Code(proof.trim().to_owned())),
            _ => Err(Problem::bad_request(
                "send loginState and finalization, or a proof, and nothing else",
            )),
        }
    }
}
/// `GET /kem/v1/account/export`.
async fn export_account<S, P, K, A, X, F>(
    State(env): State<Env<S, P, K, A, X, F>>,
    caller: Caller,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    A: AccountServices,
    X: SendEraser + Clone + 'static,
    F: ErasureFiles + Clone + 'static,
{
    let user = caller.0.actor.user;
    guard(&env.exports, &user.to_string(), env.api.now())?;
    let exported = ExportAccount {
        users: env.api.store.clone(),
        data: env.privacy.clone(),
        log: env.privacy.clone(),
        clock: env.api.crypto.clone(),
    }
    .execute(user, Requester::Account)
    .await?;
    let disposition = format!("attachment; filename=\"{}\"", exported.file_name);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        Json(exported.document),
    )
        .into_response())
}

/// `DELETE /kem/v1/account`: 204 when the account is erased; 202 with the due date when the admin
/// gave deleted accounts a grace period.
async fn erase_account<S, P, K, A, X, F>(
    State(env): State<Env<S, P, K, A, X, F>>,
    caller: Caller,
    body: Body,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    A: AccountServices,
    X: SendEraser + Clone + 'static,
    F: ErasureFiles + Clone + 'static,
{
    let api = &env.api;
    let request: EraseRequest = body.json()?;
    let user = UserRepo::by_id(&api.store, caller.0.actor.user)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| Problem::from(AppError::Unauthorized))?;

    let proof = request.proof()?;
    // The refusal that needs no proof comes first, so a proof is never spent on it.
    if !env
        .privacy
        .blocking_spaces(user.id)
        .await
        .map_err(AppError::from)?
        .is_empty()
    {
        return Err(AppError::Invalid(
            "the account is the only owner of a space with other members: hand it over or delete the space first",
        )
        .into());
    }
    match proof {
        Proof::Code(code) => {
            guard(&api.limits.sign_in, &ip_key(caller.0.ip), api.now())?;
            require_proof_via_api(api, user.id, &code, true).await?;
        }
        Proof::Password {
            login_state,
            finalization,
        } => {
            // A wrong password counts against the account like a wrong sign-in does.
            let account = format!("acct:{}", credential_id(user.email.as_str()));
            api.limits
                .account
                .blocked(&account, api.now())
                .map_err(rate_limited)?;
            let login_state = decode("loginState", &login_state)?;
            let finalization = decode("finalization", &finalization)?;
            // A login state finishes once, whether the password was right or not. Only a genuine,
            // fresh state is remembered.
            api.sign_in().check_login_state(&login_state)?;
            match api.used_states.insert(&login_state, api.now()) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Problem::bad_request("the login state was already used"));
                }
                Err(Full) => return Err(Problem::overloaded()),
            }
            let checked = Reauthenticate {
                users: api.store.clone(),
                auth: api.crypto.clone(),
                seal: api.crypto.clone(),
                clock: api.crypto.clone(),
            }
            .execute(user.id, &login_state, &finalization, &caller.0.jkt)
            .await;
            match &checked {
                Err(AppError::Unauthorized) => api.limits.account.fail(&account, api.now()),
                Ok(()) => api.limits.account.clear(&account),
                Err(_) => {}
            }
            checked?;
        }
    }

    let outcome = EraseAccount {
        users: api.store.clone(),
        eraser: env.privacy.clone(),
        sends: env.sends.clone(),
        files: env.files.clone(),
        settings: env.privacy.clone(),
        log: env.privacy.clone(),
        env: api.crypto.clone(),
    }
    .execute(user.id, Requester::Account)
    .await?;
    Ok(match outcome {
        Erasure::Erased(_) => StatusCode::NO_CONTENT.into_response(),
        Erasure::Scheduled { due } => (
            StatusCode::ACCEPTED,
            Json(json!({
                "status": "scheduled",
                "dueAt": due.format(&Rfc3339).unwrap_or_default(),
            })),
        )
            .into_response(),
    })
}

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K, A, X, F>(
    State(env): State<Env<S, P, K, A, X, F>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    A: AccountServices,
    X: SendEraser + Clone + 'static,
    F: ErasureFiles + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The routes of `/kem/v1/account`'s data rights. Merge it beside [`crate::router`]; it has no
/// fallback.
///
/// ```text
/// GET     /kem/v1/account/export   the server's record of the account, plus the vault as stored
/// DELETE  /kem/v1/account          erase the account after re-authenticating
/// ```
pub fn router<S, P, K, A, X, F>(api: Api<S, P, K>, privacy: A, sends: X, files: F) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    A: AccountServices,
    X: SendEraser + Clone + 'static,
    F: ErasureFiles + Clone + 'static,
{
    let env = Env {
        api,
        privacy,
        sends,
        files,
        exports: Arc::new(Limiter::new(EXPORTS_PER_HOUR, 3600)),
    };
    Router::new()
        .route(
            "/kem/v1/account/export",
            get(export_account::<S, P, K, A, X, F>),
        )
        .route(
            "/kem/v1/account",
            axum::routing::delete(erase_account::<S, P, K, A, X, F>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, A, X, F>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/account/export", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The server's record of the account as JSON, plus the encrypted vault as stored; sent as an attachment"),
        (status = 401, description = "Not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Five exports an hour", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_export() {}

#[utoipa::path(
    delete, path = "/kem/v1/account", tag = "account",
    security(("dpop" = [])),
    request_body = EraseRequest,
    responses(
        (status = 204, description = "The account is erased"),
        (status = 202, description = "Scheduled: the admin gave deleted accounts a grace period; carries `status` and `dueAt`"),
        (status = 400, description = "The login state was used before, or isn't well formed; the proof is wrong or spent; or the account is the only owner of a space with other members", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong password, or not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong passwords", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_erase() {}

/// The account routes' part of `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(paths(doc_export, doc_erase), components(schemas(EraseRequest)))]
struct AccountDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    AccountDoc::openapi()
}
