//! The personal API key, for the Bitwarden CLI and scripts.
//!
//! ```text
//! GET   /kem/v1/account/api-key          the client id, and whether a key was made; never the secret
//! POST  /kem/v1/account/api-key          the secret (made on first ask): {proof}
//! POST  /kem/v1/account/api-key/rotate   a new secret, the old one stops working: {proof}
//! ```
//!
//! The key is the one the Bitwarden API's `POST /api/accounts/api-key` hands out and
//! `grant_type=client_credentials` takes (`client_id` `user.<id>`, scope `api`), so showing it
//! and replacing it take the fresh proof turning a second step off does (the mailed code from
//! `POST /kem/v1/account/two-factor/proof`, an authenticator code or the recovery code): a stolen
//! session can't read a secret that opens the account without its second step. Each use writes an
//! event. An account made through the Kemlock sign-in alone has no Bitwarden record and so no
//! key: 404. The routes need the Bitwarden account store, so they have a router of their own, see
//! [`api_key_router`].

use super::guard;
use super::two_step::{ProofRequest, nonce_header, require_proof_via_api};
use crate::extract::{Authed, Body};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Extension, Json, Router, middleware};
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::bitwarden::api_key::{ApiKey, ApiKeys};
use kemlock_app::ports::TokenSigner;
use serde::Serialize;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};

/// The store of the Bitwarden account records, `SqlStore` in the server.
struct Repos<R>(R);

/// What an account's key looks like without its secret.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiKeyInfoDto {
    /// `user.<id>`: what the CLI calls `client_id`.
    client_id: String,
    /// Whether the key was made yet.
    set: bool,
}

/// The key with its secret.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiKeyDto {
    client_id: String,
    /// The secret (`client_secret`). Shown on request only.
    client_secret: String,
    /// The account's revision date, RFC 3339.
    revision_date: String,
}

impl ApiKeyDto {
    fn of(key: &ApiKey) -> Self {
        let at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(key.revision_ms) * 1_000_000)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        Self {
            client_id: key.client_id.clone(),
            client_secret: key.client_secret.clone(),
            revision_date: at.format(&Rfc3339).unwrap_or_default(),
        }
    }
}

fn keys<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> ApiKeys<R, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: BwAccountRepo + Clone + 'static,
{
    ApiKeys {
        accounts: repos.0.clone(),
        env: api.crypto.clone(),
    }
}

async fn handle_show<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<Json<ApiKeyInfoDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: BwAccountRepo + Clone + 'static,
{
    guard(&api.limits.proof, &ip_key(authed.ip), api.now())?;
    let (client_id, set) = keys(&api, &repos).show(authed.actor.user).await?;
    Ok(Json(ApiKeyInfoDto { client_id, set }))
}

async fn handle_reveal<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<ApiKeyDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: BwAccountRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: ProofRequest = body.json()?;
    let use_case = keys(&api, &repos);
    // An account with no key to show is refused before the proof is spent.
    use_case.show(authed.actor.user).await?;
    require_proof_via_api(&api, authed.actor.user, &request.proof, true).await?;
    let key = use_case.reveal(authed.actor.user).await?;
    api.sessions()
        .record(
            if key.created {
                "account.api_key_created"
            } else {
                "account.api_key_viewed"
            },
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    Ok(Json(ApiKeyDto::of(&key)))
}

async fn handle_rotate<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<ApiKeyDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: BwAccountRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: ProofRequest = body.json()?;
    let use_case = keys(&api, &repos);
    use_case.show(authed.actor.user).await?;
    require_proof_via_api(&api, authed.actor.user, &request.proof, true).await?;
    let key = use_case.rotate(authed.actor.user).await?;
    api.sessions()
        .record(
            "account.api_key_rotated",
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    Ok(Json(ApiKeyDto::of(&key)))
}

/// The API key routes. Merge the result into the main router, with the store of the Bitwarden
/// account records:
///
/// ```ignore
/// router(api.clone()).merge(api_key_router(api, store))
/// ```
pub fn api_key_router<S, P, K, R>(api: Api<S, P, K>, accounts: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: BwAccountRepo + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/account/api-key",
            get(handle_show::<S, P, K, R>).post(handle_reveal::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/api-key/rotate",
            post(handle_rotate::<S, P, K, R>),
        )
        .layer(Extension(Arc::new(Repos(accounts))))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/account/api-key", tag = "api-key",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The client id, and whether a key was made", body = ApiKeyInfoDto),
        (status = 404, description = "The account has no Bitwarden record, so no key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_show() {}

#[utoipa::path(
    post, path = "/kem/v1/account/api-key", tag = "api-key",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses(
        (status = 200, description = "The key with its secret; made now when there was none", body = ApiKeyDto),
        (status = 400, description = "The proof is wrong or spent", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "The account has no Bitwarden record, so no key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_reveal() {}

#[utoipa::path(
    post, path = "/kem/v1/account/api-key/rotate", tag = "api-key",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses(
        (status = 200, description = "A new key; the old secret no longer signs in", body = ApiKeyDto),
        (status = 400, description = "The proof is wrong or spent", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "The account has no Bitwarden record, so no key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_rotate() {}

#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_show, doc_reveal, doc_rotate),
    components(schemas(ApiKeyInfoDto, ApiKeyDto))
)]
pub struct ApiKeyApiDoc;
