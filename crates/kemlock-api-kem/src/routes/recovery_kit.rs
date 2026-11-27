//! The Recovery Kit: the root key split into 3 pieces, any 2 of which unlock the vault
//! (docs/crypto.md, "The Recovery Kit").
//!
//! ```text
//! GET    /kem/v1/account/recovery-kit   the kit's id, key version, time and wrap, or 404
//! POST   /kem/v1/account/recovery-kit   the first kit: {kitId, keyVersion, wrappedKey}; 409 when there is one
//! PUT    /kem/v1/account/recovery-kit   a new kit in place of the old: the same, with {proof}
//! DELETE /kem/v1/account/recovery-kit   no kit any more: {proof}
//! ```
//!
//! The key worker makes the kit, so the pieces never leave the browser and the server keeps only
//! the non-secret record. The wrap is also the verifier: only the right pieces open it. Replacing
//! or removing the kit takes the same fresh proof turning a second step off does (the code mailed
//! by `POST /kem/v1/account/two-factor/proof`, an answer of a security key or passkey, or, with mail off, a current code of the authenticator
//! app or the recovery code), so a stolen session can't swap the kit for one it
//! holds the pieces of, and each change writes an event. The routes need a store that keeps kits,
//! so they have a router of their own: see [`recovery_kit_router`].

use super::guard;
use super::two_step::{ProofRequest, nonce_header, proof_steps, require_proof};
use crate::dto::{FreshProof, decode};
use crate::extract::{Authed, Body};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use kemlock_app::passkeys::ChallengeRepo;
use kemlock_app::ports::TokenSigner;
use kemlock_app::recovery_kit::{NewKit, RecoveryKitRepo, RecoveryKits};
use kemlock_app::{AppError, b64url};
use kemlock_domain::RecoveryKit;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};

/// What the kit routes need beyond the rest of the API: the kit records and the challenge store
/// the fresh proof is checked with. `SqlStore` is both.
struct Repos<R>(R);

fn iso(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

// ---- wire types ----

/// A new kit's record, from the key worker's `kitMake`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateKitRequest {
    /// The kit id: 8 base32 characters, as in every piece.
    pub(crate) kit_id: String,
    /// The account's key version the wrap is for: the current one.
    pub(crate) key_version: u32,
    /// The root key wrapped under the kit key, base64url, 92 bytes.
    pub(crate) wrapped_key: String,
}

/// A new kit in place of the old one.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplaceKitRequest {
    pub(crate) kit_id: String,
    pub(crate) key_version: u32,
    pub(crate) wrapped_key: String,
    /// A fresh proof: the code mailed by `POST /kem/v1/account/two-factor/proof` (it works once), a
    /// current code of the authenticator app, or `{"webauthn": ...}`, the answer of a security key
    /// or passkey.
    pub(crate) proof: FreshProof,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KitDto {
    pub(crate) kit_id: String,
    /// Pieces needed to unlock.
    pub(crate) threshold: u8,
    /// Pieces made.
    pub(crate) shares: u8,
    pub(crate) key_version: u32,
    /// When the kit was made, RFC 3339.
    pub(crate) created_at: String,
    /// Whether the kit is for the account's current key version: only then do its pieces open the
    /// vault.
    pub(crate) current: bool,
    /// The root key wrapped under the kit key, base64url: opaque to the server, and useless
    /// without the pieces.
    pub(crate) wrapped_key: String,
}

impl KitDto {
    fn of(kit: &RecoveryKit, current: bool) -> Self {
        Self {
            kit_id: kit.kit_id.clone(),
            threshold: 2,
            shares: 3,
            key_version: kit.key_version,
            created_at: iso(kit.created_at),
            current,
            wrapped_key: b64url::encode(&kit.wrapped_key),
        }
    }
}

// ---- handlers ----

fn kits<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> RecoveryKits<R, S, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + Clone + 'static,
{
    RecoveryKits {
        kits: repos.0.clone(),
        users: api.store.clone(),
        env: api.crypto.clone(),
    }
}

async fn handle_show<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<Json<KitDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + ChallengeRepo + Clone + 'static,
{
    guard(&api.limits.proof, &ip_key(authed.ip), api.now())?;
    let view = kits(&api, &repos)
        .show(authed.actor.user)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(KitDto::of(&view.kit, view.current)))
}

async fn handle_create<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<(StatusCode, Json<KitDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + ChallengeRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    authed.require_fresh_sign_in(api.now())?;
    let request: CreateKitRequest = body.json()?;
    let kit = kits(&api, &repos)
        .create(
            authed.actor.user,
            NewKit {
                kit_id: request.kit_id,
                wrapped_key: decode("wrappedKey", &request.wrapped_key)?,
                key_version: request.key_version,
            },
        )
        .await?;
    api.sessions()
        .record(
            "account.recovery_kit_created",
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    Ok((StatusCode::CREATED, Json(KitDto::of(&kit, true))))
}

async fn handle_replace<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<KitDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + ChallengeRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: ReplaceKitRequest = body.json()?;
    let new = NewKit {
        kit_id: request.kit_id,
        wrapped_key: decode("wrappedKey", &request.wrapped_key)?,
        key_version: request.key_version,
    };
    // Everything that can be known to be wrong is said before the proof is spent.
    let use_case = kits(&api, &repos);
    use_case.check(authed.actor.user, &new).await?;
    if use_case.show(authed.actor.user).await?.is_none() {
        return Err(AppError::NotFound.into());
    }
    require_proof(
        &api,
        &proof_steps(&api, repos.0.clone()),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    let kit = use_case.regenerate(authed.actor.user, new).await?;
    api.sessions()
        .record(
            "account.recovery_kit_regenerated",
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    Ok(Json(KitDto::of(&kit, true)))
}

async fn handle_remove<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + ChallengeRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: ProofRequest = body.json()?;
    if kits(&api, &repos).show(authed.actor.user).await?.is_none() {
        return Err(AppError::NotFound.into());
    }
    require_proof(
        &api,
        &proof_steps(&api, repos.0.clone()),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    kits(&api, &repos).remove(authed.actor.user).await?;
    api.sessions()
        .record(
            "account.recovery_kit_removed",
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// The Recovery Kit routes. Merge the result into the main router, with the store that keeps the
/// kits and the proof's challenges:
///
/// ```ignore
/// router(api.clone()).merge(recovery_kit_router(api, store))
/// ```
pub fn recovery_kit_router<S, P, K, R>(api: Api<S, P, K>, repos: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RecoveryKitRepo + ChallengeRepo + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/account/recovery-kit",
            get(handle_show::<S, P, K, R>)
                .post(handle_create::<S, P, K, R>)
                .put(handle_replace::<S, P, K, R>)
                .delete(handle_remove::<S, P, K, R>),
        )
        .layer(Extension(Arc::new(Repos(repos))))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/account/recovery-kit", tag = "recovery-kit",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The account's kit", body = KitDto),
        (status = 404, description = "The account has no kit", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_show() {}

#[utoipa::path(
    post, path = "/kem/v1/account/recovery-kit", tag = "recovery-kit",
    security(("dpop" = [])),
    request_body = CreateKitRequest,
    responses(
        (status = 201, description = "The kit is kept", body = KitDto),
        (status = 400, description = "The id or the wrap is malformed, or the wrap is for another key version", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The account has a kit: replace it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_create() {}

#[utoipa::path(
    put, path = "/kem/v1/account/recovery-kit", tag = "recovery-kit",
    security(("dpop" = [])),
    request_body = ReplaceKitRequest,
    responses(
        (status = 200, description = "The new kit is kept; the old pieces no longer work", body = KitDto),
        (status = 400, description = "The proof is wrong or spent, or the id or wrap is malformed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "The account has no kit", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_replace() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/recovery-kit", tag = "recovery-kit",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses(
        (status = 204, description = "The kit is gone"),
        (status = 400, description = "The proof is wrong or spent", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "The account has no kit", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_remove() {}

#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_show, doc_create, doc_replace, doc_remove),
    components(schemas(CreateKitRequest, ReplaceKitRequest, KitDto))
)]
pub struct RecoveryKitApiDoc;
