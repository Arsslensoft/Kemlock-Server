//! `PUT` and `GET /kem/v1/manifests/{owner}`: the signed manifest of an owner's items, where the
//! owner is the account (`user:<uuid>`) or one of its spaces (`space:<uuid>`).
//!
//! They need the space store beside the API's, to check who may write a space's manifest, so
//! they have a state of their own, like the item routes.

use super::contract::{ManifestRequest, ManifestResponse, manifest_problem, owner_param};
use super::contract_crypto::Sig1Manifests;
use super::spaces::{Caller, Env, nonce_header};
use crate::dto::decode;
use crate::extract::Body;
use crate::problem::Problem;
use crate::state::{Crypto, Store};
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router, middleware};
use kemlock_app::manifests::{
    GetManifest, ManifestRepo, PutManifest, PutManifestInput, SpaceMembers,
};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;

/// `PUT /kem/v1/manifests/{owner}`: stores the owner's signed manifest. The account's own, or a
/// space's when the account is a confirmed member with edit on one of its collections; the
/// counter must be above the one stored for that owner.
async fn put_manifest<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(owner): Path<String>,
    body: Body,
) -> Result<Json<ManifestResponse>, Problem>
where
    S: Store + ManifestRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let owner = owner_param(&owner)?;
    let request: ManifestRequest = body.json()?;
    let stored = PutManifest {
        manifests: env.api.store.clone(),
        users: env.api.store.clone(),
        verifier: Sig1Manifests,
        clock: env.api.crypto.clone(),
        access: SpaceMembers {
            spaces: env.spaces.clone(),
        },
    }
    .execute(
        &caller.actor(),
        PutManifestInput {
            owner,
            bytes: decode("manifest", &request.manifest)?,
            signature: decode("signature", &request.signature)?,
        },
    )
    .await
    .map_err(manifest_problem)?;
    Ok(Json(ManifestResponse::from_manifest(&stored)))
}

/// `GET /kem/v1/manifests/{owner}`: the latest stored manifest of the account, or of a space the
/// account is a confirmed member of.
async fn get_manifest<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(owner): Path<String>,
) -> Result<Json<ManifestResponse>, Problem>
where
    S: Store + ManifestRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let owner = owner_param(&owner)?;
    let stored = GetManifest {
        manifests: env.api.store.clone(),
        access: SpaceMembers {
            spaces: env.spaces.clone(),
        },
    }
    .execute(&caller.actor(), owner)
    .await?;
    Ok(Json(ManifestResponse::from_manifest(&stored)))
}

/// The manifest routes.
pub(crate) fn router<S, P, K, R>(env: Env<S, P, K, R>) -> Router
where
    S: Store + ManifestRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/manifests/{owner}",
            get(get_manifest::<S, P, K, R>).put(put_manifest::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}
