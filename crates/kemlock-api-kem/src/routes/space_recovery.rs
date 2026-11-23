//! Account recovery enrolment of a space: `/kem/v1/spaces/{id}/members/{user}/recovery`
//! (docs/crypto.md, "Policies and recovery").
//!
//! ```text
//! PUT    /kem/v1/spaces/{id}/members/me/recovery        enrol: {"box", "keySeq"}, replacing any earlier box
//! DELETE /kem/v1/spaces/{id}/members/me/recovery        withdraw
//! GET    /kem/v1/spaces/{id}/members/{user}/recovery    an Owner or Admin gets {"box", "keySeq", "stale"}
//! ```
//!
//! The box is the member's 64-byte root key sealed under the `"account-recovery"` context, base64url,
//! with the aad `space id ‖ account id ‖ u64be(keySeq)`; `keySeq` is the `seq` of the chain record
//! that set the recovery key. `PUT` and `DELETE` are for the caller, so `{user}` is `me` or the
//! caller's own id. These routes need a store that keeps chains and boxes, so they have a router of
//! their own, merged beside the spaces router.

use crate::dto::decode;
use crate::extract::Body;
use crate::problem::Problem;
use crate::routes::spaces::{Caller, Env, nonce_header};
use crate::state::{Api, Crypto, Store};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Json, Router};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::{
    Recovered, RecoveryError, SpaceChainRepo, SpaceRecovery, SpaceRecoveryRepo, SpaceRepo,
};
use kemlock_app::{AppError, b64url};
use kemlock_domain::{SpaceId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{OpenApi, ToSchema};

fn space_id(text: &str) -> Result<SpaceId, Problem> {
    text.parse()
        .map_err(|_| Problem::bad_request("the space id isn't a UUID"))
}

/// A member in a path: an account id, or `me` for the caller.
fn member_ref(text: &str, me: UserId) -> Result<UserId, Problem> {
    if text == "me" {
        Ok(me)
    } else {
        text.parse()
            .map_err(|_| Problem::bad_request("the member id isn't a UUID"))
    }
}

// ---- wire types ----

/// What a member enrols.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnrolRecoveryRequest {
    /// The member's root key sealed under `"account-recovery"` to the chain's recovery key: 1693
    /// bytes starting with `u8(1)`, base64url.
    #[serde(rename = "box")]
    sealed: String,
    /// The `seq` of the chain record that set the recovery key the box is sealed to, and that is
    /// in the box's aad.
    key_seq: u64,
}

/// An enrolled box.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryBoxDto {
    /// The sealed box, base64url.
    #[serde(rename = "box")]
    sealed: String,
    /// The `seq` in the box's aad.
    key_seq: u64,
    /// The chain's recovery key is no longer the one the box was sealed to.
    stale: bool,
}

impl RecoveryBoxDto {
    fn of(found: &Recovered) -> Self {
        RecoveryBoxDto {
            sealed: b64url::encode(&found.sealed),
            key_seq: found.key_seq,
            stale: found.stale,
        }
    }
}

// ---- errors ----

impl From<RecoveryError> for Problem {
    fn from(e: RecoveryError) -> Self {
        match e {
            RecoveryError::NotFound => Problem::not_found(),
            RecoveryError::Forbidden => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(
                    "an Owner may recover any confirmed member, an Admin any but an Owner, and \
                     only a confirmed member enrols",
                )
            }
            RecoveryError::NotEnabled => Problem::new(
                StatusCode::CONFLICT,
                "recovery-not-enabled",
                "Account recovery isn't on for this space",
            )
            .detail("the space's chain has its accountRecovery policy off"),
            RecoveryError::Stale { current } => Problem::new(
                StatusCode::CONFLICT,
                "stale-recovery-key",
                "The recovery key has changed",
            )
            .detail("keySeq isn't the record that set the chain's current recovery key")
            .with("current", json!(current)),
            RecoveryError::Invalid(why) => Problem::bad_request(why),
            RecoveryError::Store(message) => Problem::from(AppError::Store(message)),
        }
    }
}

// ---- handlers ----

fn use_case<S, P, K, R>(env: &Env<S, P, K, R>) -> SpaceRecovery<R, S, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo + Clone + 'static,
{
    SpaceRecovery {
        spaces: env.spaces.clone(),
        events: env.api.store.clone(),
        clock: env.api.crypto.clone(),
    }
}

/// Only the caller enrols or withdraws their own box.
fn own(text: &str, me: UserId) -> Result<(), Problem> {
    if member_ref(text, me)? == me {
        Ok(())
    } else {
        Err(
            Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed")
                .detail("a member enrols or withdraws only their own recovery box"),
        )
    }
}

async fn enrol<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo + Clone + 'static,
{
    let actor = caller.actor();
    own(&user, actor.user)?;
    let request: EnrolRecoveryRequest = body.json()?;
    let sealed = decode("box", &request.sealed)?;
    use_case(&env)
        .enrol(&actor, space_id(&id)?, request.key_seq, sealed)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn withdraw<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo + Clone + 'static,
{
    let actor = caller.actor();
    own(&user, actor.user)?;
    use_case(&env).withdraw(&actor, space_id(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<Json<RecoveryBoxDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo + Clone + 'static,
{
    let actor = caller.actor();
    let found = use_case(&env)
        .fetch(&actor, space_id(&id)?, member_ref(&user, actor.user)?)
        .await?;
    Ok(Json(RecoveryBoxDto::of(&found)))
}

/// The routes of account recovery enrolment. Merge it beside [`crate::spaces_router`]; it has no
/// fallback.
pub fn router<S, P, K, R>(api: Api<S, P, K>, spaces: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + SpaceRecoveryRepo + Clone + 'static,
{
    let env = Env { api, spaces };
    Router::new()
        .route(
            "/kem/v1/spaces/{id}/members/{user}/recovery",
            get(fetch::<S, P, K, R>)
                .put(enrol::<S, P, K, R>)
                .delete(withdraw::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/members/{user}/recovery", tag = "space-recovery",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("user" = String, Path, description = "`me`, or the caller's own id: a member enrols only their own box"),
    ),
    request_body = EnrolRecoveryRequest,
    responses(
        (status = 204, description = "Stored, replacing any earlier box"),
        (status = 400, description = "The box isn't unpadded base64url, or isn't a 1693-byte sealed root key starting with u8(1)"),
        (status = 403, description = "The caller isn't a confirmed member, or {user} isn't the caller"),
        (status = 404, description = "No such space, or the caller isn't an invited or confirmed member"),
        (status = 409, description = "recovery-not-enabled: the chain's accountRecovery policy is off; stale-recovery-key: keySeq isn't the record that set the chain's current recovery key (the problem carries `current`)"),
    )
)]
#[allow(dead_code)]
fn doc_enrol() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/members/{user}/recovery", tag = "space-recovery",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("user" = String, Path, description = "`me`, or the caller's own id"),
    ),
    responses(
        (status = 204, description = "Withdrawn; also when there was no box"),
        (status = 403, description = "{user} isn't the caller"),
        (status = 404, description = "No such space, or the caller isn't an invited or confirmed member"),
    )
)]
#[allow(dead_code)]
fn doc_withdraw() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/members/{user}/recovery", tag = "space-recovery",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("user" = String, Path, description = "The member to recover: an account id"),
    ),
    responses(
        (status = 200, description = "The member's box, with `stale` true when the chain's recovery key has changed since", body = RecoveryBoxDto),
        (status = 403, description = "The caller isn't a confirmed Owner or Admin, or is an Admin asking for an Owner"),
        (status = 404, description = "No such space, the caller isn't in it, or the member isn't confirmed or hasn't enrolled"),
    )
)]
#[allow(dead_code)]
fn doc_fetch() {}

#[derive(OpenApi)]
#[openapi(
    paths(doc_enrol, doc_withdraw, doc_fetch),
    components(schemas(EnrolRecoveryRequest, RecoveryBoxDto))
)]
struct SpaceRecoveryDoc;

/// The OpenAPI document of the account recovery routes alone.
pub fn openapi() -> utoipa::openapi::OpenApi {
    SpaceRecoveryDoc::openapi()
}
