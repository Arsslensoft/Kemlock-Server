//! `GET /kem/v1/placement`: where each of the account's vaults lives, for the web vault's
//! failover banner and its "Where your vault is stored" page.
//!
//! A server that federates none of the account's vaults answers 404, which the web vault reads
//! as "a single server" and shows nothing for.
//!
//! `DELETE /kem/v1/placement/{vault}/pending/{change}` drops the changes of a vault that wait for
//! a server that is down (`change` is that server's id, as `pending.id` says). The vault is `me`,
//! or a space the caller is a confirmed owner or admin of. Nothing held here is deleted: the
//! changes stay in this server's copy and are only not sent to that server (`docs/federation.md`,
//! "Waiting changes"). It answers 409 while the server answers its probes.

use super::spaces::{Caller, Env, nonce_header};
use super::view::MaybeView;
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Crypto, Store};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router, middleware};
use kemlock_app::federation_view::{CancelOutcome, ResumeOutcome};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::{AppError, Placement, ReadPlacement};
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::{Owner, ServerId, SpaceId};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlacementServerDto {
    /// The server's id.
    id: String,
    /// The host of its address.
    name: String,
    /// What the descriptor doesn't carry: always `null` for now.
    place: Option<String>,
    /// `home` or `replica`.
    role: &'static str,
    /// `online`, `degraded`, `offline` or `unknown` (not probed yet), from this server's probes of
    /// the peer. This server itself is always `online`.
    status: &'static str,
    /// When the peer started failing its probes, while it is `offline`.
    offline_since: Option<String>,
    /// When the peer last answered.
    last_seen: Option<String>,
    /// How long its last answer took, in milliseconds.
    latency_ms: Option<u64>,
    /// The apps of this vault are on it right now.
    in_use: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlacementVaultDto {
    /// `me`, or the space's id.
    id: String,
    name: String,
    /// Home first, then the replicas in order.
    servers: Vec<PlacementServerDto>,
    /// Changes of this vault that haven't reached a server that holds it, the ones waiting for a
    /// server that is down first; `null` when none wait.
    pending: Option<PlacementPendingDto>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlacementPendingDto {
    /// The id of the server they wait for: what `DELETE .../pending/{change}` takes.
    id: String,
    /// What waits, in words.
    summary: String,
    /// When the oldest was written.
    asked_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlacementAppDto {
    name: String,
    /// The server it uses now, by name.
    server: String,
    since: Option<String>,
    /// A Bitwarden-compatible app, which stays on its address.
    local_copy: bool,
    address: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlacementDto {
    vaults: Vec<PlacementVaultDto>,
    apps: Vec<PlacementAppDto>,
}

/// A time as the web vault reads it.
fn iso(secs: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(secs).ok()?)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// "3 changes waiting for vps.example.net", "100+ changes ...", "1 change ...".
fn waiting_summary(changes: u64, at_least: bool, server: &str) -> String {
    let count = if at_least {
        format!("{changes}+ changes")
    } else if changes == 1 {
        "1 change".to_owned()
    } else {
        format!("{changes} changes")
    };
    format!("{count} waiting for {server}")
}

impl PlacementDto {
    fn from_app(placement: Placement) -> Self {
        PlacementDto {
            vaults: placement
                .vaults
                .into_iter()
                .map(|vault| PlacementVaultDto {
                    id: vault.id,
                    name: vault.name,
                    servers: vault
                        .servers
                        .into_iter()
                        .map(|server| PlacementServerDto {
                            id: server.id,
                            name: server.name,
                            place: None,
                            role: server.role.as_str(),
                            status: server.health.status.as_str(),
                            offline_since: server.health.offline_since.and_then(iso),
                            last_seen: server.health.last_seen.and_then(iso),
                            latency_ms: server.health.latency_ms,
                            in_use: server.in_use,
                        })
                        .collect(),
                    pending: vault.pending.map(|p| PlacementPendingDto {
                        id: p.peer.to_string(),
                        summary: waiting_summary(p.changes, p.at_least, &p.peer_name),
                        asked_at: p.oldest_at.and_then(iso),
                    }),
                })
                .collect(),
            apps: placement
                .apps
                .into_iter()
                .map(|app| PlacementAppDto {
                    name: app.name,
                    server: app.server,
                    since: None,
                    local_copy: app.local_copy,
                    address: app.address,
                })
                .collect(),
        }
    }
}

/// `GET /kem/v1/placement`.
async fn get_placement<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    MaybeView(view): MaybeView,
) -> Result<Json<PlacementDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let view = view.ok_or_else(Problem::not_found)?;
    let read = ReadPlacement {
        devices: env.api.store.clone(),
        spaces: env.spaces.clone(),
    };
    let placement = read
        .execute(caller.actor().user, view.as_ref(), &env.api.config.domain)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(Json(PlacementDto::from_app(placement)))
}

/// What dropping the waiting changes did.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelledDto {
    /// How many waiting changes will not be sent to that server, counted to a limit.
    dropped: u64,
}

/// The vault a path names: `me`, or a space the caller is a confirmed owner or admin of.
async fn vault_of<S, P, K, R>(
    env: &Env<S, P, K, R>,
    user: kemlock_domain::UserId,
    vault: &str,
) -> Result<Owner, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    if vault == "me" {
        return Ok(Owner::User(user));
    }
    let space: SpaceId = vault
        .parse()
        .map_err(|_| Problem::bad_request("the vault is `me` or a space id"))?;
    let member = env
        .spaces
        .memberships(user)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?
        .into_iter()
        .find(|m| m.space == space && m.is_confirmed())
        .ok_or_else(Problem::not_found)?;
    if !matches!(member.role, SpaceRole::Owner | SpaceRole::Admin) {
        return Err(Problem::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Only a space's owners and admins may change its waiting changes",
        ));
    }
    Ok(Owner::Space(space))
}

fn server_of(change: &str) -> Result<ServerId, Problem> {
    change
        .parse::<uuid::Uuid>()
        .map(ServerId)
        .map_err(|_| Problem::bad_request("the change is the id of the server it waits for"))
}

/// What taking back a cancel did.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResumedDto {
    /// The withheld changes are offered to that server again, at the next comparison of the two
    /// copies of the vault.
    resumed: bool,
}

/// `POST /kem/v1/placement/{vault}/pending/{change}/resume`: offers the changes a cancel withheld
/// from that server again. Nothing is lost by a cancel, so this restores what it kept back.
async fn resume_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    MaybeView(view): MaybeView,
    Path((vault, change)): Path<(String, String)>,
) -> Result<Json<ResumedDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let view = view.ok_or_else(Problem::not_found)?;
    let user = caller.actor().user;
    let owner = vault_of(&env, user, &vault).await?;
    let peer = server_of(&change)?;
    match view
        .resume_waiting(owner, peer, user)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?
    {
        ResumeOutcome::Resumed => Ok(Json(ResumedDto { resumed: true })),
        ResumeOutcome::NothingHeld | ResumeOutcome::Unknown => Err(Problem::not_found()),
    }
}

/// `DELETE /kem/v1/placement/{vault}/pending/{change}`.
async fn cancel_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    MaybeView(view): MaybeView,
    Path((vault, change)): Path<(String, String)>,
) -> Result<Json<CancelledDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let view = view.ok_or_else(Problem::not_found)?;
    let user = caller.actor().user;
    let owner = vault_of(&env, user, &vault).await?;
    let peer = server_of(&change)?;
    match view
        .cancel_waiting(owner, peer, user)
        .await
        .map_err(|e| Problem::from(AppError::from(e)))?
    {
        CancelOutcome::Cancelled { dropped } => Ok(Json(CancelledDto { dropped })),
        CancelOutcome::NothingWaiting | CancelOutcome::Unknown => Err(Problem::not_found()),
        CancelOutcome::NotOffline => Err(Problem::new(
            StatusCode::CONFLICT,
            "server-answering",
            "That server is answering, so its changes are on their way",
        )),
    }
}

/// The placement routes.
pub(crate) fn router<S, P, K, R>(env: Env<S, P, K, R>) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    Router::new()
        .route("/kem/v1/placement", get(get_placement::<S, P, K, R>))
        .route(
            "/kem/v1/placement/{vault}/pending/{change}",
            delete(cancel_pending::<S, P, K, R>),
        )
        .route(
            "/kem/v1/placement/{vault}/pending/{change}/resume",
            post(resume_pending::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---------------------------------------------------------------------------------------------
// OpenAPI.

#[utoipa::path(
    get, path = "/kem/v1/placement", tag = "failover",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The servers that hold each of the account's federated vaults (the home first), and the apps that use this server", body = PlacementDto),
        (status = 404, description = "None of the account's vaults is federated here: a single server", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_placement() {}

#[utoipa::path(
    delete, path = "/kem/v1/placement/{vault}/pending/{change}", tag = "failover",
    security(("dpop" = [])),
    params(
        ("vault" = String, Path, description = "`me` or a space id"),
        ("change" = String, Path, description = "The id of the server the changes wait for, as `pending.id` says"),
    ),
    responses(
        (status = 200, description = "The queued push to that server was dropped; nothing held here was deleted", body = CancelledDto),
        (status = 403, description = "The vault is a space, and the caller is not one of its owners or admins", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "Nothing waits for that server, or the vault isn't federated with it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "That server is answering its probes: only changes queued for a server that is down can be dropped", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_cancel_pending() {}

#[utoipa::path(
    post, path = "/kem/v1/placement/{vault}/pending/{change}/resume", tag = "failover",
    security(("dpop" = [])),
    params(
        ("vault" = String, Path, description = "`me` or a space id"),
        ("change" = String, Path, description = "The id of the server whose changes were withheld"),
    ),
    responses(
        (status = 200, description = "The withheld changes are offered to that server again", body = ResumedDto),
        (status = 403, description = "The vault is a space, and the caller is not one of its owners or admins", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "Nothing is withheld from that server, or the vault isn't federated with it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_resume_pending() {}

#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_placement, doc_cancel_pending, doc_resume_pending),
    components(schemas(
        PlacementDto,
        PlacementVaultDto,
        PlacementServerDto,
        PlacementPendingDto,
        CancelledDto,
        ResumedDto,
        PlacementAppDto
    ))
)]
struct PlacementDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    PlacementDoc::openapi()
}
