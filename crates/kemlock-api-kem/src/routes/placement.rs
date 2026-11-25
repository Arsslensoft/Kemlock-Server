//! `GET /kem/v1/placement`: where each of the account's vaults lives, for the web vault's
//! failover banner and its "Where your vault is stored" page.
//!
//! A server that federates none of the account's vaults answers 404, which the web vault reads
//! as "a single server" and shows nothing for. `DELETE .../pending/{change}` is routed so the
//! web vault's cancel button gets a clean 404: the server keeps no waiting changes per vault yet.

use super::spaces::{Caller, Env, nonce_header};
use super::view::MaybeView;
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Crypto, Store};
use axum::extract::State;
use axum::routing::{delete, get};
use axum::{Json, Router, middleware};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::{Placement, ReadPlacement};
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

/// `DELETE /kem/v1/placement/{vault}/pending/{change}`: there is never a waiting change to
/// cancel yet.
async fn cancel_pending<S, P, K, R>(
    State(_env): State<Env<S, P, K, R>>,
    _caller: Caller,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    Err(Problem::not_found())
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
        ("change" = String, Path, description = "The waiting change's id"),
    ),
    responses(
        (status = 404, description = "The server keeps no waiting changes per vault yet", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_cancel_pending() {}

#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_placement, doc_cancel_pending),
    components(schemas(
        PlacementDto,
        PlacementVaultDto,
        PlacementServerDto,
        PlacementPendingDto,
        PlacementAppDto
    ))
)]
struct PlacementDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    PlacementDoc::openapi()
}
