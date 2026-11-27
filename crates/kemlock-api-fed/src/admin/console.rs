//! The admin routes the web vault's federation screens need beyond the rows: the vaults that may
//! be federated, reaching every peer or comparing hash trees now, a peer's keys and descriptor,
//! this server's own keys and suites, and a peer that offered an identity key other than the
//! pinned one.
//!
//! Every route asks the admin gate first. Every write (POST and PUT) also needs a step-up token the
//! gate accepted ([`AdminActor::step_up`](super::AdminActor)); without one it answers 403
//! `step-up-required`.
//!
//! What a server cannot know it does not say. A vault's name is ciphertext under a key only its
//! members hold, so a vault is named by its owner's email (an account's vault) and a space has
//! none; a peer's country and database are not in its descriptor, so a peer has none.

use super::{
    Admin, AdminState, ApiError, KeyChangeDto, ServerDto, host_of, key_change_dto, parse_server,
    peer_target, require_step_up,
};
use crate::routes::DESCRIPTOR_MEDIA_TYPE;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use kemlock_app::b64url;
use kemlock_domain::{Owner, ServerId};
use kemlock_federation::descriptor::KEM_ROTATION_SECS;
use kemlock_federation::insight::VaultInfo;
use kemlock_federation::{
    Connector, FedError, FedStore, Leases, MismatchView, PausedVault, PeerCheck, PeerConsistency,
    PeerSecurityView, SelfView, Suite, unix_now,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ---------------------------------------------------------------------------------------------
// Bodies and answers.

/// A vault an admin may federate.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ShareableDto {
    /// `user:<uuid>` or `space:<uuid>`.
    #[schema(value_type = String)]
    vault: Owner,
    /// The owner's email address, for an account's vault. A vault's name is ciphertext only its
    /// members can read, so the server has none to give; a space has no email either, and the
    /// console shows its short id.
    owner_email: Option<String>,
    /// People who can open the vault.
    members: u64,
    /// What the vault takes here in bytes: stored items and ready attachments.
    size_bytes: u64,
}

fn shareable_dto(info: &VaultInfo) -> ShareableDto {
    ShareableDto {
        vault: info.vault,
        owner_email: info.owner_email.clone(),
        members: info.members,
        size_bytes: info.size_bytes,
    }
}

/// How a visit to one peer went.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PeerCheckDto {
    #[schema(value_type = String)]
    peer: ServerId,
    /// `reached`, `busy`, `not-paired`, `nothing-shared`, `key-mismatch` or `unreachable`.
    reach: &'static str,
    /// Why the peer could not be reached.
    detail: Option<String>,
}

fn check_dto(check: &PeerCheck) -> PeerCheckDto {
    PeerCheckDto {
        peer: check.peer,
        reach: check.reach.as_str(),
        detail: check.detail.clone(),
    }
}

/// One vault's hash trees, compared with a peer's.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ComparisonDto {
    #[schema(value_type = String)]
    vault: Owner,
    /// The roots matched. Null when the comparison did not run.
    in_step: Option<bool>,
    detail: Option<String>,
}

/// What comparing hash trees with one peer found.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConsistencyDto {
    #[schema(value_type = String)]
    peer: ServerId,
    reach: &'static str,
    vaults: Vec<ComparisonDto>,
    detail: Option<String>,
}

fn consistency_dto(entry: &PeerConsistency) -> ConsistencyDto {
    ConsistencyDto {
        peer: entry.peer,
        reach: entry.reach.as_str(),
        vaults: entry
            .vaults
            .iter()
            .map(|v| ComparisonDto {
                vault: v.vault,
                in_step: v.in_step,
                detail: v.detail.clone(),
            })
            .collect(),
        detail: entry.detail.clone(),
    }
}

/// What a peer's descriptor says.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DescriptorDto {
    /// The identity key in the descriptor, hex.
    identity_key: String,
    operator: String,
    addresses: Vec<String>,
    not_before: u64,
    not_after: u64,
}

/// A peer's KEM key.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KemDto {
    algorithm: &'static str,
    /// When this server first saw the key. A KEM key's creation time is not in the descriptor, so
    /// this is the nearest the server can say of its age.
    first_seen_at: Option<u64>,
    /// 30 days after it was first seen.
    next_rotation_at: Option<u64>,
    /// First 8 bytes of SHA-256 of the key, as four groups of hex.
    fingerprint: String,
}

/// One suite in the two servers' lists.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SuiteRowDto {
    name: String,
    /// Its place in the peer's list, from 1.
    theirs: Option<u32>,
    /// Its place in this server's list, from 1.
    ours: Option<u32>,
    /// The suite a session between the two would use.
    in_use: bool,
}

/// What is known of a peer's keys and descriptor.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PeerSecurityDto {
    #[schema(value_type = String)]
    peer_id: ServerId,
    operator: String,
    /// The descriptor's identity key is the pinned one and no run met another.
    keys_match: bool,
    /// The descriptor's signature holds and it is inside its window.
    signature_ok: bool,
    /// When the descriptor shown was read from the peer, Unix seconds.
    fetched_at: Option<u64>,
    /// Why a fresh read failed, when an older copy is shown instead.
    fetch_error: Option<String>,
    descriptor: Option<DescriptorDto>,
    kem: Option<KemDto>,
    suites: Vec<SuiteRowDto>,
    /// The last session that opened with the peer, Unix seconds.
    last_handshake_at: Option<u64>,
}

fn security_dto(view: &PeerSecurityView) -> PeerSecurityDto {
    PeerSecurityDto {
        peer_id: view.peer.id,
        operator: view.peer.operator.clone(),
        keys_match: view.keys_match,
        signature_ok: view.signature_ok,
        fetched_at: view.fetched_at,
        fetch_error: view.fetch_error.clone(),
        descriptor: view.descriptor.as_ref().map(|d| DescriptorDto {
            identity_key: hex::encode(d.identity_key.as_bytes()),
            operator: d.operator.clone(),
            addresses: d.addresses.clone(),
            not_before: d.not_before,
            not_after: d.not_after,
        }),
        kem: view.kem_fingerprint.as_ref().map(|fingerprint| KemDto {
            algorithm: "ML-KEM-1024 + X25519",
            first_seen_at: view.kem_first_seen,
            next_rotation_at: view
                .kem_first_seen
                .map(|t| t.saturating_add(KEM_ROTATION_SECS)),
            fingerprint: fingerprint.clone(),
        }),
        suites: view
            .suites
            .iter()
            .map(|s| SuiteRowDto {
                name: s.name.clone(),
                theirs: s.theirs,
                ours: s.ours,
                in_use: s.in_use,
            })
            .collect(),
        last_handshake_at: view.last_handshake_at,
    }
}

/// One suite of this server's setting.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SuiteSettingDto {
    name: &'static str,
    on: bool,
    /// This build can run it.
    available: bool,
}

/// This server's own federation identity.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SelfDto {
    server: ServerDto,
    /// First 16 bytes of SHA-256 of the identity key, as eight groups of hex.
    identity_fingerprint: String,
    /// The signed descriptor this server publishes, base64url.
    descriptor: String,
    valid_from: u64,
    valid_to: u64,
    /// When the current KEM key was made, if the server knows.
    kem_made_at: Option<u64>,
    kem_next_rotation_at: Option<u64>,
    /// In this server's order, most preferred first; the ones left off follow.
    suites: Vec<SuiteSettingDto>,
}

fn self_dto(view: &SelfView) -> SelfDto {
    SelfDto {
        server: ServerDto {
            server_id: view.server,
            name: view
                .profile
                .name
                .clone()
                .unwrap_or_else(|| host_of(view.addresses.first().map_or("", String::as_str))),
            operator: view.operator.clone(),
            addresses: view.addresses.clone(),
            identity_key: hex::encode(&view.identity_key),
            descriptor_not_after: view.valid_to,
            database: view.profile.database.clone(),
            country: view.profile.country.clone(),
        },
        identity_fingerprint: view.identity_fingerprint.clone(),
        descriptor: b64url::encode(&view.descriptor),
        valid_from: view.valid_from,
        valid_to: view.valid_to,
        kem_made_at: view.kem_made_at,
        kem_next_rotation_at: view.kem_next_rotation_at,
        suites: view
            .suites
            .iter()
            .map(|s| SuiteSettingDto {
                name: s.suite.name(),
                on: s.on,
                available: s.available,
            })
            .collect(),
    }
}

/// One suite the admin turns on or off; the order of the list is the preference.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SuiteChoice {
    name: String,
    on: bool,
}

/// `PUT /self/suites`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SuitesBody {
    suites: Vec<SuiteChoice>,
    /// `sealed` (the only way this server keeps its keys) or left out.
    key_holding: Option<String>,
}

/// A vault paused by a mismatch.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PausedDto {
    #[schema(value_type = String)]
    vault: Owner,
    owner_email: Option<String>,
    members: Option<u64>,
    size_bytes: Option<u64>,
    waiting_changes: u64,
}

fn paused_dto(paused: &PausedVault) -> PausedDto {
    PausedDto {
        vault: paused.vault,
        owner_email: paused.info.as_ref().and_then(|i| i.owner_email.clone()),
        members: paused.info.as_ref().map(|i| i.members),
        size_bytes: paused.info.as_ref().map(|i| i.size_bytes),
        waiting_changes: paused.waiting.changes,
    }
}

/// A peer that offered an identity key other than the pinned one.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct MismatchDto {
    #[schema(value_type = String)]
    peer_id: ServerId,
    /// The pinned `sig1` identity key, hex, and when it was pinned.
    pinned_key: String,
    pinned_at: u64,
    /// The key the peer offered, hex, and when it was first and last offered.
    offered_key: String,
    first_offered_at: u64,
    last_attempt_at: u64,
    /// Connection attempts that met the key.
    attempts: u64,
    /// The address this server dialled when it met the key. The key is only ever met by this
    /// server dialling the peer: a session the peer opens to this server is refused before it says
    /// which peer it is.
    from_address: String,
    from_host: String,
    /// The addresses the peer is known by.
    usual_addresses: Vec<String>,
    /// The address is `https`, so the descriptor came over a verified TLS connection.
    tls_valid: bool,
    /// Always false while a mismatch stands: a rotation the pinned key signed would have been
    /// accepted and would have cleared it.
    signed_by_pinned: bool,
    /// The key was offered before the latest attempt.
    seen_before: bool,
    /// When an admin chose to keep blocking, and who.
    kept_blocking_at: Option<u64>,
    kept_blocking_by: Option<String>,
    /// The vaults shared with the peer, which cannot sync while the mismatch stands.
    paused_vaults: Vec<PausedDto>,
    /// Vaults homed here and not federated: they are not affected.
    local_vaults: u64,
}

fn mismatch_dto(view: &MismatchView) -> MismatchDto {
    let record = &view.record;
    MismatchDto {
        peer_id: view.peer.id,
        pinned_key: hex::encode(&view.pinned_key),
        pinned_at: view.pinned_at,
        offered_key: hex::encode(&record.offered_key),
        first_offered_at: record.first_at,
        last_attempt_at: record.last_at,
        attempts: record.attempts,
        from_address: record.source.clone(),
        from_host: host_of(&record.source),
        usual_addresses: view.usual_addresses.clone(),
        tls_valid: record.source.starts_with("https://"),
        signed_by_pinned: false,
        seen_before: view.seen_before,
        kept_blocking_at: record.kept_blocking_at,
        kept_blocking_by: record.kept_blocking_by.clone(),
        paused_vaults: view.paused.iter().map(paused_dto).collect(),
        local_vaults: view.local_vaults,
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers.

fn not_found(detail: &str) -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not-found",
        "Not found",
        Some(detail.to_owned()),
    )
}

async fn shareable<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<ShareableDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .shareable()
            .await?
            .iter()
            .map(shareable_dto)
            .collect(),
    ))
}

async fn check<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<Vec<PeerCheckDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(&actor, "federation.admin.check", None)
        .await;
    Ok(Json(
        state
            .federation
            .check(unix_now())
            .await?
            .iter()
            .map(check_dto)
            .collect(),
    ))
}

async fn consistency<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<Vec<ConsistencyDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(&actor, "federation.admin.consistency", None)
        .await;
    Ok(Json(
        state
            .federation
            .consistency(unix_now())
            .await?
            .iter()
            .map(consistency_dto)
            .collect(),
    ))
}

async fn peer_security<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
    Path(id): Path<String>,
) -> Result<Json<PeerSecurityDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let view = state
        .federation
        .peer_security(parse_server(&id)?, unix_now())
        .await?;
    Ok(Json(security_dto(&view)))
}

async fn peer_descriptor<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
    Path(id): Path<String>,
) -> Result<Response, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let id = parse_server(&id)?;
    let view = state.federation.peer_security(id, unix_now()).await?;
    let bytes = view
        .descriptor_bytes
        .ok_or_else(|| not_found("no descriptor of this peer has been read yet"))?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, DESCRIPTOR_MEDIA_TYPE.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"descriptor-{}.cbor\"", id.0),
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn self_security<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<SelfDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(self_dto(&state.federation.self_view())))
}

async fn rotate_kem<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<SelfDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(&actor, "federation.admin.kem_rotate", None)
        .await;
    Ok(Json(self_dto(&state.federation.rotate_kem(unix_now())?)))
}

async fn rotate_identity<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<KeyChangeDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(&actor, "federation.admin.identity_rotate", None)
        .await;
    let change = state.federation.rotate_identity(unix_now()).await?;
    Ok(Json(key_change_dto(change)))
}

async fn choose_suites<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    body: Bytes,
) -> Result<Json<SelfDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(&actor, "federation.admin.suites", None)
        .await;
    let request: SuitesBody = super::parse_body(&body)?;
    if request
        .key_holding
        .as_deref()
        .is_some_and(|h| h != "sealed")
    {
        return Err(FedError::Refused("this server keeps its keys sealed under server.key").into());
    }
    let mut suites = Vec::new();
    for choice in request.suites.iter().filter(|c| c.on) {
        suites.push(
            Suite::from_name(&choice.name).ok_or_else(|| ApiError::bad("a suite is not known"))?,
        );
    }
    Ok(Json(self_dto(
        &state.federation.choose_suites(&suites, unix_now())?,
    )))
}

async fn mismatch<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
    Path(peer): Path<String>,
) -> Result<Json<MismatchDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let view = state
        .federation
        .mismatch(parse_server(&peer)?, unix_now())
        .await?
        .ok_or_else(|| not_found("no key mismatch is on record for this peer"))?;
    Ok(Json(mismatch_dto(&view)))
}

async fn keep_blocking<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(peer): Path<String>,
) -> Result<Json<MismatchDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state
        .gate
        .audit(
            &actor,
            "federation.admin.mismatch_keep_blocking",
            peer_target(&peer),
        )
        .await;
    let peer = parse_server(&peer)?;
    let now = unix_now();
    state
        .federation
        .keep_blocking(peer, &actor.user.to_string(), now)
        .await
        .map_err(|e| match e {
            FedError::UnknownPeer => not_found("no key mismatch is on record for this peer"),
            other => other.into(),
        })?;
    let view = state
        .federation
        .mismatch(peer, now)
        .await?
        .ok_or_else(|| not_found("no key mismatch is on record for this peer"))?;
    Ok(Json(mismatch_dto(&view)))
}

/// The routes of this module, merged into the admin router before its state is set.
pub(super) fn routes<S, C>() -> Router<AdminState<S, C>>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    const BASE: &str = "/admin/v1/federation";
    Router::new()
        .route(&format!("{BASE}/shareable"), get(shareable::<S, C>))
        .route(&format!("{BASE}/check"), post(check::<S, C>))
        .route(&format!("{BASE}/consistency"), post(consistency::<S, C>))
        .route(
            &format!("{BASE}/peers/{{id}}/security"),
            get(peer_security::<S, C>),
        )
        .route(
            &format!("{BASE}/peers/{{id}}/descriptor"),
            get(peer_descriptor::<S, C>),
        )
        .route(&format!("{BASE}/self"), get(self_security::<S, C>))
        .route(
            &format!("{BASE}/self/kem-rotation"),
            post(rotate_kem::<S, C>),
        )
        .route(
            &format!("{BASE}/self/identity-rotation"),
            post(rotate_identity::<S, C>),
        )
        .route(&format!("{BASE}/self/suites"), put(choose_suites::<S, C>))
        .route(
            &format!("{BASE}/mismatches/{{peer}}"),
            get(mismatch::<S, C>),
        )
        .route(
            &format!("{BASE}/mismatches/{{peer}}/keep-blocking"),
            post(keep_blocking::<S, C>),
        )
}
