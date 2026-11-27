//! The admin routes of federation, `/admin/v1/federation`: pairing with a one-time code and a
//! fingerprint, the peer list and its health, the two event-log switches, revoking a peer, each
//! vault's policy and replica order, consent to a vault a home offers, quarantined home records
//! and promotion.
//!
//! The routes are thin: each calls [`Federation`] and maps its answer to JSON. Who may call them is
//! the server's business, so every handler asks an [`AdminGate`] first; `kemlock-server` provides
//! one that checks the Kemlock API's access token and the admin role. Promotion also needs the
//! gate's `fresh` flag (a passkey or password check just passed), which the gate decides. Every
//! write needs a step-up token (the `Step-Up-Token` header), as the writes of `/admin/v1` do.
//!
//! Errors are RFC 9457 `application/problem+json`, with `type` `urn:kemlock:problem:<slug>`.

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use kemlock_app::b64url;
use kemlock_app::federation_view::BoxFut;
use kemlock_domain::{Owner, ServerId, UserId};
use kemlock_federation::extra::{Acknowledgement, StoredOffer};
use kemlock_federation::home::{Policy, VaultFederation};
use kemlock_federation::hub::{AwaitingPeer, Confirmation, Side};
use kemlock_federation::job::{PeerStatus, VaultStatus};
use kemlock_federation::ports::{LogSwitches, StoredHomeRecord};
use kemlock_federation::{
    Connector, FedError, FedStore, Federation, KeyChange, Leases, PeerView, UnpairReport,
    VaultView, unix_now,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

mod console;
mod openapi;

pub use openapi::openapi as admin_openapi;

/// Why the gate turned a request away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateRefusal {
    pub status: StatusCode,
    pub detail: &'static str,
}

/// The admin a request is from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminActor {
    pub user: UserId,
    /// The admin just passed a passkey, password or sign-in check. What counts is the gate's call;
    /// promotion and replacing the identity key accept it.
    pub fresh: bool,
    /// The request carries a step-up token the gate accepted: made for this admin and device in the
    /// last few minutes (see `/admin/v1/step-up`). Every new write needs it, and it stands in for
    /// `fresh` where that is asked.
    pub step_up: bool,
}

/// Decides who may use the admin routes.
pub trait AdminGate: Send + Sync {
    fn authorize<'a>(&'a self, parts: &'a Parts) -> BoxFut<'a, Result<AdminActor, GateRefusal>>;
}

/// The state of the admin routes. Cloning shares everything.
pub struct AdminState<S, C> {
    pub federation: Federation<S, C>,
    pub gate: Arc<dyn AdminGate>,
}

impl<S, C> Clone for AdminState<S, C> {
    fn clone(&self) -> Self {
        AdminState {
            federation: self.federation.clone(),
            gate: self.gate.clone(),
        }
    }
}

impl<S, C> std::fmt::Debug for AdminState<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// Errors.

/// A problem answer.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    slug: &'static str,
    title: &'static str,
    detail: Option<String>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        slug: &'static str,
        title: &'static str,
        detail: Option<String>,
    ) -> ApiError {
        ApiError {
            status,
            slug,
            title,
            detail,
        }
    }

    fn bad(detail: &str) -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "The request can't be read",
            Some(detail.to_owned()),
        )
    }

    fn body(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "type": format!("urn:kemlock:problem:{}", self.slug),
            "title": self.title,
            "status": self.status.as_u16(),
        });
        if let (Some(detail), Some(map)) = (&self.detail, body.as_object_mut()) {
            map.insert(
                "detail".to_owned(),
                serde_json::Value::String(detail.clone()),
            );
        }
        body
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            self.body().to_string(),
        )
            .into_response()
    }
}

impl From<GateRefusal> for ApiError {
    fn from(refusal: GateRefusal) -> ApiError {
        let (slug, title) = if refusal.status == StatusCode::UNAUTHORIZED {
            ("unauthorized", "Authentication is required")
        } else {
            ("forbidden", "Not allowed")
        };
        ApiError::new(refusal.status, slug, title, Some(refusal.detail.to_owned()))
    }
}

impl From<FedError> for ApiError {
    fn from(error: FedError) -> ApiError {
        match error {
            FedError::Pairing => ApiError::new(
                StatusCode::BAD_REQUEST,
                "pairing-failed",
                "Pairing failed",
                None,
            ),
            FedError::UnknownPeer | FedError::UnknownVault => {
                ApiError::new(StatusCode::NOT_FOUND, "not-found", "Not found", None)
            }
            FedError::Refused(why) => ApiError::new(
                StatusCode::CONFLICT,
                "refused",
                "Refused",
                Some(why.to_owned()),
            ),
            FedError::Malformed(why) | FedError::Invalid(why) => ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad-request",
                "The request can't be read",
                Some(why.to_owned()),
            ),
            FedError::KeyMismatch { .. } => ApiError::new(
                StatusCode::CONFLICT,
                "key-mismatch",
                "The peer's identity key is not the pinned one",
                None,
            ),
            FedError::Remote(_) | FedError::Expired(_) | FedError::NoCommonSuite => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "peer-unavailable",
                "The peer could not be used",
                None,
            ),
            other => {
                tracing::warn!(error = %other, "a federation admin call failed");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Something went wrong",
                    None,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The gate as an extractor.

struct Admin(AdminActor);

impl<S, C> FromRequestParts<AdminState<S, C>> for Admin
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState<S, C>,
    ) -> Result<Admin, ApiError> {
        let actor = state.gate.authorize(&*parts).await?;
        Ok(Admin(actor))
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing.

/// `user:<uuid>` or `space:<uuid>`.
pub fn parse_owner(text: &str) -> Result<Owner, ApiError> {
    text.parse::<Owner>().map_err(ApiError::bad)
}

fn parse_server(text: &str) -> Result<ServerId, ApiError> {
    uuid::Uuid::parse_str(text)
        .map(ServerId)
        .map_err(|_| ApiError::bad("a server id is a UUID"))
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::bad("the body is not the JSON expected"))
}

// ---------------------------------------------------------------------------------------------
// Bodies and answers.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartPairingBody {
    address: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcknowledgementBody {
    metadata: bool,
    deletion: bool,
    cross_border: bool,
    by: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmBody {
    fingerprint_matches: bool,
    acknowledgement: Option<AcknowledgementBody>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogsBody {
    send: bool,
    pull: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyBody {
    /// `"local"` or `"federated"`.
    policy: String,
    #[serde(default)]
    replicas: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct CodeDto {
    code: String,
    expires_at: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ServerDto {
    #[schema(value_type = String)]
    server_id: ServerId,
    /// The name of the server, or the host of its first address.
    name: String,
    operator: String,
    addresses: Vec<String>,
    /// The `sig1` identity key, hex.
    identity_key: String,
    descriptor_not_after: u64,
    /// The kind of database, when the process that runs the server says.
    database: Option<String>,
    /// The country the server runs in, when the process that runs the server says.
    country: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AwaitingDto {
    #[schema(value_type = String)]
    peer_id: ServerId,
    operator: String,
    addresses: Vec<String>,
    /// The six words both admins compare.
    fingerprint: Vec<String>,
    /// The peer's operator isn't this server's: the three acknowledgements are needed.
    other_organisation: bool,
    /// The peer's `sig1` identity key from its descriptor, hex: what this pairing would pin.
    identity_key: String,
    /// `"typed"` when the admin here typed the code, `"showed"` when they showed it.
    side: &'static str,
    since: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct AckDto {
    metadata: bool,
    deletion: bool,
    cross_border: bool,
    by: String,
    at: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct SwitchesDto {
    send: bool,
    pull: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct PulledDto {
    applied: usize,
    siblings: usize,
    duplicates: usize,
    refused: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct VaultStatusDto {
    #[schema(value_type = String)]
    vault: Owner,
    at: u64,
    offer: Option<&'static str>,
    pulled: PulledDto,
    home_applied: usize,
    home_quarantined: usize,
    behind: bool,
    files_fetched: usize,
    files_deferred: usize,
    events_pulled: usize,
    tags_pulled: usize,
    in_step: Option<bool>,
    note: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct StatusDto {
    last_attempt: Option<u64>,
    last_success: Option<u64>,
    down_since: Option<u64>,
    last_error: Option<String>,
    /// Hex of the identity key a peer offered that wasn't the pinned one: "Possible man in the
    /// middle".
    key_mismatch: Option<String>,
    vaults: Vec<VaultStatusDto>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct PeerDto {
    #[schema(value_type = String)]
    id: ServerId,
    /// The host of its first address: a descriptor carries no name.
    name: String,
    operator: String,
    addresses: Vec<String>,
    state: &'static str,
    /// The pinned `sig1` identity key, hex.
    identity_key: String,
    paired_at: u64,
    /// When the peer last answered this server: a session or a probe, whichever was later. Unix
    /// seconds.
    last_seen: Option<u64>,
    /// Whether the peer answers, as this server's probes found: `unknown` (not probed yet),
    /// `online`, `degraded` (slow, or a probe or two failed) or `offline`.
    health: &'static str,
    /// How long the peer's last answer took, in milliseconds.
    latency_ms: Option<u64>,
    /// Why the last probe failed, until one answers.
    probe_error: Option<String>,
    /// Since when the probes have been failing, Unix seconds.
    failing_since: Option<u64>,
    fingerprint: Vec<String>,
    switches: SwitchesDto,
    acknowledgement: Option<AckDto>,
    status: Option<StatusDto>,
    /// Versions this server holds that the peer may still be waiting for, counted to a limit.
    lag_changes: u64,
    /// The age of the oldest of those versions in seconds; none when no vault is shared.
    lag_seconds: Option<u64>,
    /// When the peer last wrote a change to a shared vault, Unix seconds.
    last_change_at: Option<u64>,
    #[schema(value_type = Option<String>)]
    last_change_vault: Option<Owner>,
    /// This server holds event-log entries the peer sent. Whether the peer's own Send switch is on
    /// is not this server's to read, so this is what has arrived.
    they_send_logs: bool,
    /// Whether the peer says it reads and ranks writer signatures (`x-kemlock-signed-writes1`).
    /// Every server of a vault must before the vault's writes are signed: one that doesn't
    /// refuses the changes of one that does.
    signed_writes: bool,
    /// Whether the peer says it reads the past bundles of a member account
    /// (`x-kemlock-past-bundles1`).
    past_bundles: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct VaultDto {
    #[schema(value_type = String)]
    vault: Owner,
    policy: &'static str,
    #[schema(value_type = String)]
    home: ServerId,
    epoch: u64,
    #[schema(value_type = Vec<String>)]
    replicas: Vec<ServerId>,
    is_home: bool,
    /// The signed promotion record that made this epoch, base64url.
    promotion: Option<String>,
    /// The owner's email, for an account's vault. A vault's name is ciphertext only its members
    /// can read, so the server has none to give; a space has no email either.
    owner_email: Option<String>,
    /// People who can open the vault, when this server holds it.
    members: Option<u64>,
    /// What the vault takes here in bytes: stored items and ready attachments.
    size_bytes: Option<u64>,
    /// Versions waiting to reach the vault's other servers, counted to a limit.
    waiting_changes: u64,
    waiting_note: Option<String>,
    /// The first promotion another server signed that would make it this vault's home. It waits
    /// for this server's admin (`POST …/vaults/{owner}/demotion`); until then the vault doesn't
    /// sync. Every one that waits is in `heldPromotions`.
    held_demotion: Option<HeldDemotionDto>,
    /// All the promotions that wait, one for each server that would become the home.
    held_promotions: Vec<HeldDemotionDto>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeldDemotionDto {
    /// The server that would become the home.
    #[schema(value_type = String)]
    new_home: ServerId,
    /// The epoch it would start.
    epoch: u64,
    /// When it signed the promotion, in Unix seconds.
    issued_at: u64,
}

/// A promotion held for this server's admin: the vault, the server that would become its home and
/// the epoch it would start.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeldPromotionDto {
    #[schema(value_type = String)]
    vault: Owner,
    #[schema(value_type = String)]
    new_home: ServerId,
    epoch: u64,
    /// When the new home signed it, in Unix seconds.
    issued_at: u64,
}

/// A change of addresses that came with a peer's key rotation and waits for this server's admin.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddressChangeDto {
    #[schema(value_type = String)]
    peer: ServerId,
    operator: String,
    addresses: Vec<String>,
    suites: Vec<String>,
    /// When the rotation was applied, in Unix seconds.
    received_at: u64,
}

/// A rotation of a peer's identity key that waits for the admin: the new key is pinned only when
/// the admin confirms it is the peer's own (compare the fingerprint with the peer's admin).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct RotationDto {
    #[schema(value_type = String)]
    peer: ServerId,
    /// SHA-256 of the new identity key, in hex.
    fingerprint: String,
    operator: String,
    addresses: Vec<String>,
    issued_at: u64,
    received_at: u64,
}

/// Which held rotation a route means: the one whose new key has this fingerprint, or the only one
/// that waits.
#[derive(Debug, Default, Deserialize)]
struct RotationPick {
    fingerprint: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct OfferDto {
    #[schema(value_type = String)]
    vault: Owner,
    #[schema(value_type = String)]
    home: ServerId,
    epoch: u64,
    #[schema(value_type = Vec<String>)]
    replicas: Vec<ServerId>,
    state: &'static str,
    received_at: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct HomeRecordDto {
    index: u64,
    epoch: u64,
    kind: String,
    #[schema(value_type = String)]
    signer: ServerId,
    status: &'static str,
    payload_length: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct PeerEventDto {
    #[schema(value_type = String)]
    from: ServerId,
    /// The event's id, a UUID v7.
    id: uuid::Uuid,
    /// Unix milliseconds.
    at: u64,
    actor: Option<uuid::Uuid>,
    device: Option<uuid::Uuid>,
    action: String,
    target: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct KeyChangeDto {
    /// `rotation` or `revocation`.
    kind: &'static str,
    /// The identity key the server has now, hex.
    identity_key: String,
    /// How many paired peers will be told.
    peers_told: usize,
}

fn key_change_dto(change: KeyChange) -> KeyChangeDto {
    KeyChangeDto {
        kind: change.kind,
        identity_key: hex::encode(change.new_identity_key),
        peers_told: change.peers,
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct UnpairDto {
    /// The peer was asked to delete what it holds, and answered.
    asked: bool,
    /// What the peer says it deleted. Its word: nothing here can force it.
    peer_deleted: Option<PeerDeletedDto>,
    /// Why the peer couldn't be asked, if it couldn't.
    detail: Option<String>,
    /// What the console says before and after: a peer run by someone else can't be forced to delete.
    notice: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
struct PeerDeletedDto {
    vaults: u64,
    items: u64,
    accounts: u64,
}

fn unpair_dto(report: UnpairReport) -> UnpairDto {
    UnpairDto {
        asked: report.asked,
        peer_deleted: report.peer_report.map(|p| PeerDeletedDto {
            vaults: p.vaults,
            items: p.items,
            accounts: p.accounts,
        }),
        detail: report.detail,
        notice: report.notice,
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct OverviewDto {
    server: ServerDto,
    peers: Vec<PeerDto>,
    pairings: Vec<AwaitingDto>,
    vaults: Vec<VaultDto>,
    offers: Vec<OfferDto>,
}

#[derive(Debug, Serialize, ToSchema)]
struct PromotionDto {
    record: String,
}

fn ack_dto(ack: &Acknowledgement) -> AckDto {
    AckDto {
        metadata: ack.metadata,
        deletion: ack.deletion,
        cross_border: ack.cross_border,
        by: ack.by.clone(),
        at: ack.at,
    }
}

fn vault_status_dto(v: &VaultStatus) -> VaultStatusDto {
    VaultStatusDto {
        vault: v.vault,
        at: v.at,
        offer: v.offer.map(|o| o.as_str()),
        pulled: PulledDto {
            applied: v.pulled.applied,
            siblings: v.pulled.siblings,
            duplicates: v.pulled.duplicates,
            refused: v.pulled.refused,
        },
        home_applied: v.home_applied,
        home_quarantined: v.home_quarantined,
        behind: v.behind,
        files_fetched: v.files_fetched,
        files_deferred: v.files_deferred,
        events_pulled: v.events_pulled,
        tags_pulled: v.tags_pulled,
        in_step: v.in_step,
        note: v.note.clone(),
    }
}

fn status_dto(s: &PeerStatus) -> StatusDto {
    StatusDto {
        last_attempt: s.last_attempt,
        last_success: s.last_success,
        down_since: s.down_since,
        last_error: s.last_error.clone(),
        key_mismatch: s.key_mismatch.as_deref().map(hex::encode),
        vaults: s.vaults.iter().map(vault_status_dto).collect(),
    }
}

fn peer_dto(view: &PeerView) -> PeerDto {
    PeerDto {
        id: view.peer.id,
        name: host_of(view.peer.addresses.first().map_or("", String::as_str)),
        operator: view.peer.operator.clone(),
        addresses: view.peer.addresses.clone(),
        state: view.peer.state.as_str(),
        paired_at: view.peer.paired_at,
        last_seen: view
            .peer
            .last_seen
            .max(view.probe.as_ref().and_then(|p| p.last_seen)),
        health: view.health.as_str(),
        latency_ms: view.probe.as_ref().and_then(|p| p.latency_ms),
        probe_error: view.probe.as_ref().and_then(|p| p.last_error.clone()),
        failing_since: view.probe.as_ref().and_then(|p| p.down_since),
        identity_key: hex::encode(&view.peer.identity_key),
        fingerprint: view.fingerprint.split('-').map(str::to_owned).collect(),
        switches: SwitchesDto {
            send: view.switches.send,
            pull: view.switches.pull,
        },
        acknowledgement: view.acknowledgement.as_ref().map(ack_dto),
        status: view.status.as_ref().map(status_dto),
        lag_changes: view.activity.lag_changes,
        lag_seconds: view.activity.lag_seconds,
        last_change_at: view.activity.last_change_at,
        last_change_vault: view.activity.last_change_vault,
        they_send_logs: view.they_send_logs,
        signed_writes: view
            .peer
            .advertises(kemlock_federation::writes::SIGNED_WRITES_CAPABILITY),
        past_bundles: view
            .peer
            .advertises(kemlock_federation::writes::PAST_BUNDLES_CAPABILITY),
    }
}

fn settings_dto(settings: &VaultFederation, is_home: bool) -> VaultDto {
    let held: Vec<HeldDemotionDto> = settings
        .held_demotion
        .iter()
        .filter_map(|record| kemlock_federation::home::peek_promotion(record).ok())
        .map(|p| HeldDemotionDto {
            new_home: p.new_home,
            epoch: p.epoch,
            issued_at: p.issued_at,
        })
        .collect();
    VaultDto {
        vault: settings.owner,
        policy: settings.policy.as_str(),
        home: settings.home,
        epoch: settings.epoch,
        replicas: settings.replicas.clone(),
        is_home,
        promotion: settings.promotion.as_deref().map(b64url::encode),
        owner_email: None,
        members: None,
        size_bytes: None,
        waiting_changes: 0,
        waiting_note: None,
        held_demotion: held.first().cloned(),
        held_promotions: held,
    }
}

fn vault_dto(view: &VaultView) -> VaultDto {
    let mut dto = settings_dto(&view.settings, view.is_home);
    if let Some(info) = &view.info {
        dto.owner_email = info.owner_email.clone();
        dto.members = Some(info.members);
        dto.size_bytes = Some(info.size_bytes);
    }
    dto.waiting_changes = view.waiting.changes;
    dto.waiting_note = waiting_note(&view.waiting);
    dto
}

/// What the console says beside a count of waiting changes, when there is something to say.
fn waiting_note(waiting: &kemlock_federation::Waiting) -> Option<String> {
    if waiting.at_least {
        Some("counted up to a limit: there are at least this many".to_owned())
    } else if waiting.changes > 0 {
        Some("counted against the last pull from each server".to_owned())
    } else {
        None
    }
}

/// The host of an address: `https://vault.example.co:443/x` is `vault.example.co`.
fn host_of(address: &str) -> String {
    let bare = address
        .split_once("://")
        .map_or(address, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    match bare.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.to_owned(),
        _ => bare.to_owned(),
    }
}

fn offer_dto(offer: &StoredOffer) -> OfferDto {
    OfferDto {
        vault: offer.vault,
        home: offer.home,
        epoch: offer.epoch,
        replicas: offer.replicas.clone(),
        state: offer.state.as_str(),
        received_at: offer.received_at,
    }
}

fn record_dto(stored: &StoredHomeRecord) -> HomeRecordDto {
    HomeRecordDto {
        index: stored.record.index,
        epoch: stored.record.epoch,
        kind: stored.record.kind.clone(),
        signer: stored.record.signer,
        status: stored.status.as_str(),
        payload_length: stored.record.payload.len(),
    }
}

fn awaiting_dto(awaiting: &AwaitingPeer, our_operator: &str) -> AwaitingDto {
    let d = &awaiting.descriptor.descriptor;
    AwaitingDto {
        peer_id: d.server,
        operator: d.operator.clone(),
        addresses: d.addresses.clone(),
        fingerprint: awaiting.words(),
        other_organisation: d.operator != our_operator,
        identity_key: hex::encode(d.identity_key.as_bytes()),
        side: match awaiting.side {
            Side::Typed => "typed",
            Side::Showed => "showed",
        },
        since: awaiting.since,
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers.

fn our_operator<S: FedStore + Leases, C: Connector>(state: &AdminState<S, C>) -> String {
    state
        .federation
        .replica()
        .identity()
        .descriptor
        .descriptor
        .operator
        .clone()
}

async fn peer_view<S, C>(state: &AdminState<S, C>, id: ServerId) -> Result<PeerView, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    state
        .federation
        .peers()
        .await?
        .into_iter()
        .find(|v| v.peer.id == id)
        .ok_or_else(|| ApiError::from(FedError::UnknownPeer))
}

async fn overview<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<OverviewDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let identity = state.federation.replica().identity();
    let d = &identity.descriptor.descriptor;
    let operator = d.operator.clone();
    let profile = state.federation.profile();
    let server = ServerDto {
        server_id: identity.server,
        name: profile
            .name
            .clone()
            .unwrap_or_else(|| host_of(d.addresses.first().map_or("", String::as_str))),
        database: profile.database.clone(),
        country: profile.country.clone(),
        operator: d.operator.clone(),
        addresses: d.addresses.clone(),
        identity_key: hex::encode(identity.public.as_bytes()),
        descriptor_not_after: d.not_after,
    };
    Ok(Json(OverviewDto {
        server,
        peers: state
            .federation
            .peers()
            .await?
            .iter()
            .map(peer_dto)
            .collect(),
        pairings: state
            .federation
            .pairings()
            .awaiting(unix_now())
            .iter()
            .map(|a| awaiting_dto(a, &operator))
            .collect(),
        vaults: state
            .federation
            .vaults()
            .await?
            .iter()
            .map(vault_dto)
            .collect(),
        offers: state
            .federation
            .offers()
            .await?
            .iter()
            .map(offer_dto)
            .collect(),
    }))
}

async fn peers<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<PeerDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .peers()
            .await?
            .iter()
            .map(peer_dto)
            .collect(),
    ))
}

async fn new_code<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<CodeDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    // Every write needs a step-up token, and this one makes the secret that lets a stranger pair.
    require_step_up(&actor)?;
    let (code, expires_at) = state.federation.pairings().new_code(unix_now());
    Ok(Json(CodeDto { code, expires_at }))
}

async fn start_pairing<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    body: Bytes,
) -> Result<Json<AwaitingDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let request: StartPairingBody = parse_body(&body)?;
    let awaiting = state
        .federation
        .pairings()
        .start(&request.address, &request.code, unix_now())
        .await?;
    Ok(Json(awaiting_dto(&awaiting, &our_operator(&state))))
}

async fn pairings<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<AwaitingDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let operator = our_operator(&state);
    Ok(Json(
        state
            .federation
            .pairings()
            .awaiting(unix_now())
            .iter()
            .map(|a| awaiting_dto(a, &operator))
            .collect(),
    ))
}

async fn confirm_pairing<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(peer): Path<String>,
    body: Bytes,
) -> Result<Json<PeerDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let peer = parse_server(&peer)?;
    let request: ConfirmBody = parse_body(&body)?;
    let now = unix_now();
    let confirmation = Confirmation {
        fingerprint_matches: request.fingerprint_matches,
        acknowledgement: request.acknowledgement.map(|a| Acknowledgement {
            metadata: a.metadata,
            deletion: a.deletion,
            cross_border: a.cross_border,
            by: a.by,
            at: now,
        }),
    };
    state
        .federation
        .pairings()
        .confirm(peer, confirmation, now)
        .await?;
    Ok(Json(peer_dto(&peer_view(&state, peer).await?)))
}

async fn cancel_pairing<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(peer): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let peer = parse_server(&peer)?;
    if state.federation.pairings().cancel(peer) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(FedError::UnknownPeer.into())
    }
}

async fn set_logs<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<SwitchesDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let id = parse_server(&id)?;
    let request: LogsBody = parse_body(&body)?;
    state
        .federation
        .set_log_switches(
            id,
            LogSwitches {
                send: request.send,
                pull: request.pull,
            },
        )
        .await?;
    Ok(Json(SwitchesDto {
        send: request.send,
        pull: request.pull,
    }))
}

async fn revoke_peer<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state.federation.revoke_peer(parse_server(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_peer<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    if state.federation.remove_peer(parse_server(&id)?).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(FedError::UnknownPeer.into())
    }
}

async fn unpair_peer<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<Json<UnpairDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    Ok(Json(unpair_dto(
        state.federation.unpair(parse_server(&id)?).await?,
    )))
}

async fn vaults<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<VaultDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .vaults()
            .await?
            .iter()
            .map(vault_dto)
            .collect(),
    ))
}

async fn set_policy<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
    body: Bytes,
) -> Result<Json<VaultDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let owner = parse_owner(&owner)?;
    let request: PolicyBody = parse_body(&body)?;
    let policy = Policy::parse(&request.policy)
        .ok_or_else(|| ApiError::bad("policy is local or federated"))?;
    let replicas = request
        .replicas
        .iter()
        .map(|r| parse_server(r))
        .collect::<Result<Vec<_>, _>>()?;
    let settings = state.federation.set_policy(owner, policy, replicas).await?;
    Ok(Json(settings_dto(&settings, true)))
}

async fn quarantined<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
    Path(owner): Path<String>,
) -> Result<Json<Vec<HomeRecordDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let records = state.federation.quarantined(parse_owner(&owner)?).await?;
    Ok(Json(records.iter().map(record_dto).collect()))
}

async fn peer_events<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
    Path(owner): Path<String>,
) -> Result<Json<Vec<PeerEventDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let events = state
        .federation
        .peer_events(parse_owner(&owner)?, 200)
        .await?;
    Ok(Json(
        events
            .into_iter()
            .map(|e| PeerEventDto {
                from: e.from,
                id: uuid::Uuid::from_bytes(e.entry.id),
                at: e.entry.at_ms,
                actor: e.entry.actor.map(uuid::Uuid::from_bytes),
                device: e.entry.device.map(uuid::Uuid::from_bytes),
                action: e.entry.action,
                target: e.entry.target,
            })
            .collect(),
    ))
}

/// Refuses an admin who hasn't just passed a passkey or password check, or sent a step-up token.
fn require_fresh(actor: &AdminActor) -> Result<(), ApiError> {
    if actor.fresh || actor.step_up {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "fresh-check-needed",
        "A fresh check is needed",
        Some("confirm with your passkey or password, then try again".to_owned()),
    ))
}

/// Refuses a write that carries no step-up token the gate accepted: 403 `step-up-required`, as
/// the rest of `/admin/v1` answers.
fn require_step_up(actor: &AdminActor) -> Result<(), ApiError> {
    if actor.step_up {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "step-up-required",
        "A fresh password or two-step check is required",
        Some(
            "make one at /admin/v1/step-up/password, /totp or /passkey and send the token in the Step-Up-Token header"
                .to_owned(),
        ),
    ))
}

async fn rotate_identity<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<KeyChangeDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_fresh(&actor)?;
    let change = state.federation.rotate_identity(unix_now()).await?;
    Ok(Json(key_change_dto(change)))
}

async fn revoke_identity<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
) -> Result<Json<KeyChangeDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_fresh(&actor)?;
    let change = state.federation.revoke_identity(unix_now()).await?;
    Ok(Json(key_change_dto(change)))
}

async fn promote<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
) -> Result<Json<PromotionDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let owner = parse_owner(&owner)?;
    require_fresh(&actor)?;
    let record = state.federation.promote(owner, unix_now()).await?;
    Ok(Json(PromotionDto {
        record: b64url::encode(&record),
    }))
}

/// Which held promotion a route means: the one `newHome` names, or the only one that waits.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PromotionPick {
    new_home: Option<String>,
}

fn pick_of(pick: &PromotionPick) -> Result<Option<ServerId>, ApiError> {
    pick.new_home.as_deref().map(parse_server).transpose()
}

async fn accept_demotion<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
    Query(pick): Query<PromotionPick>,
) -> Result<Json<VaultDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let owner = parse_owner(&owner)?;
    require_fresh(&actor)?;
    let next = state
        .federation
        .accept_promotion_of(owner, pick_of(&pick)?)
        .await?;
    Ok(Json(settings_dto(&next, false)))
}

/// `GET …/promotions`: the promotions held for this server's admin, whether this server is the
/// vault's home or one of its replicas.
async fn held_promotions<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<HeldPromotionDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .held_promotions()
            .await?
            .into_iter()
            .map(|(vault, p)| HeldPromotionDto {
                vault,
                new_home: p.new_home,
                epoch: p.epoch,
                issued_at: p.issued_at,
            })
            .collect(),
    ))
}

/// `DELETE …/vaults/{owner}/demotion`: drops the held promotion without applying it.
async fn refuse_demotion<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
    Query(pick): Query<PromotionPick>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let owner = parse_owner(&owner)?;
    require_step_up(&actor)?;
    state
        .federation
        .refuse_promotion_of(owner, pick_of(&pick)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET …/address-changes`: the address changes that came with key rotations, held for the admin.
async fn address_changes<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<AddressChangeDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .pending_address_changes()
            .await?
            .into_iter()
            .map(|p| AddressChangeDto {
                peer: p.peer,
                operator: p.operator,
                addresses: p.addresses,
                suites: p.suites,
                received_at: p.received_at,
            })
            .collect(),
    ))
}

/// `GET …/rotations`: the identity-key rotations that came from peers and wait for the admin.
async fn held_rotations<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<RotationDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .held_rotations()
            .await?
            .into_iter()
            .map(|r| RotationDto {
                peer: r.server,
                fingerprint: r.fingerprint,
                operator: r.operator,
                addresses: r.addresses,
                issued_at: r.issued_at,
                received_at: r.received_at,
            })
            .collect(),
    ))
}

/// `POST …/peers/{id}/rotation`: the new key is the peer's own; pin it.
async fn accept_rotation<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
    Query(pick): Query<RotationPick>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let peer = parse_server(&id)?;
    require_step_up(&actor)?;
    state
        .federation
        .accept_held_rotation(peer, pick.fingerprint.as_deref(), unix_now())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE …/peers/{id}/rotation`: refuse the rotations held for the peer.
async fn refuse_rotation<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let peer = parse_server(&id)?;
    require_step_up(&actor)?;
    state.federation.refuse_held_rotations(peer).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST …/peers/{id}/address-change`: follow the server to its new addresses.
async fn approve_address_change<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let peer = parse_server(&id)?;
    require_step_up(&actor)?;
    state.federation.approve_address_change(peer).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE …/peers/{id}/contest`: trust a contested peer again.
async fn clear_contest<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let peer = parse_server(&id)?;
    require_step_up(&actor)?;
    state.federation.clear_contest(peer).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE …/peers/{id}/address-change`: keep the addresses this server knows.
async fn refuse_address_change<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    let peer = parse_server(&id)?;
    require_step_up(&actor)?;
    state.federation.refuse_address_change(peer).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn offers<S, C>(
    State(state): State<AdminState<S, C>>,
    _admin: Admin,
) -> Result<Json<Vec<OfferDto>>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    Ok(Json(
        state
            .federation
            .offers()
            .await?
            .iter()
            .map(offer_dto)
            .collect(),
    ))
}

/// `?rehome=true` on an accept: the admin means to take the account of a personal vault that this
/// server holds as a copy from another server over to the offering server.
#[derive(Debug, Default, Deserialize)]
struct AcceptOffer {
    #[serde(default)]
    rehome: bool,
}

async fn accept_offer<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
    Query(accept): Query<AcceptOffer>,
) -> Result<Json<VaultDto>, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    let settings = state
        .federation
        .accept_offer_rehoming(parse_owner(&owner)?, accept.rehome)
        .await?;
    Ok(Json(settings_dto(&settings, false)))
}

async fn decline_offer<S, C>(
    State(state): State<AdminState<S, C>>,
    Admin(actor): Admin,
    Path(owner): Path<String>,
) -> Result<StatusCode, ApiError>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    require_step_up(&actor)?;
    state.federation.decline_offer(parse_owner(&owner)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /admin/v1/federation/openapi.json`: the contract of the routes added for the web vault,
/// public like `/kem/v1/openapi.json`.
async fn openapi_json() -> Response {
    Json(openapi::openapi()).into_response()
}

/// The `/admin/v1/federation` routes.
pub fn admin_router<S, C>(state: AdminState<S, C>) -> Router
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    const BASE: &str = "/admin/v1/federation";
    Router::new()
        .route(&format!("{BASE}/openapi.json"), get(openapi_json))
        .route(BASE, get(overview::<S, C>))
        .route(&format!("{BASE}/peers"), get(peers::<S, C>))
        .route(&format!("{BASE}/pairing/code"), post(new_code::<S, C>))
        .route(&format!("{BASE}/pairing"), post(start_pairing::<S, C>))
        .route(&format!("{BASE}/pairings"), get(pairings::<S, C>))
        .route(
            &format!("{BASE}/pairings/{{peer}}/confirm"),
            post(confirm_pairing::<S, C>),
        )
        .route(
            &format!("{BASE}/pairings/{{peer}}"),
            delete(cancel_pairing::<S, C>),
        )
        .route(&format!("{BASE}/peers/{{id}}/logs"), put(set_logs::<S, C>))
        .route(
            &format!("{BASE}/peers/{{id}}/revoke"),
            post(revoke_peer::<S, C>),
        )
        .route(
            &format!("{BASE}/peers/{{id}}/unpair"),
            post(unpair_peer::<S, C>),
        )
        .route(&format!("{BASE}/peers/{{id}}"), delete(remove_peer::<S, C>))
        .route(&format!("{BASE}/vaults"), get(vaults::<S, C>))
        .route(&format!("{BASE}/vaults/{{owner}}"), put(set_policy::<S, C>))
        .route(
            &format!("{BASE}/vaults/{{owner}}/quarantined"),
            get(quarantined::<S, C>),
        )
        .route(
            &format!("{BASE}/vaults/{{owner}}/promote"),
            post(promote::<S, C>),
        )
        .route(
            &format!("{BASE}/vaults/{{owner}}/demotion"),
            post(accept_demotion::<S, C>).delete(refuse_demotion::<S, C>),
        )
        .route(&format!("{BASE}/promotions"), get(held_promotions::<S, C>))
        .route(
            &format!("{BASE}/address-changes"),
            get(address_changes::<S, C>),
        )
        .route(&format!("{BASE}/rotations"), get(held_rotations::<S, C>))
        .route(
            &format!("{BASE}/peers/{{id}}/rotation"),
            post(accept_rotation::<S, C>).delete(refuse_rotation::<S, C>),
        )
        .route(
            &format!("{BASE}/peers/{{id}}/address-change"),
            post(approve_address_change::<S, C>).delete(refuse_address_change::<S, C>),
        )
        .route(
            &format!("{BASE}/peers/{{id}}/contest"),
            delete(clear_contest::<S, C>),
        )
        .route(
            &format!("{BASE}/vaults/{{owner}}/events"),
            get(peer_events::<S, C>),
        )
        .route(
            &format!("{BASE}/identity/rotate"),
            post(rotate_identity::<S, C>),
        )
        .route(
            &format!("{BASE}/identity/revoke"),
            post(revoke_identity::<S, C>),
        )
        .route(&format!("{BASE}/offers"), get(offers::<S, C>))
        .route(
            &format!("{BASE}/offers/{{owner}}/accept"),
            post(accept_offer::<S, C>),
        )
        .route(
            &format!("{BASE}/offers/{{owner}}/decline"),
            post(decline_offer::<S, C>),
        )
        .merge(console::routes())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_parse_in_both_forms() {
        let id = uuid::Uuid::new_v4();
        assert!(matches!(
            parse_owner(&format!("user:{id}")),
            Ok(Owner::User(_))
        ));
        assert!(matches!(
            parse_owner(&format!("space:{id}")),
            Ok(Owner::Space(_))
        ));
        for bad in [
            "",
            "user",
            "user:nope",
            "team:00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(
                parse_owner(bad).expect_err("refused").status,
                StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
    }

    #[test]
    fn errors_map_to_statuses_without_leaking() {
        let status = |e: FedError| ApiError::from(e).status;
        assert_eq!(status(FedError::Pairing), StatusCode::BAD_REQUEST);
        assert_eq!(status(FedError::UnknownPeer), StatusCode::NOT_FOUND);
        assert_eq!(status(FedError::UnknownVault), StatusCode::NOT_FOUND);
        assert_eq!(status(FedError::Refused("x")), StatusCode::CONFLICT);
        assert_eq!(
            status(FedError::KeyMismatch { offered: vec![1] }),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(FedError::Remote("secret".to_owned())),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status(FedError::Store("secret".to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = ApiError::from(FedError::Store("secret".to_owned())).body();
        assert!(body.get("detail").is_none());
        assert_eq!(body["type"], "urn:kemlock:problem:internal");
        let pairing = ApiError::from(FedError::Pairing).body();
        assert!(pairing.get("detail").is_none());
    }
}
