//! What the Kemlock API needs to know about federation, and nothing more.
//!
//! `/kem/v1/config` lists a vault's servers (the home first, then its replicas), `/kem/v1/sync`
//! lists the siblings of an item (versions that two servers accepted apart), and a replica signs a
//! device in with the device key registered at the home. All three are answered from the
//! federation state, which lives in `kemlock-federation`; this trait is the seam, so the API
//! crates depend on the use-case crate only.
//!
//! The methods return boxed futures, so the server can hand the API one `Arc<dyn FederationView>`
//! (through a request extension) without making every API type generic over a federation store.
//! A server with no federation wired answers no extension, and the routes behave as they did.

use crate::ports::StoreError;
use kemlock_domain::{Item, ItemId, Owner, ServerId, UserId};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A boxed, sendable future, the return type of [`FederationView`]'s methods.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A server's place in a vault's set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRole {
    Home,
    Replica,
}

impl ServerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ServerRole::Home => "home",
            ServerRole::Replica => "replica",
        }
    }
}

/// One server a vault is held on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerEntry {
    pub server: ServerId,
    /// The base URL devices use, such as `https://vps.example.net`.
    pub address: String,
    /// The server's federation identity key (`sig1` public key), as the peers pinned it. A device
    /// keeps it as first seen and checks a promotion record against it.
    pub identity_key: Vec<u8>,
    pub role: ServerRole,
}

/// A vault's servers in failover order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultServers {
    pub vault: Owner,
    /// The home epoch, from 1.
    pub epoch: u64,
    /// The home first, then each replica in order.
    pub servers: Vec<ServerEntry>,
    /// The signed promotion record that made this epoch, as `docs/federation.md` defines it.
    /// `None` at epoch 1.
    pub promotion: Option<Vec<u8>>,
}

/// An item with versions held beside its head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiblingSet {
    pub item: ItemId,
    /// The siblings only; the head is what sync lists as the item.
    pub siblings: Vec<Item>,
}

/// Whether a peer server answers, as this server's probes of it say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    /// Not probed yet.
    Unknown,
    Online,
    /// It answers, slowly, or it missed a probe or two.
    Degraded,
    /// Several probes in a row failed.
    Offline,
}

impl PeerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerStatus::Unknown => "unknown",
            PeerStatus::Online => "online",
            PeerStatus::Degraded => "degraded",
            PeerStatus::Offline => "offline",
        }
    }
}

/// What this server knows of a peer's health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHealthView {
    pub status: PeerStatus,
    /// Unix seconds of the last time the peer answered.
    pub last_seen: Option<u64>,
    /// How long its last answer took, in milliseconds.
    pub latency_ms: Option<u64>,
    /// Why the last probe failed, while it is failing.
    pub last_error: Option<String>,
    /// Unix seconds since when it has been failing.
    pub offline_since: Option<u64>,
}

impl PeerHealthView {
    /// A server nothing is known of.
    pub fn unknown() -> PeerHealthView {
        PeerHealthView {
            status: PeerStatus::Unknown,
            last_seen: None,
            latency_ms: None,
            last_error: None,
            offline_since: None,
        }
    }
}

/// The changes of a vault that one peer has not been given yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitingChanges {
    /// The server they wait for.
    pub peer: ServerId,
    /// How many, counted to a limit.
    pub changes: u64,
    /// The count stopped at the limit.
    pub at_least: bool,
    /// When the oldest was written, Unix seconds.
    pub oldest_at: Option<u64>,
}

/// What cancelling the changes waiting for a peer did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The queued push to the peer was dropped: this many changes will not be sent to it.
    Cancelled { dropped: u64 },
    /// Nothing was waiting for that server.
    NothingWaiting,
    /// The peer is not offline, so its changes are on their way: nothing is dropped.
    NotOffline,
    /// This server doesn't federate the vault with that peer.
    Unknown,
}

/// Read access to federation state for the Kemlock API, and the one write a device may make: saying
/// it merged an item's siblings.
pub trait FederationView: Send + Sync {
    /// The servers `vault` is held on, or `None` when it isn't federated (or this server doesn't
    /// hold it).
    fn vault_servers(&self, vault: Owner) -> BoxFut<'_, Result<Option<VaultServers>, StoreError>>;

    /// The items of `owner` that have siblings, with the siblings.
    fn siblings(&self, owner: Owner) -> BoxFut<'_, Result<Vec<SiblingSet>, StoreError>>;

    /// Marks every sibling of the item as replaced by its head, deleting them. Returns how many
    /// went. A device calls it after it wrote the version that merged them.
    fn resolve_siblings(&self, owner: Owner, item: ItemId) -> BoxFut<'_, Result<u64, StoreError>>;

    /// Whether `user`'s account on this server was copied from its home (a federated vault's
    /// member), so that it has no OPAQUE record here and signs in with its device key.
    fn is_replica_account(&self, user: UserId) -> BoxFut<'_, Result<bool, StoreError>>;

    /// How a server answers this server's probes. Nothing is known of a server that isn't a paired
    /// peer, nor before the first probe.
    fn peer_health(&self, _server: ServerId) -> BoxFut<'_, Result<PeerHealthView, StoreError>> {
        Box::pin(async { Ok(PeerHealthView::unknown()) })
    }

    /// The changes of `vault` waiting for each other server that holds it, those with something
    /// waiting only.
    fn waiting_changes(&self, _vault: Owner) -> BoxFut<'_, Result<Vec<WaitingChanges>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Where an account's Sends that have a view limit are served from, when it isn't here: the
    /// address of the home of the account's vault, if this server holds the vault as a replica.
    /// `None` when the vault isn't federated here or this server is its home. A view limit is kept
    /// by one server, since two counting apart would each allow the whole limit.
    fn limited_send_home(&self, _owner: UserId) -> BoxFut<'_, Result<Option<String>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    /// Drops the changes of `vault` that wait for `peer`, which must be offline, on behalf of
    /// `by`. Nothing held here is deleted: the changes stay in this server's copy and are only
    /// not sent to that peer. See `docs/federation.md`, "Waiting changes".
    fn cancel_waiting(
        &self,
        _vault: Owner,
        _peer: ServerId,
        _by: UserId,
    ) -> BoxFut<'_, Result<CancelOutcome, StoreError>> {
        Box::pin(async { Ok(CancelOutcome::Unknown) })
    }
}

/// The view as the API holds it, in a request extension.
pub type SharedView = Arc<dyn FederationView>;
