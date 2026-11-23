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
}

/// The view as the API holds it, in a request extension.
pub type SharedView = Arc<dyn FederationView>;
