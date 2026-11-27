//! The ports federation needs from storage. `kemlock-store-sql` implements them on `SqlStore`;
//! [`crate::memory::MemoryStore`] is the in-memory fake the tests use.
//!
//! Async methods are written as `fn … -> impl Future<Output = …> + Send` so implementers can use
//! `async fn` and callers stay `Send` for axum, as in `kemlock_app::ports`.

use crate::change::ChangeRecord;
use crate::conflict::Rank;
use crate::error::{FedError, Result};
use crate::hashtree::Leaf;
use crate::home::{HomeRecord, VaultFederation};
use crate::wire::ChangeKey;
use kemlock_app::ports::StoreError;
use kemlock_crypto::sig1;
use kemlock_domain::{Item, ItemId, Owner, ServerId, VersionVector};
use std::future::Future;

/// Whether a peer is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Paired,
    /// The admin revoked it, or its identity key was reported stolen. No session is accepted.
    Revoked,
    /// A key this server replaced for the peer says the peer's key was stolen (and rotated away
    /// by a thief), which can't be told from an honest rotation by the old key. Nothing syncs
    /// either way, nothing is deleted, and the admin settles it: pair again, or trust the peer.
    Contested,
}

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerState::Paired => "paired",
            PeerState::Revoked => "revoked",
            PeerState::Contested => "contested",
        }
    }

    pub fn parse(s: &str) -> Option<PeerState> {
        match s {
            "paired" => Some(PeerState::Paired),
            "revoked" => Some(PeerState::Revoked),
            "contested" => Some(PeerState::Contested),
            _ => None,
        }
    }
}

/// Another Kemlock Server this one is paired with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: ServerId,
    /// Who runs it, as its descriptor says.
    pub operator: String,
    /// The pinned identity key: a `sig1` public key.
    pub identity_key: Vec<u8>,
    pub addresses: Vec<String>,
    pub suites: Vec<String>,
    pub state: PeerState,
    /// Unix seconds.
    pub paired_at: u64,
    /// Unix seconds of the last session, if any.
    pub last_seen: Option<u64>,
}

impl Peer {
    /// Whether the peer's descriptor lists `name` among its suites: how a server says it answers a
    /// request an older one doesn't know.
    pub fn advertises(&self, name: &str) -> bool {
        self.suites.iter().any(|s| s == name)
    }

    /// The pinned identity key.
    pub fn key(&self) -> Result<sig1::PublicKey> {
        sig1::PublicKey::from_bytes(&self.identity_key)
            .map_err(|_| FedError::Invalid("a stored identity key is not valid"))
    }
}

/// The two event-log switches of a peer, both off by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogSwitches {
    /// "Send our logs" to this peer.
    pub send: bool,
    /// "Pull their logs" from this peer.
    pub pull: bool,
}

/// Logs flow from one server to another only when the sender's Send and the receiver's Pull are
/// both on.
pub fn logs_flow(sender_send: bool, receiver_pull: bool) -> bool {
    sender_send && receiver_pull
}

pub trait PeerRepo: Send + Sync {
    /// Adds a peer; `Duplicate` when the id is taken.
    fn insert_peer(
        &self,
        peer: &Peer,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
    fn get_peer(
        &self,
        id: ServerId,
    ) -> impl Future<Output = std::result::Result<Option<Peer>, StoreError>> + Send;
    fn list_peers(&self)
    -> impl Future<Output = std::result::Result<Vec<Peer>, StoreError>> + Send;
    /// `NotFound` for an unknown peer.
    fn set_peer_state(
        &self,
        id: ServerId,
        state: PeerState,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
    fn touch_peer(
        &self,
        id: ServerId,
        at: u64,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
    /// Removes the peer with its cursors and switches. False when it wasn't there.
    fn remove_peer(
        &self,
        id: ServerId,
    ) -> impl Future<Output = std::result::Result<bool, StoreError>> + Send;
    /// Both off for a peer that never set them.
    fn log_switches(
        &self,
        id: ServerId,
    ) -> impl Future<Output = std::result::Result<LogSwitches, StoreError>> + Send;
    fn set_log_switches(
        &self,
        id: ServerId,
        switches: LogSwitches,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
}

/// Where a home record stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeStatus {
    /// Made under the vault's current epoch by its home.
    Applied,
    /// Made under an older epoch: kept for the vault's admins to redo or drop.
    Quarantined,
}

impl HomeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HomeStatus::Applied => "applied",
            HomeStatus::Quarantined => "quarantined",
        }
    }

    pub fn parse(s: &str) -> Option<HomeStatus> {
        match s {
            "applied" => Some(HomeStatus::Applied),
            "quarantined" => Some(HomeStatus::Quarantined),
            _ => None,
        }
    }
}

/// A home record as stored: the signed envelope (to pass on) and what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHomeRecord {
    pub signed: Vec<u8>,
    pub record: HomeRecord,
    pub status: HomeStatus,
}

pub trait VaultRepo: Send + Sync {
    fn get_vault(
        &self,
        owner: Owner,
    ) -> impl Future<Output = std::result::Result<Option<VaultFederation>, StoreError>> + Send;
    /// Adds or replaces a vault's federation settings.
    fn put_vault(
        &self,
        vault: &VaultFederation,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
    fn list_vaults(
        &self,
    ) -> impl Future<Output = std::result::Result<Vec<VaultFederation>, StoreError>> + Send;
    /// What we have pulled from `peer` for `vault`: empty before the first pull.
    fn peer_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
    ) -> impl Future<Output = std::result::Result<VersionVector, StoreError>> + Send;
    fn set_peer_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
        cursor: &VersionVector,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;
    /// Stores a home record unless one with its index is already held. False when it was.
    fn put_home_record(
        &self,
        stored: &StoredHomeRecord,
    ) -> impl Future<Output = std::result::Result<bool, StoreError>> + Send;
    /// Home records of a vault after index `after`, in index order.
    fn home_records(
        &self,
        vault: Owner,
        after: u64,
        limit: u32,
    ) -> impl Future<Output = std::result::Result<Vec<StoredHomeRecord>, StoreError>> + Send;
    /// The quarantined records of a vault, for its admins.
    fn quarantined(
        &self,
        vault: Owner,
    ) -> impl Future<Output = std::result::Result<Vec<StoredHomeRecord>, StoreError>> + Send;
}

/// A stored version of an item with what is needed to sign and relay it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    pub item: Item,
    /// The versions this one replaced: stored for a replicated change, worked out and stored the
    /// first time for one this server accepted.
    pub lineage: Vec<ChangeKey>,
    /// The origin's signature, if one is stored. A change this server accepted has none until it
    /// is first sent.
    pub signature: Option<Vec<u8>>,
    /// The collection of an item of a space, as this server holds it: what the writer's signature
    /// covers. The same for every version of the item held, which is the item's current one.
    pub collection: Option<kemlock_domain::spaces::CollectionId>,
}

/// A page of versions, in (origin, sequence) order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPage {
    pub entries: Vec<Exported>,
    /// `since` advanced by every version in the page.
    pub next: VersionVector,
    pub more: bool,
}

/// What applying a remote change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The version is now the item's head.
    Applied,
    /// The version is held beside the head: a conflict that a device will merge.
    Sibling,
    /// The version was already held, or a held version replaced it.
    Duplicate,
    /// The version would have replaced the head at no higher revision: a rollback, left out.
    Refused,
}

pub trait ReplicaStore: Send + Sync {
    /// This server's id.
    fn server_id(&self) -> ServerId;

    /// The versions (heads and siblings) of `owner`'s items that `since` doesn't cover, at most
    /// `limit`, with the lineage of each.
    fn export_since(
        &self,
        owner: Owner,
        since: &VersionVector,
        limit: u32,
    ) -> impl Future<Output = std::result::Result<ExportPage, StoreError>> + Send;

    /// Every version held of these items of `owner`.
    fn export_items(
        &self,
        owner: Owner,
        items: &[ItemId],
    ) -> impl Future<Output = std::result::Result<Vec<Exported>, StoreError>> + Send;

    /// Records the lineage and signature of a change this server accepted, once. A signature
    /// already stored is kept.
    fn store_signature(
        &self,
        key: ChangeKey,
        lineage: &[ChangeKey],
        signature: &[u8],
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send;

    /// Applies a verified record from another server: merges it with the versions held, as
    /// `conflict::merge_ranked` says with `rank`, and keeps its signature for relaying. One
    /// transaction.
    fn apply_ranked(
        &self,
        record: &ChangeRecord,
        signature: &[u8],
        rank: Rank,
    ) -> impl Future<Output = std::result::Result<ApplyOutcome, StoreError>> + Send;

    /// [`apply_ranked`](Self::apply_ranked), choosing the head by clock alone.
    fn apply(
        &self,
        record: &ChangeRecord,
        signature: &[u8],
    ) -> impl Future<Output = std::result::Result<ApplyOutcome, StoreError>> + Send {
        self.apply_ranked(record, signature, Rank::Clock)
    }

    /// A digest per item of `owner`, over the versions held.
    fn leaves(
        &self,
        owner: Owner,
    ) -> impl Future<Output = std::result::Result<Vec<Leaf>, StoreError>> + Send;

    /// The newest change of each origin among `owner`'s items, siblings included: what a peer
    /// that is up to date holds.
    fn latest(
        &self,
        owner: Owner,
    ) -> impl Future<Output = std::result::Result<VersionVector, StoreError>> + Send;

    /// Whether the change `key` is already held here, applied or since replaced: what a record is
    /// asked before anything is spent on it, since a change is applied once.
    ///
    /// The default holds none, for a store that can't say.
    fn holds_change(
        &self,
        _key: ChangeKey,
    ) -> impl Future<Output = std::result::Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }

    /// Sets or clears the flag of `owner` here, as the home's signed record says
    /// (`docs/federation.md`, "Writer signatures"). Idempotent.
    ///
    /// The default keeps no flag.
    fn set_owner_signed_only(
        &self,
        _owner: Owner,
        _required: bool,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// Whether `owner` accepts signed `kem1` writes only on this server (docs/crypto.md, "The
    /// signed-only flag"): the owner asked for it, here or at the home server it replicates from.
    ///
    /// The default is false, for a store that keeps no such flag.
    fn owner_signed_only(
        &self,
        _owner: Owner,
    ) -> impl Future<Output = std::result::Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }

    /// Whether this server ranks `owner`'s versions by revision for good: once every server of the
    /// vault's set said it does, the vault stays that way, whatever a descriptor says later.
    ///
    /// The default is false, for a store that keeps no such pin.
    fn revision_ranked(
        &self,
        _owner: Owner,
    ) -> impl Future<Output = std::result::Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }

    /// Pins `owner` to ranking by revision. Idempotent, and never undone except by erasing the
    /// vault.
    fn pin_revision_ranking(
        &self,
        _owner: Owner,
    ) -> impl Future<Output = std::result::Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// The siblings of an item: the versions held beside its head.
    fn siblings(
        &self,
        owner: Owner,
        item: ItemId,
    ) -> impl Future<Output = std::result::Result<Vec<Item>, StoreError>> + Send;

    /// Marks every sibling of the item as replaced by its head, deleting them. For the sync API
    /// to call after a device merged the siblings and wrote the result. Returns how many went.
    fn resolve_siblings(
        &self,
        owner: Owner,
        item: ItemId,
    ) -> impl Future<Output = std::result::Result<u64, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_flow_only_when_both_switches_are_on() {
        assert!(logs_flow(true, true));
        assert!(!logs_flow(true, false));
        assert!(!logs_flow(false, true));
        assert!(!logs_flow(false, false));
        assert_eq!(
            LogSwitches::default(),
            LogSwitches {
                send: false,
                pull: false
            }
        );
    }

    #[test]
    fn states_round_trip() {
        for s in [PeerState::Paired, PeerState::Revoked, PeerState::Contested] {
            assert_eq!(PeerState::parse(s.as_str()), Some(s));
        }
        for s in [HomeStatus::Applied, HomeStatus::Quarantined] {
            assert_eq!(HomeStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(PeerState::parse("x"), None);
        assert_eq!(HomeStatus::parse("x"), None);
    }

    #[test]
    fn a_peer_exposes_its_pinned_key() {
        let key = crate::crypto::sign_public(&sig1::SigningKey::from_bytes(&[1; 64])).expect("key");
        let mut peer = Peer {
            id: ServerId::random(),
            operator: "x".to_owned(),
            identity_key: key.as_bytes().to_vec(),
            addresses: vec![],
            suites: vec![],
            state: PeerState::Paired,
            paired_at: 1,
            last_seen: None,
        };
        assert_eq!(peer.key(), Ok(key));
        peer.identity_key.pop();
        assert!(peer.key().is_err());
    }
}
