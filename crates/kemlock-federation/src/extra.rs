//! The storage ports of the pieces that wire federation to a running server: consent to a vault,
//! the member accounts a replica holds, attachments, and the lease a replication job runs under.
//!
//! Every method of [`FedAdminRepo`], [`MemberStore`], [`BlobSync`], [`ErasureOutbox`] and
//! [`VaultErasure`] has a default body that
//! answers "nothing here", so a store that doesn't do a part (the in-memory fake) needs only an
//! empty `impl`. `kemlock-store-sql` implements them all on `SqlStore`.

use crate::insight::{MismatchRecord, PeerSecurityRecord, VaultInfo};
use crate::members::MemberAccount;
use crate::message::OfferState;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Attachment, AttachmentId, BlobId, ItemId, Owner, ServerId, UserId};
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// What an admin acknowledged when pairing with a server another organisation runs: the peer sees
/// the metadata of the vaults it holds, it can't be forced to delete them, and a peer in another
/// country is a cross-border transfer. Kept as the operator's record of the data sharing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acknowledgement {
    pub metadata: bool,
    pub deletion: bool,
    pub cross_border: bool,
    /// Who acknowledged, as the console names them.
    pub by: String,
    /// Unix seconds.
    pub at: u64,
}

impl Acknowledgement {
    /// Whether all three were acknowledged.
    pub fn complete(&self) -> bool {
        self.metadata && self.deletion && self.cross_border
    }
}

/// An offer of a vault the home made to this server, and where its admin left it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOffer {
    pub vault: Owner,
    pub home: ServerId,
    pub epoch: u64,
    /// The replicas in the home's order; this server is one of them.
    pub replicas: Vec<ServerId>,
    pub state: OfferState,
    /// Unix seconds the offer was first received.
    pub received_at: u64,
}

/// What a server does with a promotion a replica signed for itself and announces unasked. The
/// setting `federation_promotion` (environment `KEMLOCK_FEDERATION_PROMOTION`) chooses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PromotionMode {
    /// Keep it, unapplied, for this server's admin to accept or refuse. The default.
    #[default]
    Hold,
    /// Apply it at once, when it checks out. (The home of a vault still holds one that would
    /// take the vault from it.)
    Auto,
}

impl PromotionMode {
    /// `auto` is the one word that turns holding off; anything else holds.
    pub fn parse(text: &str) -> PromotionMode {
        if text.trim().eq_ignore_ascii_case("auto") {
            PromotionMode::Auto
        } else {
            PromotionMode::Hold
        }
    }
}

pub trait FedAdminRepo: Send + Sync {
    /// What to do with a promotion another server signed for itself: see [`PromotionMode`].
    fn promotion_mode(&self) -> impl Future<Output = R<PromotionMode>> + Send {
        ready(Ok(PromotionMode::Hold))
    }

    /// Refreshes what a peer's descriptor says: operator, addresses and suites. The identity key
    /// is never changed here. A peer that isn't known is not an error.
    fn update_peer_descriptor(
        &self,
        _peer: ServerId,
        _operator: &str,
        _addresses: &[String],
        _suites: &[String],
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    /// The addresses of `peer` the admin chose: typed at pairing, listed by its descriptor when the
    /// pairing was confirmed, or approved since. Only these may be `http` or on a private network
    /// (see [`crate::addr`]).
    fn trusted_addresses(&self, _peer: ServerId) -> impl Future<Output = R<Vec<String>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Adds addresses the admin chose to `peer`'s trusted ones.
    fn trust_addresses(
        &self,
        _peer: ServerId,
        _addresses: &[String],
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    /// Records (or replaces) the admin's acknowledgements for a peer.
    fn put_acknowledgement(
        &self,
        _peer: ServerId,
        _ack: &Acknowledgement,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn acknowledgement(
        &self,
        _peer: ServerId,
    ) -> impl Future<Output = R<Option<Acknowledgement>>> + Send {
        ready(Ok(None))
    }

    /// Adds or replaces an offer received from a home.
    fn put_offer(&self, _offer: &StoredOffer) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn offer(&self, _vault: Owner) -> impl Future<Output = R<Option<StoredOffer>>> + Send {
        ready(Ok(None))
    }

    fn list_offers(&self) -> impl Future<Output = R<Vec<StoredOffer>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Whether `vault` is one this server is the original home of: its account or space exists
    /// here and wasn't copied from another server.
    fn owns_vault(&self, _vault: Owner) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(true))
    }

    /// The items of `owner` that have versions held beside their head.
    fn items_with_siblings(&self, _owner: Owner) -> impl Future<Output = R<Vec<ItemId>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Every vault homed on this server: each account that isn't a copy, and each space. For the
    /// console's list of what may be federated.
    fn local_vaults(&self) -> impl Future<Output = R<Vec<VaultInfo>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// What the console shows of one vault: `None` when this store can't say.
    fn vault_info(&self, _vault: Owner) -> impl Future<Output = R<Option<VaultInfo>>> + Send {
        ready(Ok(None))
    }

    /// When the newest item of `vault` written by `origin` was updated, in Unix seconds.
    fn newest_change_from(
        &self,
        _vault: Owner,
        _origin: ServerId,
    ) -> impl Future<Output = R<Option<u64>>> + Send {
        ready(Ok(None))
    }

    /// Keeps (or replaces) what is known of a peer's descriptor.
    fn put_peer_security(
        &self,
        _record: &PeerSecurityRecord,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn peer_security(
        &self,
        _peer: ServerId,
    ) -> impl Future<Output = R<Option<PeerSecurityRecord>>> + Send {
        ready(Ok(None))
    }

    /// Keeps (or replaces) the record of a peer's key mismatch.
    fn put_mismatch(&self, _record: &MismatchRecord) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn mismatch(&self, _peer: ServerId) -> impl Future<Output = R<Option<MismatchRecord>>> + Send {
        ready(Ok(None))
    }
}

/// How an account copied from a home was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberApply {
    /// The account is new here or changed.
    Applied,
    /// Nothing differed.
    Unchanged,
    /// An account of this server (not a copy) has the same id or email, so the copy was refused.
    Refused,
}

/// The member accounts of a federated vault: what the home publishes and a replica keeps. Never
/// an OPAQUE record, so no password secret is shared; the copy signs in with its device keys.
pub trait MemberStore: Send + Sync {
    /// The accounts that are members of `vault`: for a personal vault its account, for a space
    /// its confirmed members.
    fn member_ids(&self, _vault: Owner) -> impl Future<Output = R<Vec<UserId>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// The public part of an account that lives on this server, with its device registrations.
    /// `None` when there is no such account or it is a copy from another server.
    fn member_account(
        &self,
        _user: UserId,
    ) -> impl Future<Output = R<Option<MemberAccount>>> + Send {
        ready(Ok(None))
    }

    /// Stores a copy of an account, published by `home` as the home of `vault`, replacing an
    /// earlier copy. The home of the account's own personal vault may replace a copy that came
    /// in through a space; the home of a space may not (and creates one only while this server
    /// doesn't federate that personal vault at all).
    fn apply_member_account(
        &self,
        _vault: Owner,
        _home: ServerId,
        _account: &MemberAccount,
    ) -> impl Future<Output = R<MemberApply>> + Send {
        ready(Ok(MemberApply::Unchanged))
    }

    /// Whether `user` is a copy from another server.
    fn is_replica_account(&self, _user: UserId) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(false))
    }
}

/// Attachments as federation moves them: the rows here, the bytes in blob storage.
pub trait BlobSync: Send + Sync {
    /// The ready attachments of `owner` with an id after `after`, in id order, at most `limit`.
    fn attachments_after(
        &self,
        _owner: Owner,
        _after: AttachmentId,
        _limit: u32,
    ) -> impl Future<Output = R<Vec<Attachment>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// The attachment stored as `blob`, if any.
    fn attachment_of_blob(
        &self,
        _blob: BlobId,
    ) -> impl Future<Output = R<Option<Attachment>>> + Send {
        ready(Ok(None))
    }

    /// The attachment with this id, if any.
    fn attachment(&self, _id: AttachmentId) -> impl Future<Output = R<Option<Attachment>>> + Send {
        ready(Ok(None))
    }

    /// Stores a row for an attachment a peer holds, as ready. False when its id is taken.
    fn add_replicated_attachment(
        &self,
        _attachment: &Attachment,
    ) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(false))
    }
}

/// An erasure of a vault that this server, its home, still has to tell a replica about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingErasure {
    pub peer: ServerId,
    pub vault: Owner,
    /// Unix seconds the home erased the vault.
    pub queued_at: u64,
}

/// The erasures a home owes its replicas. When a home erases a vault (an account's, or a space's
/// that went with its last owner) its store queues one for each replica of the vault, in the same
/// transaction, because the vault's federation settings are deleted with it. The replication job
/// sends each in the peer's next session ([`Request::Erase`](crate::message::Request::Erase)) and
/// completes it when the peer acknowledges; one the peer can't take now stays queued.
pub trait ErasureOutbox: Send + Sync {
    /// What `peer` hasn't been told, oldest first.
    fn pending_erasures(
        &self,
        _peer: ServerId,
    ) -> impl Future<Output = R<Vec<PendingErasure>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// The peer acknowledged: the erasure is done for it. A repeat is not an error.
    fn complete_erasure(
        &self,
        _peer: ServerId,
        _vault: Owner,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }
}

/// What a replica deleted of a vault its home erased.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultErased {
    /// Item rows, tombstones included.
    pub items: u64,
    /// The attachment files whose rows went: the replica deletes them from its file storage.
    pub blobs: Vec<BlobId>,
    /// Copied accounts removed (the account of a personal vault, which lived here only as a copy).
    pub accounts: u64,
}

/// Deleting a replica's copy of a vault.
pub trait VaultErasure: Send + Sync {
    /// Deletes everything this server holds of `vault`: its items and every version of them, the
    /// change log, attachment rows, home records, cursors, the offer and the federation settings,
    /// and, for a personal vault, the copied account with its devices. Never an account that lives
    /// here (a copy is marked as one). One transaction.
    fn erase_vault(&self, _vault: Owner) -> impl Future<Output = R<VaultErased>> + Send {
        ready(Ok(VaultErased::default()))
    }
}

/// Named leases, so a job runs on one replica of the server at a time. A holder that lives
/// releases its lease; expiry is the safety net for one that crashed.
pub trait Leases: Send + Sync {
    /// Tries once to take `name` for `ttl_secs`. False when someone else holds it.
    fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        ttl_secs: u64,
    ) -> impl Future<Output = R<bool>> + Send;

    fn drop_lease(&self, name: &str, holder: &str) -> impl Future<Output = R<()>> + Send;
}
