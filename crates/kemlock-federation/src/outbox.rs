//! Changes waiting for a peer, per vault, and dropping the queue to one that is offline.
//!
//! Replication here is pull: a peer asks for the versions its cursor doesn't cover, and this server
//! only nudges it when it has more. So the changes "waiting" for a peer are the versions this
//! server holds that the peer hasn't been given. [`Replica::waiting_for`] counts them (to
//! [`WAITING_LIMIT`]) from what the peer has echoed back, which is as exact as this server can
//! know, and drops to nothing once the peer has caught up.
//!
//! Cancelling ([`Replica::cancel_waiting`]) is the one thing an account can do about them. It
//! withholds, for one peer and one vault, every version this server holds now: from then on the
//! peer's `Pull` and `Fetch` answers leave those versions out, and they are no longer counted as
//! waiting. Nothing is deleted. The versions stay in this server's copy, in the account's sync and
//! in its backups, and are still sent to every other server; changes made after the cancel flow to
//! the peer as usual. The two copies of the vault differ by exactly those versions from then on, and
//! the hourly hash-tree comparison says so ("out of step") until the vault is copied afresh.
//! Nothing here asks the peer to forget anything it already has.

use crate::admin::Waiting;
use crate::error::Result;
use crate::home::Policy;
use crate::ports::{ReplicaStore, VaultRepo};
use crate::replicate::{FedStore, Replica};
use kemlock_app::ports::StoreError;
use kemlock_domain::{ChangeId, Owner, ServerId, VersionVector};
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// The most versions read to say how many a peer is waiting for.
pub const WAITING_LIMIT: u32 = 100;
/// The most pages read to count them.
const MAX_PAGES: usize = 20;

/// The versions of a vault that are kept from one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Withheld {
    /// Every version this server held when its queue to the peer was cancelled, as the newest
    /// change of each origin: a version this covers is not sent to the peer.
    pub upto: VersionVector,
    /// Unix seconds of the last cancel.
    pub at: u64,
}

impl Withheld {
    /// Whether the version is one that was cancelled.
    pub fn covers(&self, change: &ChangeId) -> bool {
        self.upto.covers(change)
    }
}

/// What federation needs from storage to keep the cancelled queues. The defaults say nothing is
/// withheld.
pub trait Withholding: Send + Sync {
    /// What is kept from `peer` in `vault`, if a queue to it was cancelled.
    fn withheld(
        &self,
        _peer: ServerId,
        _vault: Owner,
    ) -> impl Future<Output = R<Option<Withheld>>> + Send {
        ready(Ok(None))
    }

    /// Keeps the versions `upto` covers from `peer`, adding them to what was kept before.
    fn withhold(
        &self,
        _peer: ServerId,
        _vault: Owner,
        _upto: &VersionVector,
        _at: u64,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    /// Forgets everything kept from `peer`, for a peer that is no longer paired.
    fn forget_withheld(&self, _peer: ServerId) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }
}

/// What cancelling a queue did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled {
    /// How many waiting versions will not be sent.
    pub dropped: u64,
    /// The count stopped at [`WAITING_LIMIT`].
    pub at_least: bool,
}

impl<S: FedStore> Replica<S> {
    /// What `peer` may still be waiting for in `vault`: the versions this server holds that its
    /// last pull from the peer did not cover, less those whose queue was cancelled, counted to
    /// [`WAITING_LIMIT`]. Not exact, since what the peer holds is only known as of that pull, but
    /// it falls to nothing once the peer has caught up.
    pub async fn waiting_for(&self, peer: ServerId, vault: Owner) -> Result<Waiting> {
        let mut since = self.store.peer_cursor(peer, vault).await?;
        let withheld = self.store.withheld(peer, vault).await?;
        let mut changes = 0u64;
        let mut oldest_at: Option<u64> = None;
        let mut more = false;
        // Pages of what the peer lacks, skipping what was cancelled, until the count has what it
        // needs. The pages are bounded: a vault with a long cancelled queue still answers.
        for _ in 0..MAX_PAGES {
            let page = self.store.export_since(vault, &since, WAITING_LIMIT).await?;
            for entry in &page.entries {
                since.observe(&entry.item.change);
                if withheld
                    .as_ref()
                    .is_some_and(|w| w.covers(&entry.item.change))
                {
                    continue;
                }
                changes += 1;
                if let Ok(at) = u64::try_from(entry.item.updated_at.unix_timestamp()) {
                    oldest_at = Some(oldest_at.map_or(at, |seen| seen.min(at)));
                }
            }
            more = page.more && !page.entries.is_empty();
            if !more || changes >= u64::from(WAITING_LIMIT) {
                break;
            }
        }
        // The count is held to the limit, and says so when there may be more behind it.
        let limit = u64::from(WAITING_LIMIT);
        Ok(Waiting {
            changes: changes.min(limit),
            at_least: more || changes > limit,
            oldest_at,
        })
    }

    /// Drops the queue of `vault` to `peer`: keeps every version held now from the peer (see the
    /// module's account of it). `None` when this server doesn't hold the vault federated with the
    /// peer, or nothing is waiting.
    pub async fn cancel_waiting(
        &self,
        peer: ServerId,
        vault: Owner,
        now: u64,
    ) -> Result<Option<Cancelled>> {
        let me = self.server_id();
        let held = self
            .store
            .get_vault(vault)
            .await?
            .filter(|v| v.policy == Policy::Federated && v.holds(me) && v.holds(peer));
        if held.is_none() || peer == me {
            return Ok(None);
        }
        let waiting = self.waiting_for(peer, vault).await?;
        if waiting.changes == 0 {
            return Ok(None);
        }
        let latest = self.store.latest(vault).await?;
        self.store.withhold(peer, vault, &latest, now).await?;
        Ok(Some(Cancelled {
            dropped: waiting.changes,
            at_least: waiting.at_least,
        }))
    }
}
