//! Sync delta: the items that changed since a cursor, in pages of up to 500.
//!
//! The cursor holds a version vector per owner (`SyncCursor`): a device syncs its own vault and
//! every space it is a confirmed member of, and each owner is read from the vector the device
//! holds for it. An owner the cursor doesn't list, such as a space the device has just joined,
//! is read from the empty vector, so the device receives that space's whole history once, even
//! though it already holds high sequence numbers of the same server from its own vault. The cursor
//! the sync returns lists exactly the owners the device syncs now, so a space the account was
//! removed from drops out of it, and comes back from empty if the account is ever restored.
//!
//! Design choice: a vector per owner, not one vector plus a record, kept by the server, of the
//! change at which each member joined or was granted a collection. The record is a position in
//! this server's own log, so a federation replica that applies the same membership at another
//! position would disagree about what "before the join" means, and a device moving between
//! servers would be sent the wrong history. Version vectors per vault are what replicas already
//! answer (docs/federation.md), and the cursor needs no server-side state. A collection grant
//! needs nothing either: members receive every item envelope of a confirmed space, the
//! collections they aren't granted included (see `spaces::SyncOwners`), so a grant adds a key to
//! envelopes the device already holds. And the cursor is not normalised to one vector at the end
//! of a sync: a replica pulls each vault on its own, so it can hold one vault's changes of an
//! origin up to a higher sequence than another's, and a vector shared between them would claim
//! changes of the lagging vault as seen.
//!
//! Three shortcuts keep a sync cheap and safe. A cursor that already covers the newest change of
//! each owner is "unchanged" (the API's 304). A cursor older than an owner's tombstone horizon
//! can't be trusted to have seen the deletions that were purged, so the client must start a full
//! sync. An empty cursor is that full sync.
//!
//! A key replacement can leave live items **held** (docs/crypto.md, I3 and I4). The reads above
//! leave them out. Every confirmed member of the space is sent them anyway, marked held and with
//! their old key version, so an item the space manifest lists doesn't go missing from a member's
//! copy. The cursor keeps a vector per collection for them, because an owner's vector covers live
//! items and can't say which held ones a device has been sent: a member who joins the space later
//! finds its collections absent from the cursor and is sent their held items, as an owner new to
//! the device is. When a write releases the item it has a new change id and every device gets it
//! as an ordinary change.
//!
//! The horizon is read after the page, never before: a purge that runs in between then shows in
//! the horizon (at worst a needless full sync), whereas reading it first could pair a page that
//! lacks a freshly purged tombstone with a horizon that doesn't mention it, and the client would
//! never learn of the deletion.

use crate::error::AppError;
use crate::ports::ItemStore;
use crate::spaces::SpaceRepo;
use crate::spaces::sync_owners::owners_of;
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{Item, ItemId, Owner, SpaceId, SyncCursor, UserId, VersionVector};
use std::collections::{BTreeMap, BTreeSet};

/// The most items one page holds.
pub const MAX_PAGE: u32 = 500;

/// `spaces` says which spaces the account is confirmed in: a delta covers the account's own
/// vault and each of those spaces (see `spaces::SyncOwners`).
#[derive(Debug)]
pub struct SyncDelta<I, R> {
    pub items: I,
    pub spaces: R,
}

/// One page of a delta sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncPage {
    /// Items (and tombstones) changed after the cursor, in (origin, seq) order, each once at its
    /// latest revision.
    pub items: Vec<Item>,
    /// The items of `items` that are held (I4): sent to every confirmed member of the space,
    /// with the key version they had. A held item is never also live.
    pub held: BTreeSet<ItemId>,
    /// The cursor after this page: a version 2 cursor of the owners the device syncs now.
    pub next: SyncCursor,
    /// Whether another page follows.
    pub more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The cursor covers everything: nothing changed.
    Unchanged,
    /// Changes since the cursor, with the cursor to continue from and whether more follow.
    Page(SyncPage),
}

impl<I: ItemStore, R: SpaceRepo> SyncDelta<I, R> {
    /// `since` is the client's cursor; empty for a first sync. `limit` is clamped to 1..=500.
    pub async fn execute(
        &self,
        actor: UserId,
        since: &SyncCursor,
        limit: Option<u32>,
    ) -> Result<SyncOutcome, AppError> {
        let owners = owners_of(&self.spaces, actor).await?;
        let limit = limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
        // What the device holds of each owner it syncs now; owners it doesn't know are empty.
        let held: Vec<(Owner, VersionVector)> = owners
            .iter()
            .map(|owner| (*owner, since.since(*owner).clone()))
            .collect();
        // The collections whose held items this account is sent, each with what the device has.
        let held_in = self.held_collections(&owners).await?;
        let held_seen: Vec<(CollectionId, VersionVector)> = held_in
            .iter()
            .map(|collection| (*collection, since.held_since(*collection)))
            .collect();

        let page = if since.is_empty() || !self.is_current(&owners, &held_in, since).await? {
            let live = self.items.changes_since_each(&held, limit).await?;
            let held_page = self.items.held_since_each(&held_seen, limit).await?;
            Some(merge(
                live.items,
                live.more,
                held_page.items,
                held_page.more,
                limit,
            ))
        } else {
            None
        };
        // After the page; see the module comment. The horizon covers this account's vault and its
        // spaces: purged tombstones of anything else could not have been on this device. An owner
        // the device holds nothing of reads its full state, so its horizon doesn't matter.
        let purged: BTreeMap<Owner, VersionVector> =
            self.items.purged_each(&owners).await?.into_iter().collect();
        for (owner, seen) in &held {
            let horizon = purged.get(owner);
            if !seen.is_empty() && horizon.is_some_and(|horizon| !seen.dominates(horizon)) {
                return Err(AppError::FullSyncRequired);
            }
        }
        let Some(page) = page else {
            return Ok(SyncOutcome::Unchanged);
        };

        let mut next: BTreeMap<Owner, VersionVector> = held.into_iter().collect();
        let mut next_held: BTreeMap<CollectionId, VersionVector> = held_seen.into_iter().collect();
        let mut held_ids = BTreeSet::new();
        for (item, collection) in &page.items {
            match collection {
                Some(collection) => {
                    held_ids.insert(item.id);
                    if let Some(vector) = next_held.get_mut(collection) {
                        vector.observe(&item.change);
                    }
                }
                None => {
                    if let Some(vector) = next.get_mut(&item.owner) {
                        vector.observe(&item.change);
                    }
                }
            }
        }
        if !page.more {
            // A client that has read everything has also, by reading the current state, handled
            // the deletions that were purged. Without this its cursor would stay behind the
            // horizon and every later sync would demand another full sync.
            for (owner, vector) in &mut next {
                if let Some(horizon) = purged.get(owner) {
                    vector.merge(horizon);
                }
            }
        }
        Ok(SyncOutcome::Page(SyncPage {
            items: page.items.into_iter().map(|(item, _)| item).collect(),
            held: held_ids,
            next: SyncCursor::from_parts(next, next_held),
            more: page.more,
        }))
    }

    /// The collections with held items in the spaces `owners` lists, which are the spaces the
    /// account is confirmed in: every confirmed member is sent their held items (I4), whatever
    /// access they have.
    async fn held_collections(&self, owners: &[Owner]) -> Result<Vec<CollectionId>, AppError> {
        let spaces: Vec<SpaceId> = owners
            .iter()
            .filter_map(|owner| match owner {
                Owner::Space(space) => Some(*space),
                Owner::User(_) => None,
            })
            .collect();
        if spaces.is_empty() {
            return Ok(Vec::new());
        }
        let collections: BTreeSet<CollectionId> = self
            .spaces
            .held_collections(&spaces)
            .await?
            .into_iter()
            .map(|(_, collection)| collection)
            .collect();
        Ok(collections.into_iter().collect())
    }

    /// Whether the cursor covers the newest change of every owner the device syncs now, and of
    /// the held items it is sent.
    async fn is_current(
        &self,
        owners: &[Owner],
        held_in: &[CollectionId],
        since: &SyncCursor,
    ) -> Result<bool, AppError> {
        let latest = self.items.latest_each(owners).await?;
        if !latest
            .iter()
            .all(|(owner, newest)| since.since(*owner).dominates(newest))
        {
            return Ok(false);
        }
        let held = self.items.held_latest_each(held_in).await?;
        Ok(held
            .iter()
            .all(|(collection, newest)| since.held_since(*collection).dominates(newest)))
    }
}

/// The first `limit` of the live items and the held ones together, in (origin, seq) order, each
/// held one with its collection. Each part is a prefix of its own uncovered items in that order, so
/// the first `limit` of both is a prefix of what remains, and a cursor that advances by the items
/// of the page skips nothing (see `EachPage::merge`).
fn merge(
    live: Vec<Item>,
    live_more: bool,
    held: Vec<(CollectionId, Item)>,
    held_more: bool,
    limit: u32,
) -> Merged {
    let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
    let mut items: Vec<(Item, Option<CollectionId>)> = live
        .into_iter()
        .map(|item| (item, None))
        .chain(
            held.into_iter()
                .map(|(collection, item)| (item, Some(collection))),
        )
        .collect();
    items.sort_by_key(|(item, _)| (item.change.origin, item.change.seq));
    let mut more = live_more || held_more;
    if items.len() > limit {
        items.truncate(limit);
        more = true;
    }
    Merged { items, more }
}

/// A page of live and held items before the cursor is built.
struct Merged {
    items: Vec<(Item, Option<CollectionId>)>,
    more: bool,
}
