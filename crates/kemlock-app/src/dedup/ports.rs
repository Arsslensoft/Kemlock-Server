//! The ports of the duplicate cleaner. `kemlock-store-sql` implements them on `item_tags`,
//! `duplicate_dismissals` and `dedup_owners`; tests use an in-memory fake. Like `crate::ports`,
//! async methods return `impl Future + Send` and every method is cancel-safe.

use crate::ports::StoreError;
use kemlock_domain::{
    Dismissal, DismissalId, DuplicateGroup, ItemId, MatchingSettings, Owner, Revision, TagSet,
    UserId,
};
use std::future::Future;
use time::OffsetDateTime;

/// Tags, the dedup key version and the on/off switch of server matching.
///
/// Whatever writes an item (the Kemlock API, the Bitwarden API, a space, a key replacement) clears
/// that item's tags in the same transaction, so a tag never outlives the revision it was made
/// for. A write that carries tags stores them afterwards with [`put_tags`](Self::put_tags).
pub trait TagStore: Send + Sync {
    /// The owner's settings; [`MatchingSettings::initial`] when nobody has chosen yet.
    fn settings(
        &self,
        owner: Owner,
    ) -> impl Future<Output = Result<MatchingSettings, StoreError>> + Send;

    /// Turns server matching on or off. Turning it off deletes every tag of the owner in the same
    /// transaction. Returns the settings as stored.
    fn set_matching(
        &self,
        owner: Owner,
        enabled: bool,
        by: UserId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<MatchingSettings, StoreError>> + Send;

    /// A new user key or space key: deletes the owner's tags and moves the dedup key version up by
    /// one. Returns the new version.
    fn bump_version(
        &self,
        owner: Owner,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<u32, StoreError>> + Send;

    /// Replaces the tags of `item` with `tags`, if the item is `owner`'s, live and at `revision`;
    /// `false` (and nothing changed) when it isn't. An empty set clears the item's tags.
    fn put_tags(
        &self,
        owner: Owner,
        item: ItemId,
        revision: Revision,
        tags: &TagSet,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// The other live items of `owner` whose tags at their current revision and `version` share a
    /// tag with `item`'s, sorted.
    fn matches(
        &self,
        owner: Owner,
        version: u32,
        item: ItemId,
    ) -> impl Future<Output = Result<Vec<ItemId>, StoreError>> + Send;

    /// The owner's groups under `version`: items sharing a tag, each at its current revision,
    /// tombstones skipped (see [`kemlock_domain::dedup::group_pairs`]).
    fn groups(
        &self,
        owner: Owner,
        version: u32,
    ) -> impl Future<Output = Result<Vec<DuplicateGroup>, StoreError>> + Send;

    /// How many live items of the owner have no tags under `version` at their current revision.
    fn waiting(
        &self,
        owner: Owner,
        version: u32,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// "Not duplicates" answers, seen by every member of the owner.
pub trait DismissalStore: Send + Sync {
    fn add(&self, dismissal: &Dismissal) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn get(
        &self,
        id: DismissalId,
    ) -> impl Future<Output = Result<Option<Dismissal>, StoreError>> + Send;

    /// The owner's answers, oldest first.
    fn list(&self, owner: Owner)
    -> impl Future<Output = Result<Vec<Dismissal>, StoreError>> + Send;

    /// Whether there was one to remove.
    fn remove(&self, id: DismissalId) -> impl Future<Output = Result<bool, StoreError>> + Send;
}
