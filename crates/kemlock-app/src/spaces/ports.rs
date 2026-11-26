//! The ports the spaces use cases call. `kemlock-store-sql` implements [`SpaceRepo`]; tests use an
//! in-memory fake. Like `crate::ports`, async methods return `impl Future + Send`, and every
//! method is cancel-safe.

use super::chain::{ExternalChangeMode, PendingExternal};
use crate::ports::StoreError;
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, Grantee, Group, GroupId, KeyCopy, Member, Space,
    SpaceState,
};
use kemlock_domain::{Item, ItemDraft, ItemFormat, ItemId, Revision, SpaceId, UserId};
use std::collections::BTreeSet;
use std::future::Future;

/// A set of changes to one space, applied in one transaction. Removals apply first, then
/// upserts.
///
/// - `members` are inserted or replaced by `(space, user)`; `members_removed` delete the member's
///   row, their grants, their group memberships and every key copy they hold in the space.
/// - `groups` are inserted or replaced, with their member sets; `groups_removed` delete the group,
///   its members and the grants made to it.
/// - `collections` are inserted or replaced; `collections_removed` delete the collection, its
///   grants, its key copies and the item-to-collection rows that point at it.
/// - Collection and group ids are unique across spaces: a store refuses (`Duplicate`) changes that
///   name a collection or group of another space, in any field, rather than take it over.
/// - `grants` and `key_copies` are inserted or replaced by their keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceChanges {
    /// The space these changes are to.
    pub space_id: SpaceId,
    pub space: Option<Space>,
    pub members: Vec<Member>,
    pub members_removed: Vec<UserId>,
    pub groups: Vec<Group>,
    pub groups_removed: Vec<GroupId>,
    pub collections: Vec<Collection>,
    pub collections_removed: Vec<CollectionId>,
    pub grants: Vec<CollectionGrant>,
    pub grants_removed: Vec<(CollectionId, Grantee)>,
    pub key_copies: Vec<KeyCopy>,
    pub key_copies_removed: Vec<(CollectionId, UserId)>,
}

impl SpaceChanges {
    /// No changes yet, to `space_id`.
    pub fn new(space_id: SpaceId) -> SpaceChanges {
        SpaceChanges {
            space_id,
            space: None,
            members: Vec::new(),
            members_removed: Vec::new(),
            groups: Vec::new(),
            groups_removed: Vec::new(),
            collections: Vec::new(),
            collections_removed: Vec::new(),
            grants: Vec::new(),
            grants_removed: Vec::new(),
            key_copies: Vec::new(),
            key_copies_removed: Vec::new(),
        }
    }
}

/// What the server knows about one item of a space without opening it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceItemInfo {
    pub id: ItemId,
    /// The collection the item is in; `None` only for an item written before collections.
    pub collection: Option<CollectionId>,
    pub format: ItemFormat,
    pub key_version: u32,
    pub revision: Revision,
    /// A tombstone.
    pub deleted: bool,
}

/// A key replacement: the new keys and names, and the items re-wrapped under the new keys, stored
/// together or not at all. Each write is stored as `ItemStore::put_batch` would store it, with
/// its collection recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReplacement {
    pub changes: SpaceChanges,
    pub writes: Vec<(ItemDraft, CollectionId)>,
}

pub trait SpaceRepo: Send + Sync {
    /// The space with its members, groups, collections and grants.
    fn load(
        &self,
        id: SpaceId,
    ) -> impl Future<Output = Result<Option<SpaceState>, StoreError>> + Send;

    /// The account's rows in every space, in any state.
    fn memberships(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send;

    /// The spaces with these ids, as stored.
    fn spaces(
        &self,
        ids: &[SpaceId],
    ) -> impl Future<Output = Result<Vec<Space>, StoreError>> + Send;

    /// The space that holds the collection with this id, if any does. Collection ids are chosen by
    /// clients and are unique across spaces, so creating one checks every space, not only the
    /// caller's.
    fn collection_space(
        &self,
        id: CollectionId,
    ) -> impl Future<Output = Result<Option<SpaceId>, StoreError>> + Send;

    /// The space that holds the group with this id, if any does; see `collection_space`.
    fn group_space(
        &self,
        id: GroupId,
    ) -> impl Future<Output = Result<Option<SpaceId>, StoreError>> + Send;

    /// The collection keys sealed to one member.
    fn key_copies(
        &self,
        space: SpaceId,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<KeyCopy>, StoreError>> + Send;

    /// Who holds a key copy of which collection, as `(collection, member)`.
    fn holders(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<Vec<(CollectionId, UserId)>, StoreError>> + Send;

    /// The space's items, as the server sees them.
    fn space_items(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<Vec<SpaceItemInfo>, StoreError>> + Send;

    /// The collection of each of these items that has one.
    fn item_collections(
        &self,
        items: &[ItemId],
    ) -> impl Future<Output = Result<Vec<(ItemId, CollectionId)>, StoreError>> + Send;

    /// Applies `changes`, which must carry the new space; `Duplicate` when it exists.
    fn create(&self, changes: SpaceChanges) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Applies `changes` in one transaction.
    fn apply(&self, changes: SpaceChanges) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores one space item, as `ItemStore::put` does, and records its collection, in one
    /// transaction. A conflict names the item. The caller has authorized the write (I1, I2), and a
    /// store releases the item if it was held (I4), but keeps it held unless the write is a
    /// tombstone or its `key_version` is the collection's current one.
    fn put_item(
        &self,
        draft: ItemDraft,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Item, StoreError>> + Send;

    /// Stores personal and space items together or not at all, as `ItemStore::put_batch` stores
    /// drafts, and records the collection of each item that has one. A conflict names the item.
    /// Held items are released as `put_item` releases them.
    fn put_items(
        &self,
        writes: Vec<(ItemDraft, Option<CollectionId>)>,
    ) -> impl Future<Output = Result<Vec<Item>, StoreError>> + Send;

    /// Which of these spaces have the "Require SSO" policy on. A space with no stored policy
    /// doesn't. It reads the same policies as `PolicyRepo`: a store keeps them in one place.
    fn require_sso_of(
        &self,
        spaces: &[SpaceId],
    ) -> impl Future<Output = Result<Vec<SpaceId>, StoreError>> + Send;

    /// Turns the "Require SSO" policy of a space on or off, leaving its other policies as they
    /// are. It writes the same policies as `PolicyRepo`; the use cases set them through that.
    fn set_require_sso(
        &self,
        space: SpaceId,
        on: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Applies a key replacement in one transaction: the changes and every write, or nothing.
    fn replace_keys(
        &self,
        replacement: KeyReplacement,
    ) -> impl Future<Output = Result<Vec<Item>, StoreError>> + Send;

    /// Whether the space has a chain: its members, roles, keys and policies then change only by
    /// signed records (docs/crypto.md, "Space chain"). A store without chains keeps this default.
    fn is_chained(&self, _space: SpaceId) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }

    /// The members the chain of a chained space says are confirmed (`spaces::chain_confirmed`),
    /// or `None` for a space with no chain. A store without chains keeps this default.
    ///
    /// The members table says "confirmed" too, but on a chained space only the chain may: what
    /// asks whether someone is confirmed of a chained space (sync, policies) asks here.
    fn chain_confirmed_members(
        &self,
        _space: SpaceId,
    ) -> impl Future<Output = Result<Option<BTreeSet<UserId>>, StoreError>> + Send {
        async { Ok(None) }
    }

    /// What happens to a change from outside Kemlock clients on a chained space: the setting
    /// `space_chain_external_changes`, `refuse` unless it says otherwise.
    fn external_change_mode(
        &self,
    ) -> impl Future<Output = Result<ExternalChangeMode, StoreError>> + Send {
        async { Ok(ExternalChangeMode::Queue) }
    }

    /// Keeps a change from outside Kemlock clients for the space's admins to sign as a record.
    fn queue_external(
        &self,
        _change: PendingExternal,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// Marks live items as held by a key replacement: kept, but not served as live, and counted as
    /// covered by the replacement's completeness check.
    fn hold_items(
        &self,
        _space: SpaceId,
        _items: &[ItemId],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async { Ok(()) }
    }

    /// The collections of these spaces that hold held items, with their space: the ones every
    /// confirmed member of the space is sent those items from (I4).
    fn held_collections(
        &self,
        _spaces: &[SpaceId],
    ) -> impl Future<Output = Result<Vec<(SpaceId, CollectionId)>, StoreError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// The items a key replacement held, still awaiting a client that can read them.
    fn held_items(
        &self,
        _space: SpaceId,
    ) -> impl Future<Output = Result<Vec<ItemId>, StoreError>> + Send {
        async { Ok(Vec::new()) }
    }
}

/// What a confirmation of a member says, as the server knows it: the statement the confirmer
/// signs is built from exactly these (docs/crypto.md, "Member confirmation").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationFacts<'a> {
    pub space: SpaceId,
    pub member: UserId,
    /// The key version of the member's bundle, which the fingerprint belongs to.
    pub member_key_version: u32,
    /// The fingerprint the confirmer compared.
    pub fingerprint: &'a [u8],
    pub confirmer: UserId,
}

/// What the server asks of `kemlock-crypto` about public-key bundles: their fingerprints
/// (docs/crypto.md: `SHA-512("kemlock/v1/fingerprint" ‖ bundle)`), and whether a confirmation is
/// signed with the confirmer's key. The server wires it to `kemlock-crypto`.
pub trait BundleFingerprints: Send + Sync {
    /// The 64-byte fingerprint of an encoded bundle, or `None` when it doesn't parse.
    fn fingerprint(&self, bundle: &[u8]) -> Option<[u8; 64]>;

    /// Whether `statement` is exactly the statement of `facts` and `signature` is the `sig1`
    /// signature over it, under context `"confirm"`, of the key in `confirmer_bundle`.
    fn verify_confirmation(
        &self,
        confirmer_bundle: &[u8],
        facts: &ConfirmationFacts<'_>,
        statement: &[u8],
        signature: &[u8],
    ) -> bool;
}
