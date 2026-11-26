//! An in-memory `SpaceRepo`, a fingerprint fake over `kemlock-crypto`, and a `SpaceWorld` that wires
//! the spaces use cases to them and to the fakes of `fakes/mod.rs`. A test file includes both
//! with `mod fakes;` and `mod space_fakes;`.
#![allow(dead_code, unused_imports)]

use crate::fakes::{FakeEnv, FakeNotifier, FakeStore, World, actor, make_user};
use kemlock_app::Actor;
use kemlock_app::SyncDelta;
use kemlock_app::ports::{ItemStore, StoreError};
use kemlock_app::spaces::{
    AcceptInvitation, AppendOutcome, ApplyGroupRules, BundleFingerprints, ChainAppend, ChainHead,
    ChangeRole, ConfirmInput, ConfirmMember, ConfirmationFacts, CreateCollection,
    CreateCollectionInput, CreateGroup, CreateGroupInput, CreateSpace, CreateSpaceInput,
    DeleteCollection, DeleteGroup, EditCollection, EditGroup, GetSpace, GrantAccess, InviteInput,
    InviteMember, KeyReplacement, ListMembers, ListSpaces, NewCollection, Offboard,
    PendingExternal, PutSpaceBatch, PutSpaceItem, RecoveryBox, ReplaceKeys, RevokeGrant,
    SealedCollectionKey, SpaceChainRepo, SpaceChanges, SpaceFacts, SpaceItemInfo,
    SpaceRecoveryRepo, SpaceRepo, StoredRecord, StoredSeal, SyncOwners,
};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee,
    Group, GroupId, KeyCopy, Member, SEALED_KEY_LEN, Space, SpaceRole, SpaceState,
};
use kemlock_domain::{
    Item, ItemDraft, ItemFormat, ItemId, ItemKind, ItemWrite, Owner, Revision, Sealed, SpaceId,
    UserId, VersionVector,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
struct Inner {
    spaces: BTreeMap<SpaceId, Space>,
    members: BTreeMap<(SpaceId, UserId), Member>,
    groups: BTreeMap<GroupId, Group>,
    collections: BTreeMap<CollectionId, Collection>,
    grants: Vec<CollectionGrant>,
    copies: BTreeMap<(CollectionId, UserId), KeyCopy>,
    item_collections: BTreeMap<ItemId, CollectionId>,
    require_sso: BTreeSet<SpaceId>,
    chains: BTreeMap<SpaceId, Vec<StoredRecord>>,
    chain_seals: Vec<(SpaceId, StoredSeal)>,
    pending: Vec<PendingExternal>,
    done: BTreeSet<uuid::Uuid>,
    held: BTreeSet<ItemId>,
    recovery: BTreeMap<(SpaceId, UserId), RecoveryBox>,
}

/// `SpaceRepo` over maps. Items live in `I`, the item store of the test's world, so a space item
/// written here is visible to `changes_since` there.
pub(crate) struct FakeSpaces<I> {
    inner: Arc<Mutex<Inner>>,
    items: I,
}

impl<I: Clone> Clone for FakeSpaces<I> {
    fn clone(&self) -> Self {
        FakeSpaces {
            inner: Arc::clone(&self.inner),
            items: self.items.clone(),
        }
    }
}

fn apply_in(g: &mut Inner, c: SpaceChanges) {
    let space = c.space_id;
    for user in &c.members_removed {
        g.members.remove(&(space, *user));
        let in_space: BTreeSet<CollectionId> = g
            .collections
            .values()
            .filter(|x| x.space == space)
            .map(|x| x.id)
            .collect();
        g.grants.retain(|gr| {
            !(in_space.contains(&gr.collection) && gr.grantee == Grantee::Member(*user))
        });
        g.copies
            .retain(|(col, u), _| !(*u == *user && in_space.contains(col)));
        for group in g.groups.values_mut().filter(|x| x.space == space) {
            group.members.remove(user);
        }
    }
    for id in &c.groups_removed {
        g.groups.remove(id);
        g.grants.retain(|gr| gr.grantee != Grantee::Group(*id));
    }
    for id in &c.collections_removed {
        g.collections.remove(id);
        g.grants.retain(|gr| gr.collection != *id);
        g.copies.retain(|(col, _), _| *col != *id);
        g.item_collections.retain(|_, col| *col != *id);
    }
    for (collection, grantee) in &c.grants_removed {
        g.grants
            .retain(|gr| !(gr.collection == *collection && gr.grantee == *grantee));
    }
    for (collection, user) in &c.key_copies_removed {
        g.copies.remove(&(*collection, *user));
    }
    if let Some(s) = c.space {
        g.spaces.insert(s.id, s);
    }
    for m in c.members {
        g.members.insert((m.space, m.user), m);
    }
    for group in c.groups {
        g.groups.insert(group.id, group);
    }
    for collection in c.collections {
        g.collections.insert(collection.id, collection);
    }
    for grant in c.grants {
        g.grants
            .retain(|x| !(x.collection == grant.collection && x.grantee == grant.grantee));
        g.grants.push(grant);
    }
    for copy in c.key_copies {
        g.copies.insert((copy.collection, copy.user), copy);
    }
}

/// Whether `c` names a collection or group of another space, or a row that says it is another
/// space's: the SQL store refuses these (`Duplicate`) instead of taking the row over.
fn foreign(g: &Inner, c: &SpaceChanges) -> bool {
    let space = c.space_id;
    let other_collection =
        |id: &CollectionId| g.collections.get(id).is_some_and(|x| x.space != space);
    let other_group = |id: &GroupId| g.groups.get(id).is_some_and(|x| x.space != space);
    let other_grantee =
        |grantee: &Grantee| matches!(grantee, Grantee::Group(group) if other_group(group));
    c.collections
        .iter()
        .any(|x| x.space != space || other_collection(&x.id))
        || c.collections_removed.iter().any(other_collection)
        || c.groups
            .iter()
            .any(|x| x.space != space || other_group(&x.id))
        || c.groups_removed.iter().any(other_group)
        || c.members.iter().any(|m| m.space != space)
        || c.grants
            .iter()
            .any(|x| other_collection(&x.collection) || other_grantee(&x.grantee))
        || c.grants_removed
            .iter()
            .any(|(col, grantee)| other_collection(col) || other_grantee(grantee))
        || c.key_copies.iter().any(|k| other_collection(&k.collection))
        || c.key_copies_removed
            .iter()
            .any(|(col, _)| other_collection(col))
}

/// What the SQL store does with a held item that a space item write has replaced (I4): a
/// tombstone, or a revision under the collection's current key version, releases it.
fn release_written(g: &mut Inner, item: &Item, collection: Option<CollectionId>) {
    let current = collection
        .and_then(|c| g.collections.get(&c))
        .map(|c| c.key_version);
    if item.is_tombstone() || current == Some(item.key_version) {
        g.held.remove(&item.id);
    }
}

impl<I> FakeSpaces<I> {
    pub(crate) fn new(items: I) -> Self {
        FakeSpaces {
            inner: Arc::new(Mutex::new(Inner::default())),
            items,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("the spaces lock isn't poisoned")
    }

    fn state_of(g: &Inner, id: SpaceId) -> Option<SpaceState> {
        let space = g.spaces.get(&id)?.clone();
        let collections: Vec<Collection> = g
            .collections
            .values()
            .filter(|c| c.space == id)
            .cloned()
            .collect();
        let ids: BTreeSet<CollectionId> = collections.iter().map(|c| c.id).collect();
        Some(SpaceState {
            space,
            members: g
                .members
                .values()
                .filter(|m| m.space == id)
                .cloned()
                .collect(),
            groups: g
                .groups
                .values()
                .filter(|x| x.space == id)
                .cloned()
                .collect(),
            collections,
            grants: g
                .grants
                .iter()
                .filter(|gr| ids.contains(&gr.collection))
                .copied()
                .collect(),
        })
    }

    /// The space as stored; panics when it isn't there.
    pub(crate) fn state(&self, id: SpaceId) -> SpaceState {
        Self::state_of(&self.lock(), id).expect("the space exists")
    }

    pub(crate) fn copy(&self, collection: CollectionId, user: UserId) -> Option<KeyCopy> {
        self.lock().copies.get(&(collection, user)).cloned()
    }

    /// Who holds a key copy of `collection`.
    pub(crate) fn holders_of(&self, collection: CollectionId) -> BTreeSet<UserId> {
        self.lock()
            .copies
            .keys()
            .filter(|(c, _)| *c == collection)
            .map(|(_, u)| *u)
            .collect()
    }

    pub(crate) fn item_collection(&self, item: ItemId) -> Option<CollectionId> {
        self.lock().item_collections.get(&item).copied()
    }

    pub(crate) fn member(&self, space: SpaceId, user: UserId) -> Option<Member> {
        self.lock().members.get(&(space, user)).cloned()
    }
}

impl<I: ItemStore> SpaceRepo for FakeSpaces<I> {
    async fn load(&self, id: SpaceId) -> Result<Option<SpaceState>, StoreError> {
        Ok(Self::state_of(&self.lock(), id))
    }

    async fn memberships(&self, user: UserId) -> Result<Vec<Member>, StoreError> {
        Ok(self
            .lock()
            .members
            .values()
            .filter(|m| m.user == user)
            .cloned()
            .collect())
    }

    async fn spaces(&self, ids: &[SpaceId]) -> Result<Vec<Space>, StoreError> {
        let g = self.lock();
        Ok(ids
            .iter()
            .filter_map(|id| g.spaces.get(id).cloned())
            .collect())
    }

    async fn collection_space(&self, id: CollectionId) -> Result<Option<SpaceId>, StoreError> {
        Ok(self.lock().collections.get(&id).map(|c| c.space))
    }

    async fn group_space(&self, id: GroupId) -> Result<Option<SpaceId>, StoreError> {
        Ok(self.lock().groups.get(&id).map(|x| x.space))
    }

    async fn key_copies(&self, space: SpaceId, user: UserId) -> Result<Vec<KeyCopy>, StoreError> {
        let g = self.lock();
        Ok(g.copies
            .values()
            .filter(|k| {
                k.user == user
                    && g.collections
                        .get(&k.collection)
                        .is_some_and(|c| c.space == space)
            })
            .cloned()
            .collect())
    }

    async fn holders(&self, space: SpaceId) -> Result<Vec<(CollectionId, UserId)>, StoreError> {
        let g = self.lock();
        Ok(g.copies
            .keys()
            .filter(|(c, _)| g.collections.get(c).is_some_and(|x| x.space == space))
            .copied()
            .collect())
    }

    async fn space_items(&self, space: SpaceId) -> Result<Vec<SpaceItemInfo>, StoreError> {
        let page = self
            .items
            .changes_since(&[Owner::Space(space)], &VersionVector::new(), u32::MAX)
            .await?;
        let g = self.lock();
        Ok(page
            .items
            .iter()
            .map(|i| SpaceItemInfo {
                id: i.id,
                collection: g.item_collections.get(&i.id).copied(),
                format: i.format,
                key_version: i.key_version,
                revision: i.revision,
                deleted: i.is_tombstone(),
            })
            .collect())
    }

    async fn item_collections(
        &self,
        items: &[ItemId],
    ) -> Result<Vec<(ItemId, CollectionId)>, StoreError> {
        let g = self.lock();
        Ok(items
            .iter()
            .filter_map(|i| g.item_collections.get(i).map(|c| (*i, *c)))
            .collect())
    }

    async fn create(&self, changes: SpaceChanges) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.spaces.contains_key(&changes.space_id) {
            return Err(StoreError::Duplicate);
        }
        if foreign(&g, &changes) {
            return Err(StoreError::Duplicate);
        }
        apply_in(&mut g, changes);
        Ok(())
    }

    async fn apply(&self, changes: SpaceChanges) -> Result<(), StoreError> {
        let mut g = self.lock();
        if foreign(&g, &changes) {
            return Err(StoreError::Duplicate);
        }
        apply_in(&mut g, changes);
        Ok(())
    }

    async fn put_item(
        &self,
        draft: ItemDraft,
        collection: CollectionId,
    ) -> Result<Item, StoreError> {
        let item = self.items.put(draft).await?;
        let mut g = self.lock();
        g.item_collections.insert(item.id, collection);
        release_written(&mut g, &item, Some(collection));
        Ok(item)
    }

    async fn require_sso_of(&self, spaces: &[SpaceId]) -> Result<Vec<SpaceId>, StoreError> {
        let g = self.lock();
        Ok(spaces
            .iter()
            .filter(|s| g.require_sso.contains(s))
            .copied()
            .collect())
    }

    async fn set_require_sso(&self, space: SpaceId, on: bool) -> Result<(), StoreError> {
        let mut g = self.lock();
        if on {
            g.require_sso.insert(space);
        } else {
            g.require_sso.remove(&space);
        }
        Ok(())
    }

    async fn put_items(
        &self,
        writes: Vec<(ItemDraft, Option<CollectionId>)>,
    ) -> Result<Vec<Item>, StoreError> {
        let (drafts, collections): (Vec<ItemDraft>, Vec<Option<CollectionId>>) =
            writes.into_iter().unzip();
        let stored = self.items.put_batch(drafts).await?;
        let mut g = self.lock();
        for (item, collection) in stored.iter().zip(collections) {
            if let Some(collection) = collection {
                g.item_collections.insert(item.id, collection);
                release_written(&mut g, item, Some(collection));
            }
        }
        Ok(stored)
    }

    async fn is_chained(&self, space: SpaceId) -> Result<bool, StoreError> {
        Ok(self.lock().chains.contains_key(&space))
    }

    async fn chain_confirmed_members(
        &self,
        space: SpaceId,
    ) -> Result<Option<std::collections::BTreeSet<UserId>>, StoreError> {
        kemlock_app::spaces::chain_confirmed(self, space).await
    }

    async fn queue_external(&self, change: PendingExternal) -> Result<(), StoreError> {
        self.lock().pending.push(change);
        Ok(())
    }

    async fn hold_items(&self, _space: SpaceId, items: &[ItemId]) -> Result<(), StoreError> {
        self.lock().held.extend(items.iter().copied());
        Ok(())
    }

    async fn held_items(&self, _space: SpaceId) -> Result<Vec<ItemId>, StoreError> {
        Ok(self.lock().held.iter().copied().collect())
    }

    async fn held_collections(
        &self,
        spaces: &[SpaceId],
    ) -> Result<Vec<(SpaceId, CollectionId)>, StoreError> {
        let g = self.lock();
        let mut out = BTreeSet::new();
        for item in &g.held {
            let Some(collection) = g.item_collections.get(item) else {
                continue;
            };
            if let Some(space) = g.collections.get(collection).map(|c| c.space)
                && spaces.contains(&space)
            {
                out.insert((space, *collection));
            }
        }
        Ok(out.into_iter().collect())
    }

    async fn replace_keys(&self, replacement: KeyReplacement) -> Result<Vec<Item>, StoreError> {
        let KeyReplacement { changes, writes } = replacement;
        let (drafts, collections): (Vec<ItemDraft>, Vec<CollectionId>) = writes.into_iter().unzip();
        let stored = self.items.put_batch(drafts).await?;
        let mut g = self.lock();
        for (item, collection) in stored.iter().zip(collections) {
            g.item_collections.insert(item.id, collection);
        }
        apply_in(&mut g, changes);
        Ok(stored)
    }
}

/// Fingerprints through `kemlock-crypto`'s bundle, so the tests compare the real thing.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FakeFingerprints;

impl BundleFingerprints for FakeFingerprints {
    fn fingerprint(&self, bundle: &[u8]) -> Option<[u8; 64]> {
        kemlock_crypto::bundle::Bundle::from_bytes(bundle)
            .ok()
            .map(|b| b.fingerprint())
    }

    /// A confirmation passes when it carries `signature()`: the real check is `kemlock-crypto`'s,
    /// and runs in the API tests with real keys.
    fn verify_confirmation(
        &self,
        _confirmer_bundle: &[u8],
        _facts: &ConfirmationFacts<'_>,
        _statement: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == self::signature().as_slice()
    }
}

/// A sealed-looking collection or space key (the right length and version byte).
pub(crate) fn sealed_key(fill: u8) -> Vec<u8> {
    let mut key = vec![fill; SEALED_KEY_LEN];
    key[0] = 1;
    key
}

/// A sealed-looking name.
pub(crate) fn name(fill: u8) -> Vec<u8> {
    vec![fill; 40]
}

pub(crate) fn signature() -> Vec<u8> {
    vec![0x55; kemlock_domain::spaces::CONFIRMATION_SIGNATURE_LEN]
}

/// A collection key sealed to `user`.
pub(crate) fn key_for(collection: CollectionId, user: UserId, fill: u8) -> SealedCollectionKey {
    SealedCollectionKey {
        collection,
        user,
        sealed: sealed_key(fill),
    }
}

pub(crate) type Spaces = FakeSpaces<FakeStore>;

/// The fakes of `World`, plus a space store over its item store.
pub(crate) struct SpaceWorld {
    pub(crate) world: World,
    pub(crate) spaces: Spaces,
}

impl SpaceWorld {
    pub(crate) fn new() -> Self {
        let world = World::new().with_signups();
        let spaces = FakeSpaces::new(world.store.clone());
        SpaceWorld { world, spaces }
    }

    pub(crate) async fn user(&self, email: &str) -> UserId {
        make_user(&self.world, email).await
    }

    pub(crate) fn create_space(&self) -> CreateSpace<Spaces, FakeStore, FakeEnv> {
        CreateSpace {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn invite(&self) -> InviteMember<Spaces, FakeStore, FakeStore, FakeEnv> {
        InviteMember {
            spaces: self.spaces.clone(),
            users: self.world.store.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn accept(&self) -> AcceptInvitation<Spaces, FakeStore, FakeEnv> {
        AcceptInvitation {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn confirm(
        &self,
    ) -> ConfirmMember<Spaces, FakeStore, FakeFingerprints, FakeStore, FakeEnv> {
        ConfirmMember {
            spaces: self.spaces.clone(),
            users: self.world.store.clone(),
            fingerprints: FakeFingerprints,
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn change_role(&self) -> ChangeRole<Spaces, FakeStore, FakeEnv> {
        ChangeRole {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn offboard(&self) -> Offboard<Spaces, FakeStore, FakeEnv> {
        Offboard {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn apply_group_rules(&self) -> ApplyGroupRules<Spaces, FakeStore, FakeEnv> {
        ApplyGroupRules {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn list_spaces(&self) -> ListSpaces<Spaces> {
        ListSpaces {
            spaces: self.spaces.clone(),
        }
    }

    pub(crate) fn get_space(&self) -> GetSpace<Spaces> {
        GetSpace {
            spaces: self.spaces.clone(),
        }
    }

    pub(crate) fn list_members(&self) -> ListMembers<Spaces, FakeStore> {
        ListMembers {
            spaces: self.spaces.clone(),
            users: self.world.store.clone(),
        }
    }

    pub(crate) fn create_collection(&self) -> CreateCollection<Spaces, FakeStore, FakeEnv> {
        CreateCollection {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn edit_collection(&self) -> EditCollection<Spaces, FakeStore, FakeEnv> {
        EditCollection {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn delete_collection(&self) -> DeleteCollection<Spaces, FakeStore, FakeEnv> {
        DeleteCollection {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn create_group(&self) -> CreateGroup<Spaces, FakeStore, FakeEnv> {
        CreateGroup {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn edit_group(&self) -> EditGroup<Spaces, FakeStore, FakeEnv> {
        EditGroup {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn delete_group(&self) -> DeleteGroup<Spaces, FakeStore, FakeEnv> {
        DeleteGroup {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn grant(&self) -> GrantAccess<Spaces, FakeStore, FakeEnv> {
        GrantAccess {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn revoke_grant(&self) -> RevokeGrant<Spaces, FakeStore, FakeEnv> {
        RevokeGrant {
            spaces: self.spaces.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    pub(crate) fn replace_keys(
        &self,
    ) -> ReplaceKeys<Spaces, FakeStore, FakeStore, FakeStore, FakeNotifier, FakeEnv> {
        ReplaceKeys {
            spaces: self.spaces.clone(),
            items: self.world.store.clone(),
            tags: self.world.store.clone(),
            events: self.world.store.clone(),
            push: self.world.notifier.clone(),
            clock: self.world.env.clone(),
            config: self.world.config,
        }
    }

    pub(crate) fn put_space_item(
        &self,
    ) -> PutSpaceItem<Spaces, FakeStore, FakeStore, FakeNotifier, FakeEnv> {
        PutSpaceItem {
            spaces: self.spaces.clone(),
            items: self.world.store.clone(),
            events: self.world.store.clone(),
            push: self.world.notifier.clone(),
            clock: self.world.env.clone(),
            config: self.world.config,
        }
    }

    pub(crate) fn put_space_batch(
        &self,
    ) -> PutSpaceBatch<Spaces, FakeStore, FakeStore, FakeNotifier, FakeEnv> {
        PutSpaceBatch {
            spaces: self.spaces.clone(),
            items: self.world.store.clone(),
            events: self.world.store.clone(),
            push: self.world.notifier.clone(),
            clock: self.world.env.clone(),
            config: self.world.config,
        }
    }

    pub(crate) fn facts(&self) -> SpaceFacts<Spaces> {
        SpaceFacts {
            spaces: self.spaces.clone(),
        }
    }

    pub(crate) fn sync_owners(&self) -> SyncOwners<Spaces> {
        SyncOwners {
            spaces: self.spaces.clone(),
        }
    }

    pub(crate) fn sync_delta(&self) -> SyncDelta<FakeStore, Spaces> {
        SyncDelta {
            items: self.world.store.clone(),
            spaces: self.spaces.clone(),
        }
    }

    // ---- scenario helpers: each runs real use cases ----

    /// `owner` makes a space with one collection ("Everyone"), and the owner holds both keys.
    pub(crate) async fn make_space(&self, owner: UserId) -> (SpaceId, CollectionId) {
        let space = SpaceId::random();
        let collection = CollectionId::random();
        self.create_space()
            .execute(
                &actor(owner),
                CreateSpaceInput {
                    id: space,
                    name: name(1),
                    sealed_space_key: sealed_key(2),
                    collection: NewCollection {
                        id: collection,
                        name: name(3),
                        sealed_key: sealed_key(4),
                    },
                },
            )
            .await
            .expect("the space is made");
        (space, collection)
    }

    /// The fingerprint of `user`'s bundle, as their app would show it.
    pub(crate) fn fingerprint_of(&self, user: UserId) -> Vec<u8> {
        let account = self.world.store.user(user).expect("the user exists");
        FakeFingerprints
            .fingerprint(&account.public_bundle)
            .expect("the bundle parses")
            .to_vec()
    }

    /// A confirmation of `member` with the right fingerprint, the space key and `keys`.
    pub(crate) fn confirm_input(
        &self,
        member: UserId,
        collection_keys: Vec<SealedCollectionKey>,
    ) -> ConfirmInput {
        ConfirmInput {
            fingerprint: self.fingerprint_of(member),
            statement: b"I compared the fingerprint".to_vec(),
            signature: signature(),
            sealed_space_key: sealed_key(9),
            collection_keys,
        }
    }

    /// `inviter` invites `member` with `role` and the given grants, `member` accepts, and
    /// `confirmer` confirms them with sealed keys for every collection they are granted.
    pub(crate) async fn join(
        &self,
        space: SpaceId,
        inviter: UserId,
        confirmer: UserId,
        member: UserId,
        role: SpaceRole,
        grants: Vec<(CollectionId, CollectionPermission)>,
    ) {
        let email = self
            .world
            .store
            .user(member)
            .expect("the user exists")
            .email
            .as_str()
            .to_owned();
        let keys = grants
            .iter()
            .map(|(collection, _)| key_for(*collection, member, 5))
            .collect();
        self.invite()
            .execute(
                &actor(inviter),
                space,
                InviteInput {
                    email,
                    role,
                    custom: CustomPermissions::NONE,
                    grants,
                },
            )
            .await
            .expect("the invitation is made");
        self.accept()
            .execute(&actor(member), space)
            .await
            .expect("the invitation is accepted");
        self.confirm()
            .execute(
                &actor(confirmer),
                space,
                member,
                self.confirm_input(member, keys),
            )
            .await
            .expect("the member is confirmed");
    }

    /// A new space item write into `space`, sealed under `key_version`.
    pub(crate) fn item_write(
        &self,
        space: SpaceId,
        id: ItemId,
        expected: Option<u64>,
        revision: u64,
        key_version: u32,
    ) -> ItemWrite {
        ItemWrite {
            id,
            owner: Owner::Space(space),
            kind: ItemKind::try_from("login".to_owned()).expect("a valid kind"),
            format: ItemFormat::Kem1,
            expected: expected.map(Revision),
            revision: Revision(revision),
            key_version,
            sealed: Some(Sealed {
                ciphertext: vec![0xaa; 64],
                item_key: vec![0xbb; kemlock_domain::item::ITEM_KEY_LEN],
            }),
        }
    }
}

impl<I: ItemStore> SpaceChainRepo for FakeSpaces<I> {
    async fn chain_head(&self, space: SpaceId) -> Result<Option<ChainHead>, StoreError> {
        Ok(self
            .lock()
            .chains
            .get(&space)
            .and_then(|c| c.last())
            .map(|r| ChainHead {
                seq: r.seq,
                link: r.link,
                epoch: r.epoch,
            }))
    }

    async fn chain_records(
        &self,
        space: SpaceId,
        from: u64,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .lock()
            .chains
            .get(&space)
            .map(|c| c.iter().filter(|r| r.seq >= from).cloned().collect())
            .unwrap_or_default())
    }

    async fn chain_seals(&self, space: SpaceId, seq: u64) -> Result<Vec<StoredSeal>, StoreError> {
        Ok(self
            .lock()
            .chain_seals
            .iter()
            .filter(|(s, seal)| *s == space && seal.seq == seq)
            .map(|(_, seal)| seal.clone())
            .collect())
    }

    async fn chain_append(
        &self,
        space: SpaceId,
        append: ChainAppend,
    ) -> Result<AppendOutcome, StoreError> {
        let mut g = self.lock();
        let head = g
            .chains
            .get(&space)
            .and_then(|c| c.last())
            .map(|r| ChainHead {
                seq: r.seq,
                link: r.link,
                epoch: r.epoch,
            });
        if head != append.expected {
            return Ok(AppendOutcome::Stale(head));
        }
        if foreign(&g, &append.changes) {
            return Err(StoreError::Duplicate);
        }
        let last = append.records.last().map(|r| ChainHead {
            seq: r.seq,
            link: r.link,
            epoch: r.epoch,
        });
        g.chains.entry(space).or_default().extend(append.records);
        for seal in append.seals {
            g.chain_seals.push((space, seal));
        }
        if let Some(id) = append.answers {
            g.done.insert(id);
            g.pending.retain(|p| p.id != id);
        }
        g.held.extend(append.held);
        apply_in(&mut g, append.changes);
        // The items a key replacement re-wrote, stored with the records.
        let (drafts, collections): (Vec<ItemDraft>, Vec<CollectionId>) =
            append.writes.into_iter().unzip();
        drop(g);
        if !drafts.is_empty() {
            let stored = self.items.put_batch(drafts).await?;
            let mut g = self.lock();
            for (item, collection) in stored.iter().zip(collections) {
                g.item_collections.insert(item.id, collection);
            }
        }
        Ok(AppendOutcome::Appended(
            last.expect("an append has records"),
        ))
    }

    async fn pending_external(&self, space: SpaceId) -> Result<Vec<PendingExternal>, StoreError> {
        Ok(self
            .lock()
            .pending
            .iter()
            .filter(|p| p.space == space)
            .cloned()
            .collect())
    }

    async fn pending_external_one(
        &self,
        space: SpaceId,
        id: uuid::Uuid,
    ) -> Result<Option<PendingExternal>, StoreError> {
        Ok(self
            .lock()
            .pending
            .iter()
            .find(|p| p.space == space && p.id == id)
            .cloned())
    }

    async fn dismiss_external(&self, space: SpaceId, id: uuid::Uuid) -> Result<bool, StoreError> {
        let mut g = self.lock();
        let before = g.pending.len();
        g.pending.retain(|p| !(p.space == space && p.id == id));
        Ok(g.pending.len() < before)
    }
}

impl<I: Send + Sync> SpaceRecoveryRepo for FakeSpaces<I> {
    async fn recovery_box(
        &self,
        space: SpaceId,
        user: UserId,
    ) -> Result<Option<RecoveryBox>, StoreError> {
        Ok(self.lock().recovery.get(&(space, user)).cloned())
    }

    async fn put_recovery_box(&self, recovery: RecoveryBox) -> Result<(), StoreError> {
        self.lock()
            .recovery
            .insert((recovery.space, recovery.user), recovery);
        Ok(())
    }

    async fn delete_recovery_box(&self, space: SpaceId, user: UserId) -> Result<bool, StoreError> {
        Ok(self.lock().recovery.remove(&(space, user)).is_some())
    }
}
