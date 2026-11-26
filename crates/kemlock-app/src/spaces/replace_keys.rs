//! Replace keys: the second half of offboarding.
//!
//! Revoking or removing a member (or taking a collection away from one) marks the keys they held
//! for replacement and pauses writes. The client then makes new keys, seals them to the members
//! who stay, encrypts the names again under the new space key and re-wraps every item of the
//! replaced collections, and sends it all here. The server takes it as one transaction: new key
//! versions, new sealed copies, new names and the re-wrapped items, or nothing. Until it lands,
//! item writes into the paused space or collection are refused.
//!
//! The server can't open anything it is sent, so it checks completeness instead: exactly the
//! members who may hold a key got a copy, every name is replaced, and every live `kem1` item of a
//! replaced collection is written again under the new key version.
//!
//! The duplicate cleaner's tags are HMACs under a key derived from the space key, so replacing the
//! space key moves the space's dedup key version and deletes its tags (`TagStore::bump_version`,
//! the step `RotateDedupKey` names); a tag of the old version then matches nothing. Replacing only
//! collection keys leaves it alone: the dedup key doesn't come from them.

use super::error::SpacesError;
use super::ports::{KeyReplacement, SpaceChanges, SpaceItemInfo, SpaceRepo};
use super::support::{SealedCollectionKey, load_open, record};
use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::dedup::TagStore;
use crate::ports::{Clock, EventLog, ItemStore, Notifier};
use kemlock_domain::spaces::{
    Collection, CollectionId, Group, GroupId, KeyCopy, SpaceError, SpaceRole, apply_space_write,
    check_sealed_key, check_sealed_name,
};
use kemlock_domain::{Item, ItemError, ItemFormat, ItemId, ItemWrite, Owner, SpaceId, UserId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct ReplaceKeys<R, I, T, V, N, C> {
    pub spaces: R,
    pub items: I,
    pub tags: T,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub config: AuthConfig,
}

/// A replaced collection key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionRekey {
    pub collection: CollectionId,
    /// The new key's version: the collection's current version plus one.
    pub key_version: u32,
    /// The new key sealed to every confirmed member who may hold the collection.
    pub keys: Vec<SealedCollectionKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementInput {
    /// The space key's version after the replacement: the current version plus one when the space
    /// key is replaced, the current version when only collection keys are.
    pub space_key_version: u32,
    /// The space's name under the new space key. Required when the space key is replaced.
    pub space_name: Option<Vec<u8>>,
    /// The new space key sealed to every confirmed member.
    pub sealed_space_keys: Vec<(UserId, Vec<u8>)>,
    /// Every collection's name under the new space key (when the space key is replaced).
    pub collection_names: Vec<(CollectionId, Vec<u8>)>,
    /// Every group's name under the new space key (when the space key is replaced).
    pub group_names: Vec<(GroupId, Vec<u8>)>,
    /// The replaced collection keys: exactly the collections awaiting replacement.
    pub collections: Vec<CollectionRekey>,
    /// The re-wrapped items, each with its collection and written as the next revision.
    pub writes: Vec<(CollectionId, ItemWrite)>,
}

fn invalid(why: &'static str) -> SpacesError {
    SpacesError::Rule(SpaceError::Invalid(why))
}

impl<R: SpaceRepo, I: ItemStore, T: TagStore, V: EventLog, N: Notifier, C: Clock>
    ReplaceKeys<R, I, T, V, N, C>
{
    /// Lands a key replacement. Only an owner or admin may. Returns the re-written items.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        input: ReplacementInput,
    ) -> Result<Vec<Item>, SpacesError> {
        self.execute_with_held(actor, space, input, Vec::new())
            .await
    }

    /// Lands a key replacement that names live items as **held**: kept, but not served as live,
    /// and counted as covered by the completeness check, so a replacement doesn't have to
    /// re-wrap an item its writer can't open (for instance one a removed member wrote under a
    /// key they kept). Each held item must be a live item of a replaced collection and not be
    /// re-written.
    pub async fn execute_with_held(
        &self,
        actor: &Actor,
        space: SpaceId,
        input: ReplacementInput,
        held: Vec<ItemId>,
    ) -> Result<Vec<Item>, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let me = state.confirmed_actor(actor.user)?;
        if !matches!(me.role, SpaceRole::Owner | SpaceRole::Admin) {
            return Err(SpaceError::Forbidden("only an owner or admin replaces keys").into());
        }
        let plan = state
            .replacement_plan()
            .ok_or(SpaceError::State("no key is waiting to be replaced"))?;
        let now = self.clock.now();

        let mut changes = SpaceChanges::new(space);
        let mut space_row = state.space.clone();
        space_row.updated_at = now;

        // The space key, its sealed copies, and every name under it.
        let mut collection_names: BTreeMap<CollectionId, Vec<u8>> = BTreeMap::new();
        let mut group_names: BTreeMap<GroupId, Vec<u8>> = BTreeMap::new();
        if plan.space_key {
            let version = state
                .space
                .key_version
                .checked_add(1)
                .ok_or(invalid("the space key can't be replaced again"))?;
            if input.space_key_version != version {
                return Err(invalid("the new space key must be the next version"));
            }
            let name = input.space_name.ok_or(invalid(
                "the space's name must be encrypted under the new key",
            ))?;
            check_sealed_name(&name)?;

            let sealed: BTreeMap<UserId, &Vec<u8>> = unique(
                input.sealed_space_keys.iter().map(|(u, s)| (*u, s)),
                "the space key is sealed twice to one member",
            )?;
            let confirmed: BTreeSet<UserId> = state.confirmed_members().map(|m| m.user).collect();
            if sealed.keys().copied().collect::<BTreeSet<_>>() != confirmed {
                return Err(invalid(
                    "seal the new space key to exactly the confirmed members",
                ));
            }
            for key in sealed.values() {
                check_sealed_key(key)?;
            }
            for member in state.confirmed_members() {
                let mut updated = member.clone();
                updated.sealed_space_key = sealed.get(&member.user).map(|s| (*s).clone());
                updated.key_version = Some(version);
                changes.members.push(updated);
            }

            collection_names = unique(
                input.collection_names.iter().map(|(c, n)| (*c, n.clone())),
                "a collection is named twice",
            )?;
            group_names = unique(
                input.group_names.iter().map(|(g, n)| (*g, n.clone())),
                "a group is named twice",
            )?;
            if collection_names.keys().copied().collect::<BTreeSet<_>>()
                != state
                    .collections
                    .iter()
                    .map(|c| c.id)
                    .collect::<BTreeSet<_>>()
                || group_names.keys().copied().collect::<BTreeSet<_>>()
                    != state.groups.iter().map(|g| g.id).collect::<BTreeSet<_>>()
            {
                return Err(invalid(
                    "encrypt every collection's and group's name under the new space key",
                ));
            }
            for name in collection_names.values().chain(group_names.values()) {
                check_sealed_name(name)?;
            }
            space_row.key_version = version;
            space_row.name = name;
            space_row.keys_pending_since = None;
        } else if input.space_key_version != state.space.key_version
            || input.space_name.is_some()
            || !input.sealed_space_keys.is_empty()
            || !input.collection_names.is_empty()
            || !input.group_names.is_empty()
        {
            return Err(invalid(
                "only collection keys await replacement: leave the space key and names alone",
            ));
        }

        // The collection keys.
        let rekeys: BTreeMap<CollectionId, &CollectionRekey> = unique(
            input.collections.iter().map(|r| (r.collection, r)),
            "a collection key is replaced twice",
        )?;
        if rekeys.keys().copied().collect::<BTreeSet<_>>() != plan.collections {
            return Err(invalid(
                "replace the key of exactly the collections that await it",
            ));
        }
        let mut new_versions: BTreeMap<CollectionId, u32> = BTreeMap::new();
        for (id, rekey) in &rekeys {
            let collection = state
                .collection(*id)
                .ok_or(invalid("there is no such collection"))?;
            let version = collection
                .key_version
                .checked_add(1)
                .ok_or(invalid("the collection key can't be replaced again"))?;
            if rekey.key_version != version {
                return Err(invalid("the new collection key must be the next version"));
            }
            let sealed: BTreeMap<UserId, &Vec<u8>> = unique(
                rekey.keys.iter().map(|k| (k.user, &k.sealed)),
                "a collection key is sealed twice to one member",
            )?;
            if rekey.keys.iter().any(|k| k.collection != *id)
                || sealed.keys().copied().collect::<BTreeSet<_>>() != state.recipients(*id)
            {
                return Err(invalid(
                    "seal each new collection key to exactly the members who may hold it",
                ));
            }
            for (user, sealed) in sealed {
                check_sealed_key(sealed)?;
                changes.key_copies.push(KeyCopy {
                    collection: *id,
                    user,
                    key_version: version,
                    sealed: sealed.clone(),
                });
            }
            new_versions.insert(*id, version);
        }
        for collection in &state.collections {
            let renamed = collection_names.get(&collection.id);
            let version = new_versions.get(&collection.id);
            if renamed.is_none() && version.is_none() {
                continue;
            }
            let mut updated: Collection = collection.clone();
            if let Some(name) = renamed {
                updated.name = name.clone();
            }
            if let Some(version) = version {
                updated.key_version = *version;
                updated.stale_since = None;
            }
            changes.collections.push(updated);
        }
        for group in &state.groups {
            if let Some(name) = group_names.get(&group.id) {
                let mut updated: Group = group.clone();
                updated.name = name.clone();
                changes.groups.push(updated);
            }
        }
        changes.space = Some(space_row);

        // The re-wrapped items.
        let infos = self.spaces.space_items(space).await?;
        let by_id: BTreeMap<ItemId, &SpaceItemInfo> = infos.iter().map(|i| (i.id, i)).collect();
        let mut written: BTreeSet<ItemId> = BTreeSet::new();
        let mut drafts = Vec::with_capacity(input.writes.len());
        for (collection, write) in input.writes {
            let id = write.id;
            if crate::signed_writes::refuses_unsigned(&self.items, &write).await? {
                return Err(SpacesError::from_item(id, ItemError::SignatureRequired));
            }
            if write.owner != Owner::Space(space) {
                return Err(invalid("a replacement writes items of this space only"));
            }
            if !written.insert(id) {
                return Err(invalid("an item is rewritten twice"));
            }
            let info = by_id
                .get(&id)
                .ok_or(invalid("a replacement rewrites existing items only"))?;
            if info.collection != Some(collection) || info.deleted || write.sealed.is_none() {
                return Err(invalid(
                    "a replacement rewrites live items, each in the collection it is in",
                ));
            }
            if write.format == ItemFormat::Kem1 {
                match new_versions.get(&collection) {
                    Some(version) if *version == write.key_version => {}
                    _ => {
                        return Err(invalid(
                            "rewrite kem1 items of the replaced collections under their new key version",
                        ));
                    }
                }
            }
            let stored = self.items.get(id).await?.ok_or(SpacesError::NotFound)?;
            let draft = apply_space_write(
                write,
                Some(&stored),
                actor.user,
                self.config.item_limits,
                now,
            )
            .map_err(|e| SpacesError::from_item(id, e))?;
            drafts.push((draft, collection));
        }
        let held: BTreeSet<ItemId> = held.into_iter().collect();
        for id in &held {
            let live_in_replaced = by_id.get(id).is_some_and(|info| {
                !info.deleted
                    && info
                        .collection
                        .is_some_and(|c| plan.collections.contains(&c))
            });
            if !live_in_replaced || written.contains(id) {
                return Err(invalid(
                    "hold only live items of a replaced collection that the replacement doesn't rewrite",
                ));
            }
        }
        for info in &infos {
            let replaced = info
                .collection
                .is_some_and(|c| plan.collections.contains(&c));
            if replaced
                && !info.deleted
                && info.format == ItemFormat::Kem1
                && !written.contains(&info.id)
                && !held.contains(&info.id)
            {
                return Err(invalid(
                    "every live kem1 item of a replaced collection must be re-wrapped",
                ));
            }
        }

        // Before the replacement lands: if the transaction then fails, the cost is a needless
        // re-tag, where a bump that failed after it landed would leave tags made under the old
        // key mixed with new ones under one version.
        if plan.space_key {
            self.tags.bump_version(Owner::Space(space), now).await?;
        }
        let stored = self
            .spaces
            .replace_keys(KeyReplacement {
                changes,
                writes: drafts,
            })
            .await?;
        if !held.is_empty() {
            let held: Vec<ItemId> = held.into_iter().collect();
            self.spaces.hold_items(space, &held).await?;
        }
        record(
            &self.events,
            actor,
            "space.keys.replace",
            format!("{space}: {} items", stored.len()),
            now,
        )
        .await;
        if let Some(newest) = stored.iter().map(|i| i.change).max_by_key(|c| c.seq) {
            self.push.sync_now(Owner::Space(space), newest).await;
        }
        Ok(stored)
    }
}

/// Collects pairs into a map, refusing a key that appears twice.
fn unique<K: Ord, T>(
    pairs: impl Iterator<Item = (K, T)>,
    why: &'static str,
) -> Result<BTreeMap<K, T>, SpacesError> {
    let mut map = BTreeMap::new();
    for (key, value) in pairs {
        if map.insert(key, value).is_some() {
            return Err(invalid(why));
        }
    }
    Ok(map)
}
