//! Collections: create, rename or move, and delete.
//!
//! A collection has its own key, sealed only to the members granted it. Creating one therefore
//! carries its first grants and the sealed copies that go with them, and the server checks that
//! every confirmed grantee got a copy and nobody else did.

use super::error::SpacesError;
use super::key_boxes::KeyBoxVerifier;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{SealedCollectionKey, key_changes, load_open, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog};

use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, FIRST_KEY_VERSION, Grantee,
    KeyDelta, MemberState, SpaceError, SpaceState, check_sealed_name,
};
use kemlock_domain::{SpaceId, UserId};
use std::collections::BTreeSet;

/// Whether `user` is a member who has not been revoked: someone a grant or a group may name.
pub(crate) fn check_grantee_member(state: &SpaceState, user: UserId) -> Result<(), SpaceError> {
    match state.member(user) {
        Some(m) if m.state != MemberState::Revoked => Ok(()),
        _ => Err(SpaceError::Invalid(
            "only members who have not been revoked can be granted a collection or put in a group",
        )),
    }
}

/// Whether `grantee` is someone a grant may name: a member who isn't revoked, or a group.
pub(crate) fn check_grantee(state: &SpaceState, grantee: Grantee) -> Result<(), SpaceError> {
    match grantee {
        Grantee::Member(user) => check_grantee_member(state, user),
        Grantee::Group(group) => state
            .group(group)
            .map(|_| ())
            .ok_or(SpaceError::Invalid("there is no such group")),
    }
}

#[derive(Debug)]
pub struct CreateCollection<R, V, C, K> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
    pub boxes: K,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateCollectionInput {
    /// Chosen by the client, so a failed request can be resent unchanged.
    pub id: CollectionId,
    pub parent: Option<CollectionId>,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    /// Who is granted the collection. The creator is granted Manage when not listed.
    pub grants: Vec<(Grantee, CollectionPermission)>,
    /// The collection key sealed to each confirmed grantee, the creator included.
    pub keys: Vec<SealedCollectionKey>,
}

impl<R: SpaceRepo, V: EventLog, C: Clock, K: KeyBoxVerifier> CreateCollection<R, V, C, K> {
    /// Makes a collection at key version 1. Owners, admins and Custom members who may create
    /// collections can; the space must not be waiting for a key replacement.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        input: CreateCollectionInput,
    ) -> Result<Collection, SpacesError> {
        check_sealed_name(&input.name)?;
        let state = load_open(&self.spaces, space).await?;
        state.authorize_create_collection(actor.user)?;
        state.ensure_keys_open()?;
        // Collection ids are unique across spaces: another space's id is taken too.
        if state.collection(input.id).is_some()
            || self.spaces.collection_space(input.id).await?.is_some()
        {
            return Err(SpacesError::Duplicate);
        }
        state.check_parent(input.id, input.parent)?;

        let now = self.clock.now();
        let collection = Collection {
            id: input.id,
            space,
            parent: input.parent,
            name: input.name,
            key_version: FIRST_KEY_VERSION,
            stale_since: None,
            created_at: now,
        };

        let mut grants: Vec<CollectionGrant> = Vec::new();
        let mut seen = BTreeSet::new();
        let creator = Grantee::Member(actor.user);
        let listed = input.grants.iter().any(|(g, _)| *g == creator);
        let implicit = (!listed).then_some((creator, CollectionPermission::Manage));
        for (grantee, permission) in input.grants.into_iter().chain(implicit) {
            check_grantee(&state, grantee)?;
            if !seen.insert(grantee) {
                return Err(SpaceError::Invalid("a grantee is listed twice").into());
            }
            grants.push(CollectionGrant {
                collection: collection.id,
                grantee,
                permission,
            });
        }

        let mut after = state.clone();
        after.collections.push(collection.clone());
        after.grants.extend(grants.iter().copied());
        let needed = after
            .recipients(collection.id)
            .into_iter()
            .map(|user| (collection.id, user))
            .collect();
        let delta = KeyDelta {
            needed,
            ..KeyDelta::default()
        };
        let keys = key_changes(&after, &delta, input.keys, now, &self.boxes, actor.user).await?;

        self.spaces
            .apply(SpaceChanges {
                collections: vec![collection.clone()],
                grants,
                key_copies: keys.key_copies,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.collection.create",
            format!("{space}/{}", collection.id),
            now,
        )
        .await;
        Ok(collection)
    }
}

#[derive(Debug)]
pub struct EditCollection<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditCollectionInput {
    /// A new name, encrypted under the current space key.
    pub name: Option<Vec<u8>>,
    /// `Some(None)` moves the collection to the top level; `Some(Some(parent))` under `parent`.
    pub parent: Option<Option<CollectionId>>,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> EditCollection<R, V, C> {
    /// Renames or moves a collection. Owners, admins and holders of Manage on it can.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        collection: CollectionId,
        input: EditCollectionInput,
    ) -> Result<Collection, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let mut edited = state
            .authorize_manage_collection(actor.user, collection)?
            .clone();
        // A name is sealed under the current space key, which must be the one that stays.
        state.ensure_keys_open()?;
        if let Some(name) = input.name {
            check_sealed_name(&name)?;
            edited.name = name;
        }
        if let Some(parent) = input.parent {
            state.check_parent(collection, parent)?;
            edited.parent = parent;
        }
        self.spaces
            .apply(SpaceChanges {
                collections: vec![edited.clone()],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.collection.edit",
            format!("{space}/{collection}"),
            self.clock.now(),
        )
        .await;
        Ok(edited)
    }
}

#[derive(Debug)]
pub struct DeleteCollection<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> DeleteCollection<R, V, C> {
    /// Deletes an empty collection with no nested collections, with its grants and keys. The
    /// client moves or deletes its items first.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        collection: CollectionId,
    ) -> Result<(), SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        state.authorize_manage_collection(actor.user, collection)?;
        if state
            .collections
            .iter()
            .any(|c| c.parent == Some(collection))
        {
            return Err(SpaceError::Invalid("the collection has nested collections").into());
        }
        let items = self.spaces.space_items(space).await?;
        if items
            .iter()
            .any(|i| i.collection == Some(collection) && !i.deleted)
        {
            return Err(SpaceError::Invalid("the collection still holds items").into());
        }
        self.spaces
            .apply(SpaceChanges {
                collections_removed: vec![collection],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.collection.delete",
            format!("{space}/{collection}"),
            self.clock.now(),
        )
        .await;
        Ok(())
    }
}
