//! Grant and revoke access to a collection.
//!
//! A grant is the one thing that gives a member or group a collection's key, so granting takes
//! the sealed copies for every confirmed member it newly reaches. Revoking takes the copies away
//! and marks the collection for key replacement: the server can delete a copy, but not what the
//! member already read.

use super::authority;
use super::collections::check_grantee;
use super::error::SpacesError;
use super::key_boxes::KeyBoxVerifier;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{SealedCollectionKey, key_changes, key_removals, load_open, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog};
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, Grantee, SpaceError,
};

#[derive(Debug)]
pub struct GrantAccess<R, V, C, K> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
    pub boxes: K,
}

impl<R: SpaceRepo, V: EventLog, C: Clock, K: KeyBoxVerifier> GrantAccess<R, V, C, K> {
    /// Grants `grantee` a permission on a collection, or changes the one they have. `keys` seals
    /// the collection key to each confirmed member who gains access (the grantee, or the members of
    /// the group); a change of permission for someone who already holds the key takes none.
    /// Owners, admins and holders of Manage on the collection can grant it.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        collection: CollectionId,
        grantee: Grantee,
        permission: CollectionPermission,
        keys: Vec<SealedCollectionKey>,
    ) -> Result<CollectionGrant, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let target = state.authorize_manage_collection(actor.user, collection)?;
        state.ensure_collection_open(target)?;
        check_grantee(&state, grantee)?;

        let grant = CollectionGrant {
            collection,
            grantee,
            permission,
        };
        let mut after = state.clone();
        after
            .grants
            .retain(|g| !(g.collection == collection && g.grantee == grantee));
        after.grants.push(grant);
        authority::check(&state, &after, actor.user, None)?;

        let holders = self.spaces.holders(space).await?;
        let delta = after.key_delta(&holders);
        let now = self.clock.now();
        let sealed = key_changes(&after, &delta, keys, now, &self.boxes, actor.user).await?;
        self.spaces
            .apply(SpaceChanges {
                grants: vec![grant],
                key_copies: sealed.key_copies,
                key_copies_removed: sealed.key_copies_removed,
                collections: sealed.collections,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.grant",
            format!("{space}/{collection}/{grantee}"),
            now,
        )
        .await;
        Ok(grant)
    }
}

#[derive(Debug)]
pub struct RevokeGrant<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> RevokeGrant<R, V, C> {
    /// Takes a grant away. A confirmed member who held the collection's key and has no other way
    /// to it loses their copy, and the collection's key is marked for replacement. Allowed while
    /// the space waits for a key replacement.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        collection: CollectionId,
        grantee: Grantee,
    ) -> Result<(), SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        state.authorize_manage_collection(actor.user, collection)?;
        if !state
            .grants
            .iter()
            .any(|g| g.collection == collection && g.grantee == grantee)
        {
            return Err(SpacesError::NotFound);
        }
        let mut after = state.clone();
        after
            .grants
            .retain(|g| !(g.collection == collection && g.grantee == grantee));
        authority::check(&state, &after, actor.user, None)?;

        let holders = self.spaces.holders(space).await?;
        let delta = after.key_delta(&holders);
        if !delta.needed.is_empty() {
            // Removing a grant never adds a recipient; a gap here means the stored keys and
            // grants disagree, which this change must not paper over.
            return Err(SpaceError::Invalid("the space's keys and grants disagree").into());
        }
        let now = self.clock.now();
        let sealed = key_removals(&after, &delta, now)?;
        self.spaces
            .apply(SpaceChanges {
                grants_removed: vec![(collection, grantee)],
                key_copies_removed: sealed.key_copies_removed,
                collections: sealed.collections,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.grant.revoke",
            format!("{space}/{collection}/{grantee}"),
            now,
        )
        .await;
        Ok(())
    }
}
