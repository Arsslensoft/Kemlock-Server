//! Create space: the maker becomes its confirmed owner and gets the sealed space key, the first
//! collection and its key. A space starts with one collection ("Everyone" in the apps) so a space
//! nobody configures works like a shared file.

use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::record;
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog};
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, FIRST_KEY_VERSION, Grantee,
    KeyCopy, Member, MemberState, Space, SpaceRole, SpaceState, check_sealed_key,
    check_sealed_name,
};

#[derive(Debug)]
pub struct CreateSpace<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

/// The space's first collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCollection {
    /// Chosen by the client, so a failed request can be resent unchanged.
    pub id: CollectionId,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    /// The collection key, sealed to the maker.
    pub sealed_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSpaceInput {
    /// Chosen by the client; a moved WebDAV space takes the UUID docs/crypto.md's "Legacy ids"
    /// gives its old id.
    pub id: SpaceId,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    /// The space key, sealed to the maker.
    pub sealed_space_key: Vec<u8>,
    pub collection: NewCollection,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> CreateSpace<R, V, C> {
    /// Makes the space. `Duplicate` when the id is taken.
    pub async fn execute(
        &self,
        actor: &Actor,
        input: CreateSpaceInput,
    ) -> Result<SpaceState, SpacesError> {
        check_sealed_name(&input.name)?;
        check_sealed_name(&input.collection.name)?;
        check_sealed_key(&input.sealed_space_key)?;
        check_sealed_key(&input.collection.sealed_key)?;
        let now = self.clock.now();

        let space = Space {
            id: input.id,
            name: input.name,
            key_version: FIRST_KEY_VERSION,
            keys_pending_since: None,
            created_at: now,
            updated_at: now,
        };
        let owner = Member {
            space: space.id,
            user: actor.user,
            role: SpaceRole::Owner,
            custom: Default::default(),
            state: MemberState::Confirmed,
            invited_by: actor.user,
            invited_at: now,
            accepted_at: Some(now),
            sealed_space_key: Some(input.sealed_space_key),
            key_version: Some(FIRST_KEY_VERSION),
            confirmation: None,
            revoked_at: None,
        };
        let collection = Collection {
            id: input.collection.id,
            space: space.id,
            parent: None,
            name: input.collection.name,
            key_version: FIRST_KEY_VERSION,
            stale_since: None,
            created_at: now,
        };
        // The maker holds the collection explicitly: owners have no implicit access to items.
        let grant = CollectionGrant {
            collection: collection.id,
            grantee: Grantee::Member(actor.user),
            permission: CollectionPermission::Manage,
        };
        let copy = KeyCopy {
            collection: collection.id,
            user: actor.user,
            key_version: FIRST_KEY_VERSION,
            sealed: input.collection.sealed_key,
        };

        let state = SpaceState {
            space: space.clone(),
            members: vec![owner.clone()],
            groups: Vec::new(),
            collections: vec![collection.clone()],
            grants: vec![grant],
        };
        self.spaces
            .create(SpaceChanges {
                space: Some(space),
                members: vec![owner],
                collections: vec![collection],
                grants: vec![grant],
                key_copies: vec![copy],
                ..SpaceChanges::new(state.space.id)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.create",
            state.space.id.to_string(),
            now,
        )
        .await;
        Ok(state)
    }
}
