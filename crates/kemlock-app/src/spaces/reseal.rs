//! Re-seal keys: move a space with no chain off the boxes made before keys were signed.
//!
//! An owner or admin makes fresh boxes of the keys they hold, signs each (docs/crypto.md, "Signed key
//! boxes"), and sends them for the confirmed members who are to have them: the current space key
//! for each, and the current key of any collection the member already holds a copy of. The server
//! checks each signature as it does on a confirmation and replaces the copies and their signatures
//! in one transaction. Nobody gains or loses a key, and no key version, role or grant changes: it is
//! the same keys, sealed again, so a client that accepted the old box opens the new one and finds
//! it signed.

use super::error::SpacesError;
use super::key_boxes::{KeyBoxFacts, KeyBoxKey, KeyBoxVerifier, check_box};
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{SealedCollectionKey, load_open, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog};
use kemlock_domain::spaces::{
    CollectionId, KeyCopy, MemberState, SpaceError, SpaceRole, check_sealed_key,
};
use kemlock_domain::{SpaceId, UserId};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct ResealKeys<R, V, C, K> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
    pub boxes: K,
}

/// The keys sealed again to one confirmed member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResealMember {
    pub user: UserId,
    /// The current space key, sealed to the member.
    pub sealed_space_key: Vec<u8>,
    /// The sealer's signature over that box.
    pub space_key_signature: Vec<u8>,
    /// The current key of each collection the member already holds a copy of, sealed to them, with
    /// `user` the member.
    pub collection_keys: Vec<SealedCollectionKey>,
}

fn invalid(why: &'static str) -> SpacesError {
    SpacesError::Rule(SpaceError::Invalid(why))
}

impl<R: SpaceRepo, V: EventLog, C: Clock, K: KeyBoxVerifier> ResealKeys<R, V, C, K> {
    /// Replaces the boxes of the listed members. Only an owner or admin may, for a space with no
    /// chain whose keys aren't waiting for a replacement. Returns how many members got new boxes.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        members: Vec<ResealMember>,
    ) -> Result<usize, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let me = state.confirmed_actor(actor.user)?;
        if !matches!(me.role, SpaceRole::Owner | SpaceRole::Admin) {
            return Err(SpaceError::Forbidden("only an owner or admin re-seals keys").into());
        }
        state.ensure_keys_open()?;
        if members.is_empty() {
            return Err(invalid("name the members whose keys are sealed again"));
        }
        let holders: BTreeSet<(CollectionId, UserId)> =
            self.spaces.holders(space).await?.into_iter().collect();

        let mut changes = SpaceChanges::new(space);
        let mut seen: BTreeSet<UserId> = BTreeSet::new();
        for member in members {
            if !seen.insert(member.user) {
                return Err(invalid("a member is listed twice"));
            }
            let row = state
                .member(member.user)
                .filter(|m| m.state == MemberState::Confirmed)
                .ok_or(invalid("only confirmed members are sealed keys again"))?;
            check_sealed_key(&member.sealed_space_key)?;
            let space_key_by = check_box(
                &self.boxes,
                KeyBoxFacts {
                    space,
                    key: KeyBoxKey::Space,
                    key_version: state.space.key_version,
                    recipient: member.user,
                    sealed_box: &member.sealed_space_key,
                    sealer: actor.user,
                },
                &member.space_key_signature,
            )
            .await?;
            let mut updated = row.clone();
            updated.sealed_space_key = Some(member.sealed_space_key);
            updated.sealed_by = Some(space_key_by);
            updated.key_version = Some(state.space.key_version);
            changes.members.push(updated);

            let mut collections: BTreeSet<CollectionId> = BTreeSet::new();
            for key in member.collection_keys {
                if key.user != member.user || !collections.insert(key.collection) {
                    return Err(invalid("each collection key is sealed once, to its member"));
                }
                if !holders.contains(&(key.collection, member.user)) {
                    return Err(invalid("a member is sealed again only the keys they hold"));
                }
                let collection = state
                    .collection(key.collection)
                    .ok_or(invalid("there is no such collection"))?;
                if collection.stale_since.is_some() {
                    return Err(SpaceError::KeysPending.into());
                }
                check_sealed_key(&key.sealed)?;
                let by = check_box(
                    &self.boxes,
                    KeyBoxFacts {
                        space,
                        key: KeyBoxKey::Collection(key.collection),
                        key_version: collection.key_version,
                        recipient: member.user,
                        sealed_box: &key.sealed,
                        sealer: actor.user,
                    },
                    &key.signature,
                )
                .await?;
                changes.key_copies.push(KeyCopy {
                    collection: key.collection,
                    user: member.user,
                    key_version: collection.key_version,
                    sealed: key.sealed,
                    sealed_by: Some(by),
                });
            }
        }

        let count = changes.members.len();
        let now = self.clock.now();
        self.spaces.apply(changes).await?;
        record(
            &self.events,
            actor,
            "space.keys.reseal",
            format!("{space}: {count} members"),
            now,
        )
        .await;
        Ok(count)
    }
}
