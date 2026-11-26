//! What the spaces use cases share: loading a space, recording an event, and working out the key
//! copies a change needs and the keys it exposes.

use super::error::SpacesError;
use super::ports::SpaceRepo;
use crate::authenticate::Actor;
use crate::ports::{Event, EventLog};
use kemlock_domain::spaces::{
    Collection, CollectionId, KeyCopy, KeyDelta, SpaceError, SpaceState, check_sealed_key,
};
use kemlock_domain::{SpaceId, UserId};
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// A collection key sealed to one member, as a client sends it. `collection` and `user` say whose
/// copy it is; the server can't open it and checks only its shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedCollectionKey {
    pub collection: CollectionId,
    pub user: UserId,
    pub sealed: Vec<u8>,
}

/// The key copies to store and remove, and the collections newly marked for key replacement, that
/// a change brings with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyChanges {
    pub key_copies: Vec<KeyCopy>,
    pub key_copies_removed: Vec<(CollectionId, UserId)>,
    /// Collections to store again, marked stale.
    pub collections: Vec<Collection>,
}

/// Loads a space a use case is about to change. A space with a chain changes only by records of
/// its chain, so this refuses it (`409`, with the route to use).
pub(crate) async fn load_open<R: SpaceRepo>(
    spaces: &R,
    id: SpaceId,
) -> Result<SpaceState, SpacesError> {
    super::chain::ensure_unchained(spaces, id).await?;
    load_state(spaces, id).await
}

pub(crate) async fn load_state<R: SpaceRepo>(
    spaces: &R,
    id: SpaceId,
) -> Result<SpaceState, SpacesError> {
    spaces.load(id).await?.ok_or(SpacesError::NotFound)
}

/// Records an event; a failure to record is logged, never returned, as in the item use cases.
pub(crate) async fn record<V: EventLog>(
    events: &V,
    actor: &Actor,
    action: &'static str,
    target: String,
    at: OffsetDateTime,
) {
    let event = Event {
        actor: Some(actor.user),
        device: Some(actor.device),
        action,
        target: Some(target),
        at,
    };
    if let Err(e) = events.record(event).await {
        tracing::warn!(action, error = %e, "couldn't record a space event");
    }
}

/// Checks that `provided` seals exactly the copies `delta.needed` asks for (each well formed, none
/// twice), that no collection needing a copy awaits a key replacement, and turns them into the
/// copies to store. Copies held by someone who lost access are removed, and their collections
/// marked stale at `now`.
pub(crate) fn key_changes(
    after: &SpaceState,
    delta: &KeyDelta,
    provided: Vec<SealedCollectionKey>,
    now: OffsetDateTime,
) -> Result<KeyChanges, SpacesError> {
    let mut seen: BTreeSet<(CollectionId, UserId)> = BTreeSet::new();
    for key in &provided {
        check_sealed_key(&key.sealed)?;
        if !seen.insert((key.collection, key.user)) {
            return Err(
                SpaceError::Invalid("a collection key is sealed twice to one member").into(),
            );
        }
    }
    if seen != delta.needed {
        return Err(SpaceError::Invalid(
            "seal each collection key to exactly the members who gain access to it",
        )
        .into());
    }

    let mut key_copies = Vec::with_capacity(provided.len());
    for key in provided {
        let collection = after
            .collection(key.collection)
            .ok_or(SpaceError::Invalid("there is no such collection"))?;
        if collection.stale_since.is_some() {
            return Err(SpaceError::KeysPending.into());
        }
        key_copies.push(KeyCopy {
            collection: key.collection,
            user: key.user,
            key_version: collection.key_version,
            sealed: key.sealed,
            sealed_by: None,
        });
    }

    let mut collections = Vec::new();
    for id in delta.stale_collections() {
        if let Some(collection) = after.collection(id)
            && collection.stale_since.is_none()
        {
            let mut stale = collection.clone();
            stale.stale_since = Some(now);
            collections.push(stale);
        }
    }
    Ok(KeyChanges {
        key_copies,
        key_copies_removed: delta.lost.iter().copied().collect(),
        collections,
    })
}
