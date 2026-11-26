//! Put a batch of items that may include items of spaces: up to 500 puts and deletes, stored all
//! together or not at all.
//!
//! A write to the actor's own vault goes through `ItemWrite::apply`, as in `PutBatch`. A write
//! to a space goes through [`SpaceAccess`] and `apply_space_write`, as in `PutSpaceItem`, and
//! names its collection. Every write is checked before anything is stored, then
//! `SpaceRepo::put_items` stores them in one transaction, so a refused write leaves the others
//! unwritten.

use super::access::SpaceAccess;
use super::error::SpacesError;
use super::ports::SpaceRepo;
use super::support::load_state;
use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::ports::{Clock, Event, EventLog, ItemStore, Notifier};
use crate::put_batch::MAX_BATCH;
use kemlock_domain::spaces::{CollectionId, SpaceError, SpaceState, apply_space_write};
use kemlock_domain::{ChangeId, Item, ItemError, ItemId, ItemWrite, Owner, SpaceId};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug)]
pub struct PutSpaceBatch<R, I, V, N, C> {
    pub spaces: R,
    pub items: I,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub config: AuthConfig,
}

/// A refused item write as this module's error: the id of a stranger's item reads as taken, as
/// `AppError::from_item` has it.
fn item_error(id: ItemId, e: ItemError) -> SpacesError {
    match e {
        ItemError::Taken => SpacesError::Duplicate,
        other => SpacesError::from_item(id, other),
    }
}

impl<R: SpaceRepo, I: ItemStore, V: EventLog, N: Notifier, C: Clock> PutSpaceBatch<R, I, V, N, C> {
    /// Stores every write or none, returning the items as stored. Each write comes with the
    /// collection it belongs in: required for an item of a space, absent for one of the actor's
    /// own vault. A refused write names its item (`StaleItem`), and nothing is stored. An item
    /// may appear once in a batch.
    pub async fn execute(
        &self,
        actor: &Actor,
        writes: Vec<(ItemWrite, Option<CollectionId>)>,
    ) -> Result<Vec<Item>, SpacesError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        if writes.len() > MAX_BATCH {
            return Err(SpaceError::Invalid("a batch holds at most 500 writes").into());
        }
        let mut seen: HashSet<ItemId> = HashSet::with_capacity(writes.len());
        if !writes.iter().all(|(w, _)| seen.insert(w.id)) {
            return Err(SpaceError::Invalid("an item appears twice in the batch").into());
        }

        let now = self.clock.now();
        let mut states: BTreeMap<SpaceId, SpaceState> = BTreeMap::new();
        let mut drafts = Vec::with_capacity(writes.len());
        for (write, collection) in writes {
            let id = write.id;
            let stored = self.items.get(id).await?;
            let draft = match write.owner {
                Owner::User(_) => {
                    if collection.is_some() {
                        return Err(
                            SpaceError::Invalid("an item of a vault has no collection").into()
                        );
                    }
                    write
                        .apply(stored.as_ref(), actor.user, self.config.item_limits, now)
                        .map_err(|e| item_error(id, e))?
                }
                Owner::Space(space) => {
                    let collection = collection
                        .ok_or(SpaceError::Invalid("an item of a space needs a collection"))?;
                    if let std::collections::btree_map::Entry::Vacant(slot) = states.entry(space) {
                        slot.insert(load_state(&self.spaces, space).await?);
                    }
                    let state = &states[&space];
                    let key_version = write.sealed.as_ref().map(|_| write.key_version);
                    SpaceAccess::authorize_write(state, actor.user, collection, key_version)?;
                    if stored.is_some() {
                        let previous = self
                            .spaces
                            .item_collections(&[id])
                            .await?
                            .into_iter()
                            .next()
                            .map(|(_, c)| c)
                            .ok_or(SpaceError::Invalid("the item has no collection"))?;
                        if previous != collection {
                            // Moving out of a collection takes edit there too.
                            SpaceAccess::authorize_write(state, actor.user, previous, None)?;
                        }
                    }
                    apply_space_write(
                        write,
                        stored.as_ref(),
                        actor.user,
                        self.config.item_limits,
                        now,
                    )
                    .map_err(|e| item_error(id, e))?
                }
            };
            if crate::signed_writes::refuses_unsigned(&self.items, &draft).await? {
                return Err(item_error(id, ItemError::SignatureRequired));
            }
            let collection = matches!(draft.owner, Owner::Space(_))
                .then_some(collection)
                .flatten();
            drafts.push((draft, collection));
        }
        let stored = self.spaces.put_items(drafts).await?;

        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "item.batch",
            target: Some(format!("{} items", stored.len())),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a batch event");
        }

        // One nudge per owner, with that owner's newest change.
        let mut newest: BTreeMap<Owner, ChangeId> = BTreeMap::new();
        for item in &stored {
            let newer = newest
                .get(&item.owner)
                .is_none_or(|known| item.change.seq > known.seq);
            if newer {
                newest.insert(item.owner, item.change);
            }
        }
        for (owner, change) in newest {
            self.push.sync_now(owner, change).await;
        }
        Ok(stored)
    }
}
