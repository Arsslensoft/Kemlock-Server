//! Put batch: up to 500 puts and deletes, all stored or none.

use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::ports::{Clock, Event, EventLog, ItemStore, Notifier};
use kemlock_domain::{ChangeId, Item, ItemError, ItemId, ItemWrite, Owner};
use std::collections::{BTreeMap, HashSet};

/// The most writes one batch may carry.
pub const MAX_BATCH: usize = 500;

#[derive(Debug)]
pub struct PutBatch<I, V, N, C> {
    pub items: I,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub config: AuthConfig,
}

impl<I: ItemStore, V: EventLog, N: Notifier, C: Clock> PutBatch<I, V, N, C> {
    /// Stores every write or none. A refused write names its item (`Conflict`), and nothing is
    /// stored. An item may appear once in a batch.
    pub async fn execute(
        &self,
        actor: &Actor,
        writes: Vec<ItemWrite>,
    ) -> Result<Vec<Item>, AppError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        if writes.len() > MAX_BATCH {
            return Err(AppError::Invalid("a batch holds at most 500 writes"));
        }
        let mut seen: HashSet<ItemId> = HashSet::with_capacity(writes.len());
        if !writes.iter().all(|w| seen.insert(w.id)) {
            return Err(AppError::Invalid("an item appears twice in the batch"));
        }

        let now = self.clock.now();
        let mut drafts = Vec::with_capacity(writes.len());
        for write in writes {
            let id = write.id;
            let stored = self.items.get(id).await?;
            let draft = write
                .apply(stored.as_ref(), actor.user, self.config.item_limits, now)
                .map_err(|e| AppError::from_item(id, e))?;
            if crate::signed_writes::refuses_unsigned(&self.items, &draft).await? {
                return Err(AppError::from_item(id, ItemError::SignatureRequired));
            }
            drafts.push(draft);
        }
        let stored = self.items.put_batch(drafts).await?;

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
