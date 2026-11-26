//! Put item: one create, replace or delete of an item. The domain's `ItemWrite::apply` decides
//! (access, `If-Match`, revision, size); the store makes it atomic; an event is recorded and the
//! owner's devices are told to sync, never what changed.

use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::ports::{Clock, Event, EventLog, ItemStore, Notifier};
use kemlock_domain::{Item, ItemError, ItemWrite};

#[derive(Debug)]
pub struct PutItem<I, V, N, C> {
    pub items: I,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub config: AuthConfig,
}

impl<I: ItemStore, V: EventLog, N: Notifier, C: Clock> PutItem<I, V, N, C> {
    /// Stores the write and returns the item as stored, with its change id. A write over a
    /// revision other than `write.expected` is `Conflict`, naming the current revision.
    pub async fn execute(&self, actor: &Actor, write: ItemWrite) -> Result<Item, AppError> {
        let id = write.id;
        let now = self.clock.now();
        if crate::signed_writes::refuses_unsigned(&self.items, &write).await? {
            return Err(AppError::from_item(id, ItemError::SignatureRequired));
        }
        let stored = self.items.get(id).await?;
        let draft = write
            .apply(stored.as_ref(), actor.user, self.config.item_limits, now)
            .map_err(|e| AppError::from_item(id, e))?;
        let deleted = draft.deleted_at.is_some();
        let item = self.items.put(draft).await?;

        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: if deleted { "item.delete" } else { "item.put" },
            target: Some(item.id.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record an item event");
        }
        self.push.sync_now(item.owner, item.change).await;
        Ok(item)
    }
}
