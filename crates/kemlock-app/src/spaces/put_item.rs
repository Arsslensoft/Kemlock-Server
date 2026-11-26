//! Put a space item: one create, replace or delete of an item that lives in a space.
//!
//! This is `put_item` for owners of type space. The vault path stops at `ItemWrite::apply`'s rule
//! that an actor writes only their own vault; here the authorization step is [`SpaceAccess`]: a
//! confirmed member with edit on the item's collection, in a space and collection that aren't
//! waiting for a key replacement, writing under the collection's current key version. After it,
//! the same revision rules apply (`apply_space_write`), and the store keeps the item and its
//! collection together.
//!
//! An item's collection is metadata of the server item, sent beside `owner`. Moving an item to
//! another collection is a write that names the new one: the actor needs edit on both, and the item
//! is sealed under the new collection's key.

use super::access::SpaceAccess;
use super::error::SpacesError;
use super::ports::SpaceRepo;
use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::ports::{Clock, Event, EventLog, ItemStore, Notifier};
use kemlock_domain::spaces::{CollectionId, SpaceError, apply_space_write};
use kemlock_domain::{Item, ItemError, ItemWrite, Owner};

#[derive(Debug)]
pub struct PutSpaceItem<R, I, V, N, C> {
    pub spaces: R,
    pub items: I,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub config: AuthConfig,
}

impl<R: SpaceRepo, I: ItemStore, V: EventLog, N: Notifier, C: Clock> PutSpaceItem<R, I, V, N, C> {
    /// Stores the write into `collection` and returns the item as stored, with its change id. A
    /// write over a revision other than `write.expected` is `StaleItem`, naming the current one.
    /// `write.owner` must be the space.
    pub async fn execute(
        &self,
        actor: &Actor,
        collection: CollectionId,
        write: ItemWrite,
    ) -> Result<Item, SpacesError> {
        let id = write.id;
        let Owner::Space(space) = write.owner else {
            return Err(SpacesError::from_item(id, ItemError::Forbidden));
        };
        let now = self.clock.now();
        if crate::signed_writes::refuses_unsigned(&self.items, &write).await? {
            return Err(SpacesError::from_item(id, ItemError::SignatureRequired));
        }
        // A delete seals nothing, so it has no key version to hold against the collection's.
        let key_version = write.sealed.as_ref().map(|_| write.key_version);
        let state = SpaceAccess::load_and_authorize(
            &self.spaces,
            actor.user,
            space,
            collection,
            key_version,
        )
        .await?;

        let stored = self.items.get(id).await?;
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
                SpaceAccess::authorize_write(&state, actor.user, previous, None)?;
            }
        }
        let draft = apply_space_write(
            write,
            stored.as_ref(),
            actor.user,
            self.config.item_limits,
            now,
        )
        .map_err(|e| SpacesError::from_item(id, e))?;
        let deleted = draft.deleted_at.is_some();
        let item = self.spaces.put_item(draft, collection).await?;

        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: if deleted { "item.delete" } else { "item.put" },
            target: Some(item.id.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a space item event");
        }
        self.push.sync_now(item.owner, item.change).await;
        Ok(item)
    }
}
