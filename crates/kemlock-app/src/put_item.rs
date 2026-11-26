//! Put item: one create, replace or delete of an item. The domain's `ItemWrite::apply` decides
//! (access, `If-Match`, revision, size); the store makes it atomic; an event is recorded and the
//! owner's devices are told to sync, never what changed.

use crate::authenticate::Actor;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::ports::{Clock, Event, EventLog, ItemStore, Notifier, UserRepo};
use kemlock_domain::{Item, ItemError, ItemFormat, ItemWrite, Owner, UserId};

/// A sealed write to the account's own vault must name the account's current key version.
///
/// The item key is wrapped under the account's `item-wrap` key at that version, so a write that
/// names another one was sealed under keys the account no longer has: a device that did not learn
/// of a rotation of the root key (docs/crypto.md, "Rotating the root key"), or a replica still
/// serving an older state. Storing it would leave an item nobody can open. A deletion carries no
/// sealed value and is not checked; neither are items of another format or owner.
pub(crate) async fn check_key_version<U: UserRepo>(
    users: &U,
    actor: UserId,
    write: &ItemWrite,
) -> Result<(), AppError> {
    if write.sealed.is_none()
        || write.format != ItemFormat::Kem1
        || write.owner != Owner::User(actor)
    {
        return Ok(());
    }
    let account = users.by_id(actor).await?.ok_or(AppError::Unauthorized)?;
    // An account with no keys yet (key version 0) has nothing to be stale against.
    if account.key_version != 0 && write.key_version != account.key_version {
        return Err(AppError::Invalid(
            "the item is sealed under another key version than the account's current one",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct PutItem<I, V, N, C, U> {
    pub items: I,
    pub events: V,
    pub push: N,
    pub clock: C,
    pub users: U,
    pub config: AuthConfig,
}

impl<I: ItemStore, V: EventLog, N: Notifier, C: Clock, U: UserRepo> PutItem<I, V, N, C, U> {
    /// Stores the write and returns the item as stored, with its change id. A write over a
    /// revision other than `write.expected` is `Conflict`, naming the current revision.
    pub async fn execute(&self, actor: &Actor, write: ItemWrite) -> Result<Item, AppError> {
        let id = write.id;
        check_key_version(&self.users, actor.user, &write).await?;
        let now = self.clock.now();
        let stored = self.items.get(id).await?;
        let draft = write
            .apply(stored.as_ref(), actor.user, self.config.item_limits, now)
            .map_err(|e| AppError::from_item(id, e))?;
        // After the owner, the revision and the sizes, so a caller who may not write the owner
        // learns nothing of whether it takes only signed writes.
        if crate::signed_writes::refuses_unsigned(&self.items, &draft).await? {
            return Err(AppError::from_item(id, ItemError::SignatureRequired));
        }
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
