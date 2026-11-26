//! Storing tags: beside an item write ([`StoreTags`]) and for an item already stored
//! ([`BackfillTags`], `PUT /kem/v1/items/{id}/tags`).
//!
//! The server never makes a tag. A write without tags clears the item's tags (the store does it in
//! the write's own transaction), so a tag always belongs to the revision it was made for.

use super::access::{Need, authorize, authorize_item_write, visible};
use super::error::DedupError;
use super::ports::TagStore;
use crate::authenticate::Actor;
use crate::ports::ItemStore;
use crate::spaces::SpaceRepo;
use kemlock_domain::{Item, ItemId, MatchingSettings, Owner, Revision, TagSet};
use std::collections::HashMap;

/// What became of the tags that came with a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagOutcome {
    /// Whether the tags were stored. They are not when server matching is off for the owner or
    /// the tags were made under another dedup key version; the item itself was written either way.
    pub stored: bool,
    /// The other items of the owner that share a tag with this one, and that the writer may see:
    /// in a space, only items of collections they hold a grant on. Ids of the others would tell a
    /// member with edit on one collection which guesses match items they can't see.
    pub matches: Vec<ItemId>,
}

impl TagOutcome {
    fn ignored() -> TagOutcome {
        TagOutcome {
            stored: false,
            matches: Vec::new(),
        }
    }
}

/// Stores the tags that came with item writes.
#[derive(Debug)]
pub struct StoreTags<T, R> {
    pub tags: T,
    pub spaces: R,
}

impl<T: TagStore, R: SpaceRepo> StoreTags<T, R> {
    /// Stores `tags` for `item`, which was just written. Nothing is stored for a deleted item.
    pub async fn after_write(
        &self,
        actor: &Actor,
        item: &Item,
        tags: TagSet,
    ) -> Result<TagOutcome, DedupError> {
        let settings = self.tags.settings(item.owner).await?;
        self.store(actor, &settings, item, tags).await
    }

    /// [`after_write`](Self::after_write) for a batch: the writes that carried tags, by item id.
    /// Returns an outcome for each of those items, in the order of `items`.
    pub async fn after_batch(
        &self,
        actor: &Actor,
        items: &[Item],
        mut tags: HashMap<ItemId, TagSet>,
    ) -> Result<Vec<(ItemId, TagOutcome)>, DedupError> {
        let mut settings: HashMap<Owner, MatchingSettings> = HashMap::new();
        let mut out = Vec::new();
        for item in items {
            let Some(set) = tags.remove(&item.id) else {
                continue;
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = settings.entry(item.owner) {
                slot.insert(self.tags.settings(item.owner).await?);
            }
            let Some(current) = settings.get(&item.owner) else {
                continue;
            };
            out.push((item.id, self.store(actor, current, item, set).await?));
        }
        Ok(out)
    }

    async fn store(
        &self,
        actor: &Actor,
        settings: &MatchingSettings,
        item: &Item,
        tags: TagSet,
    ) -> Result<TagOutcome, DedupError> {
        if item.is_tombstone() || !settings.enabled || tags.version != settings.version {
            return Ok(TagOutcome::ignored());
        }
        let stored = self
            .tags
            .put_tags(item.owner, item.id, item.revision, &tags)
            .await?;
        if !stored {
            return Ok(TagOutcome::ignored());
        }
        let matches = self
            .tags
            .matches(item.owner, settings.version, item.id)
            .await?;
        let matches = narrow(&self.spaces, actor, item.owner, matches).await?;
        Ok(TagOutcome {
            stored: true,
            matches,
        })
    }
}

/// Backfills the tags of an item's current revision without resending the item.
#[derive(Debug)]
pub struct BackfillTags<T, I, R> {
    pub tags: T,
    pub items: I,
    pub spaces: R,
}

impl<T: TagStore, I: ItemStore, R: SpaceRepo> BackfillTags<T, I, R> {
    /// Stores `tags` for item `id` at revision `expected` (`If-Match`) and returns the items that
    /// share one. An empty set clears the item's tags. A stale revision is `StaleItem`, tags made
    /// under another key version are `StaleVersion`, and server matching being off is
    /// `MatchingOff`.
    pub async fn execute(
        &self,
        actor: &Actor,
        id: ItemId,
        expected: Revision,
        tags: TagSet,
    ) -> Result<Vec<ItemId>, DedupError> {
        let item = self.items.get(id).await?.ok_or(DedupError::NotFound)?;
        // Who may write them, before anything says what the item looks like.
        let state = authorize(&self.spaces, actor.user, item.owner, Need::Read).await?;
        if let Some(state) = &state {
            authorize_item_write(&self.spaces, state, actor.user, id).await?;
        }
        let settings = self.tags.settings(item.owner).await?;
        if !settings.enabled {
            return Err(DedupError::MatchingOff);
        }
        if tags.version != settings.version {
            return Err(DedupError::StaleVersion {
                current: settings.version,
            });
        }
        if item.is_tombstone() {
            return Err(DedupError::NotFound);
        }
        if item.revision != expected {
            return Err(DedupError::StaleItem {
                item: id,
                current: Some(item.revision),
            });
        }
        let stored = self.tags.put_tags(item.owner, id, expected, &tags).await?;
        if !stored {
            // The item was written again between the read and the store.
            let current = self.items.get(id).await?.map(|i| i.revision);
            return Err(DedupError::StaleItem { item: id, current });
        }
        let matches = self.tags.matches(item.owner, settings.version, id).await?;
        narrow(&self.spaces, actor, item.owner, matches).await
    }
}

/// The matches `actor` may see. In a vault they are the owner's own; in a space they are the
/// items of collections the actor holds a grant on, as `ListDuplicates` shows them.
async fn narrow<R: SpaceRepo>(
    spaces: &R,
    actor: &Actor,
    owner: Owner,
    matches: Vec<ItemId>,
) -> Result<Vec<ItemId>, DedupError> {
    // A vault's matches are all the owner's own, and the owner is the only writer.
    if matches.is_empty() || !matches!(owner, Owner::Space(_)) {
        return Ok(matches);
    }
    let Some(state) = authorize(spaces, actor.user, owner, Need::Read).await? else {
        return Ok(matches);
    };
    let seen = visible(spaces, &state, actor.user, &matches).await?;
    Ok(matches
        .into_iter()
        .filter(|item| seen.contains(item))
        .collect())
}
