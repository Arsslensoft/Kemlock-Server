//! `TagSync` on `SqlStore`: the duplicate tags of an owner's items as federation moves them.
//!
//! A tag is valid only while its `item_revision` is the item's current one and the item is live (see
//! `dedup`), so what leaves here is the tags of live items at their current revision, and what
//! arrives is stored by `TagStore::put_tags`, which keeps a tag only for the revision the item is
//! at.

use super::dedup::{live_items, owner_filter};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::item_tags;
use kemlock_app::dedup::TagStore;
use kemlock_app::ports::StoreError;
use kemlock_domain::{DedupTag, ItemId, Owner, Revision, TagSet};
use kemlock_federation::tagsync::{ItemTags, TagSync};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use uuid::Uuid;

impl TagSync for SqlStore {
    async fn matching_on(&self, owner: Owner) -> Result<bool, StoreError> {
        Ok(TagStore::settings(self, owner).await?.enabled)
    }

    async fn tags_of(&self, owner: Owner, items: &[ItemId]) -> Result<Vec<ItemTags>, StoreError> {
        let live = live_items(self.reader(), owner).await?;
        let ids: Vec<Uuid> = items
            .iter()
            .map(|i| i.0)
            .filter(|id| live.contains_key(id))
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = item_tags::Entity::find()
            .filter(owner_filter(owner))
            .filter(item_tags::Column::ItemId.is_in(ids))
            .all(self.reader())
            .await
            .store()?;
        // Per item: its revision, the key version and the tags, for rows at the current revision.
        let mut by_item: BTreeMap<Uuid, (i64, i64, BTreeSet<[u8; 32]>)> = BTreeMap::new();
        for row in rows {
            if live.get(&row.item_id) != Some(&row.item_revision) {
                continue;
            }
            let Some(tag) = DedupTag::from_slice(&row.tag) else {
                continue;
            };
            by_item
                .entry(row.item_id)
                .or_insert_with(|| (row.item_revision, row.key_version, BTreeSet::new()))
                .2
                .insert(*tag.as_bytes());
        }
        Ok(by_item
            .into_iter()
            .map(|(item, (revision, version, tags))| ItemTags {
                item: ItemId(item),
                revision: u64::try_from(revision).unwrap_or(0),
                version: u32::try_from(version).unwrap_or(0),
                tags: tags.into_iter().collect(),
            })
            .collect())
    }

    async fn untagged(&self, owner: Owner, limit: u32) -> Result<Vec<ItemId>, StoreError> {
        let live = live_items(self.reader(), owner).await?;
        let tagged: Vec<(Uuid, i64)> = item_tags::Entity::find()
            .select_only()
            .column(item_tags::Column::ItemId)
            .column(item_tags::Column::ItemRevision)
            .filter(owner_filter(owner))
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let tagged: HashSet<(Uuid, i64)> = tagged.into_iter().collect();
        let mut out: Vec<ItemId> = live
            .into_iter()
            .filter(|(id, revision)| !tagged.contains(&(*id, *revision)))
            .map(|(id, _)| ItemId(id))
            .collect();
        out.sort();
        out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(out)
    }

    async fn apply_tags(&self, owner: Owner, tags: &ItemTags) -> Result<bool, StoreError> {
        let set = TagSet::new(tags.version, tags.tags.iter().map(|t| DedupTag(*t)))
            .map_err(|_| StoreError::Backend("tags that are not valid".to_owned()))?;
        TagStore::put_tags(self, owner, tags.item, Revision(tags.revision), &set).await
    }
}
