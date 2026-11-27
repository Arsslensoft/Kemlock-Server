//! `TagStore` and `DismissalStore` on `item_tags`, `dedup_owners` and `duplicate_dismissals`.
//!
//! A tag is valid only while its `item_revision` is the item's current one and the item is live:
//! the group queries join the two in memory (one read of the owner's live items), so a tag left
//! behind by any writer is inert. Writers also delete the item's tags in their own transaction
//! ([`clear_in`], called by `items::write_in`, which every item write goes through: the Kemlock
//! API, the Bitwarden API, spaces and key replacements).

use crate::convert::{corrupt, to_i64, utc};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::items::owner_parts;
use crate::tables::{dedup_owners, duplicate_dismissals, item_tags, items};
use kemlock_app::dedup::{DismissalStore, TagStore};
use kemlock_app::ports::StoreError;
use kemlock_domain::dedup::group_pairs;
use kemlock_domain::{
    DedupTag, Dismissal, DismissalId, DuplicateGroup, ItemId, MatchingSettings, Owner, Revision,
    TagSet, UserId,
};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, TransactionTrait,
};
use std::collections::{BTreeSet, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

/// Deletes the tags of these items. Called in the transaction of the write that makes them stale.
pub(super) async fn clear_in(txn: &DatabaseTransaction, items: &[Uuid]) -> Result<(), StoreError> {
    if items.is_empty() {
        return Ok(());
    }
    item_tags::Entity::delete_many()
        .filter(item_tags::Column::ItemId.is_in(items.iter().copied()))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// All of an owner's tags, in or out of date.
pub(super) fn owner_filter(owner: Owner) -> sea_orm::Condition {
    let (owner_type, owner_id) = owner_parts(owner);
    sea_orm::Condition::all()
        .add(item_tags::Column::OwnerType.eq(owner_type))
        .add(item_tags::Column::OwnerId.eq(owner_id))
}

/// The live items of `owner` and their current revisions.
pub(super) async fn live_items<C: ConnectionTrait>(
    db: &C,
    owner: Owner,
) -> Result<HashMap<Uuid, i64>, StoreError> {
    let (owner_type, owner_id) = owner_parts(owner);
    let rows: Vec<(Uuid, i64)> = items::Entity::find()
        .select_only()
        .column(items::Column::Id)
        .column(items::Column::Revision)
        .filter(items::Column::OwnerType.eq(owner_type))
        .filter(items::Column::OwnerId.eq(owner_id))
        .filter(items::Column::DeletedAt.is_null())
        .into_tuple()
        .all(db)
        .await
        .store()?;
    Ok(rows.into_iter().collect())
}

/// The owner's tag rows under `version` whose item is live at the revision the tag was made for.
async fn valid_rows<C: ConnectionTrait>(
    db: &C,
    owner: Owner,
    version: u32,
) -> Result<Vec<item_tags::Model>, StoreError> {
    let live = live_items(db, owner).await?;
    let rows = item_tags::Entity::find()
        .filter(owner_filter(owner))
        .filter(item_tags::Column::KeyVersion.eq(i64::from(version)))
        .all(db)
        .await
        .store()?;
    Ok(rows
        .into_iter()
        .filter(|row| live.get(&row.item_id) == Some(&row.item_revision))
        .collect())
}

fn tag_of(row: &item_tags::Model) -> Result<DedupTag, StoreError> {
    DedupTag::from_slice(&row.tag).ok_or_else(|| corrupt("dedup tag"))
}

/// Commits when `outcome` is good, rolls back when it isn't, and hands `outcome` on.
async fn finish<T>(
    txn: DatabaseTransaction,
    outcome: Result<T, StoreError>,
    what: &str,
) -> Result<T, StoreError> {
    match outcome {
        Ok(value) => {
            txn.commit().await.store()?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback) = txn.rollback().await {
                tracing::warn!(%rollback, "rollback after {what} failed");
            }
            Err(err)
        }
    }
}

async fn settings_in<C: ConnectionTrait>(
    db: &C,
    owner: Owner,
) -> Result<MatchingSettings, StoreError> {
    let (owner_type, owner_id) = owner_parts(owner);
    dedup_owners::Entity::find_by_id((owner_type, owner_id))
        .one(db)
        .await
        .store()?
        .map(dedup_owners::Model::into_domain)
        .transpose()
        .map(|found| found.unwrap_or_else(|| MatchingSettings::initial(owner)))
}

/// Stores `settings` as the owner's row, inserting or updating it.
async fn save_settings(
    txn: &DatabaseTransaction,
    settings: &MatchingSettings,
) -> Result<(), StoreError> {
    let (owner_type, owner_id) = owner_parts(settings.owner);
    let exists = dedup_owners::Entity::find_by_id((owner_type, owner_id))
        .one(txn)
        .await
        .store()?
        .is_some();
    let row = dedup_owners::active(settings);
    if exists {
        dedup_owners::Entity::update_many()
            .set(dedup_owners::ActiveModel {
                owner_type: NotSet,
                owner_id: NotSet,
                ..row
            })
            .filter(dedup_owners::Column::OwnerType.eq(owner_type))
            .filter(dedup_owners::Column::OwnerId.eq(owner_id))
            .exec(txn)
            .await
            .store()?;
    } else {
        dedup_owners::Entity::insert(row).exec(txn).await.store()?;
    }
    Ok(())
}

async fn delete_owner_tags(txn: &DatabaseTransaction, owner: Owner) -> Result<(), StoreError> {
    item_tags::Entity::delete_many()
        .filter(owner_filter(owner))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

impl TagStore for SqlStore {
    async fn settings(&self, owner: Owner) -> Result<MatchingSettings, StoreError> {
        settings_in(self.reader(), owner).await
    }

    async fn set_matching(
        &self,
        owner: Owner,
        enabled: bool,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<MatchingSettings, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let mut settings = settings_in(&txn, owner).await?;
            settings.enabled = enabled;
            settings.changed_by = Some(by);
            settings.changed_at = Some(utc(at));
            save_settings(&txn, &settings).await?;
            if !enabled {
                delete_owner_tags(&txn, owner).await?;
            }
            Ok::<MatchingSettings, StoreError>(settings)
        }
        .await;
        finish(txn, outcome, "a failed matching change").await
    }

    async fn bump_version(&self, owner: Owner, at: OffsetDateTime) -> Result<u32, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let mut settings = settings_in(&txn, owner).await?;
            settings.version = settings
                .version
                .checked_add(1)
                .ok_or_else(|| corrupt("dedup version"))?;
            settings.changed_at = Some(utc(at));
            save_settings(&txn, &settings).await?;
            delete_owner_tags(&txn, owner).await?;
            Ok::<u32, StoreError>(settings.version)
        }
        .await;
        finish(txn, outcome, "a failed dedup key rotation").await
    }

    async fn put_tags(
        &self,
        owner: Owner,
        item: ItemId,
        revision: Revision,
        tags: &TagSet,
    ) -> Result<bool, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        let revision = to_i64(revision.0, "revision")?;
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let current = items::Entity::find_by_id(item.0).one(&txn).await.store()?;
            let fits = current.is_some_and(|row| {
                row.owner_type == owner_type
                    && row.owner_id == owner_id
                    && row.deleted_at.is_none()
                    && row.revision == revision
            });
            if !fits {
                return Ok(false);
            }
            clear_in(&txn, &[item.0]).await?;
            if !tags.tags.is_empty() {
                let rows = tags.tags.iter().map(|tag| item_tags::ActiveModel {
                    owner_type: Set(owner_type),
                    owner_id: Set(owner_id),
                    tag: Set(tag.as_bytes().to_vec()),
                    item_id: Set(item.0),
                    item_revision: Set(revision),
                    key_version: Set(i64::from(tags.version)),
                });
                item_tags::Entity::insert_many(rows)
                    .exec(&txn)
                    .await
                    .store()?;
            }
            Ok::<bool, StoreError>(true)
        }
        .await;
        finish(txn, outcome, "a failed tag write").await
    }

    async fn matches(
        &self,
        owner: Owner,
        version: u32,
        item: ItemId,
    ) -> Result<Vec<ItemId>, StoreError> {
        let rows = valid_rows(self.reader(), owner, version).await?;
        let mine: BTreeSet<&[u8]> = rows
            .iter()
            .filter(|row| row.item_id == item.0)
            .map(|row| row.tag.as_slice())
            .collect();
        let others: BTreeSet<ItemId> = rows
            .iter()
            .filter(|row| row.item_id != item.0 && mine.contains(row.tag.as_slice()))
            .map(|row| ItemId(row.item_id))
            .collect();
        Ok(others.into_iter().collect())
    }

    async fn groups(&self, owner: Owner, version: u32) -> Result<Vec<DuplicateGroup>, StoreError> {
        let rows = valid_rows(self.reader(), owner, version).await?;
        let pairs = rows
            .iter()
            .map(|row| Ok((tag_of(row)?, ItemId(row.item_id))))
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(group_pairs(pairs))
    }

    async fn waiting(&self, owner: Owner, version: u32) -> Result<u64, StoreError> {
        let live = live_items(self.reader(), owner).await?;
        let tagged: BTreeSet<Uuid> = valid_rows(self.reader(), owner, version)
            .await?
            .into_iter()
            .map(|row| row.item_id)
            .collect();
        let waiting = live.keys().filter(|id| !tagged.contains(*id)).count();
        u64::try_from(waiting).map_err(|_| corrupt("waiting count"))
    }

    async fn waiting_items(&self, owner: Owner, version: u32) -> Result<Vec<ItemId>, StoreError> {
        let live = live_items(self.reader(), owner).await?;
        let tagged: BTreeSet<Uuid> = valid_rows(self.reader(), owner, version)
            .await?
            .into_iter()
            .map(|row| row.item_id)
            .collect();
        Ok(live
            .keys()
            .filter(|id| !tagged.contains(*id))
            .map(|id| ItemId(*id))
            .collect())
    }
}

impl DismissalStore for SqlStore {
    async fn add(&self, dismissal: &Dismissal) -> Result<(), StoreError> {
        duplicate_dismissals::Entity::insert(duplicate_dismissals::active(dismissal))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn get(&self, id: DismissalId) -> Result<Option<Dismissal>, StoreError> {
        duplicate_dismissals::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(duplicate_dismissals::Model::into_domain)
            .transpose()
    }

    async fn list(&self, owner: Owner) -> Result<Vec<Dismissal>, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        duplicate_dismissals::Entity::find()
            .filter(duplicate_dismissals::Column::OwnerType.eq(owner_type))
            .filter(duplicate_dismissals::Column::OwnerId.eq(owner_id))
            .order_by_asc(duplicate_dismissals::Column::AnsweredAt)
            .order_by_asc(duplicate_dismissals::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(duplicate_dismissals::Model::into_domain)
            .collect()
    }

    async fn remove(&self, id: DismissalId) -> Result<bool, StoreError> {
        let removed = duplicate_dismissals::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(removed.rows_affected == 1)
    }
}
