//! `ItemStore` on `items`, `changes`, `server_meta` and `sync_horizon`.
//!
//! Every write is one transaction on the writer: it takes this server's next sequence numbers,
//! checks each draft's expected revision against the stored one, writes the item row and appends
//! to the change log, and advances `server_meta`. The first statement is an update of the
//! `server_meta` row, which locks it until commit on every backend, so concurrent writers (two
//! replicas on PostgreSQL or MySQL) queue there, read the revisions after the earlier writer has
//! committed, and take consecutive sequence numbers with no gaps. On SQLite the single writer
//! connection already serialises them.

use crate::convert::{from_i64, to_i64, unix_millis, utc};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::space_chain::held;
use crate::tables::space_tables::{collections, item_collections};
use crate::tables::{changes, items, server_meta, sync_horizon};
use kemlock_app::ports::{ChangePage, EachPage, HeldPage, ItemStore, StoreError};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{
    ChangeId, Hlc, Item, ItemDraft, ItemId, Owner, Revision, ServerId, VersionVector,
};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::{Expr, Query, SelectStatement};
use sea_orm::{
    ColumnTrait, Condition, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// The most drafts one batch may hold.
const MAX_BATCH: usize = 500;

/// The most distinct cursors one `changes_since_each` query ORs together. SQLite refuses an
/// expression nested more than 1,000 deep and an OR chain nests once per branch.
const GROUPS_PER_QUERY: usize = 100;

impl ItemStore for SqlStore {
    async fn get(&self, id: ItemId) -> Result<Option<Item>, StoreError> {
        items::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(items::Model::into_domain)
            .transpose()
    }

    async fn put(&self, draft: ItemDraft) -> Result<Item, StoreError> {
        self.write_drafts(vec![draft])
            .await?
            .pop()
            .ok_or_else(|| StoreError::Backend("a write returned no item".to_owned()))
    }

    async fn put_batch(&self, drafts: Vec<ItemDraft>) -> Result<Vec<Item>, StoreError> {
        if drafts.len() > MAX_BATCH {
            return Err(StoreError::Backend(format!(
                "a batch holds at most {MAX_BATCH} items, got {}",
                drafts.len()
            )));
        }
        self.write_drafts(drafts).await
    }

    /// Pages through the items of `owners` that `since` does not cover.
    ///
    /// Items come ordered by `(origin, seq)`, and `next` is `since` advanced by the change id of
    /// every item returned. Ordering by origin first and by sequence second is what makes that
    /// advance safe when a page is cut: the page is a prefix of the uncovered items in that order,
    /// so for each origin it holds the uncovered items with the lowest sequence numbers, and
    /// moving that origin's counter to the highest of them skips nothing that is still to come.
    /// (Ordering by sequence alone would be wrong across origins: sequence numbers of different
    /// origins are unrelated, so a page cut could leave an origin's low sequences behind a high
    /// one.) A change to an item replaces its row's `(origin, seq)`, so each item appears once, at
    /// its latest revision, and a cursor used again finds nothing newer than it.
    async fn changes_since(
        &self,
        owners: &[Owner],
        since: &VersionVector,
        limit: u32,
    ) -> Result<ChangePage, StoreError> {
        if owners.is_empty() {
            return Ok(ChangePage {
                items: Vec::new(),
                next: since.clone(),
                more: false,
            });
        }
        // A page of zero items could never make progress.
        let limit = limit.max(1);
        let page_len = usize::try_from(limit).unwrap_or(usize::MAX);

        let mut query = items::Entity::find()
            .filter(owner_condition(owners))
            .filter(not_held());
        if !since.is_empty() {
            query = query.filter(uncovered_condition(since));
        }
        // One row more than the page, to know whether another page follows.
        let mut rows = query
            .order_by_asc(items::Column::Origin)
            .order_by_asc(items::Column::Seq)
            .limit(u64::from(limit) + 1)
            .all(self.reader())
            .await
            .store()?;
        let more = rows.len() > page_len;
        rows.truncate(page_len);

        let mut next = since.clone();
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let item = row.into_domain()?;
            next.observe(&item.change);
            page.push(item);
        }
        Ok(ChangePage {
            items: page,
            next,
            more,
        })
    }

    async fn latest(&self, owners: &[Owner]) -> Result<VersionVector, StoreError> {
        if owners.is_empty() {
            return Ok(VersionVector::new());
        }
        let rows: Vec<(Uuid, i64)> = items::Entity::find()
            .select_only()
            .column(items::Column::Origin)
            .column_as(items::Column::Seq.max(), "max_seq")
            .filter(owner_condition(owners))
            .filter(not_held())
            .group_by(items::Column::Origin)
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        vector_of(rows)
    }

    async fn purged_through(&self, owners: &[Owner]) -> Result<VersionVector, StoreError> {
        if owners.is_empty() {
            return Ok(VersionVector::new());
        }
        let rows = sync_horizon::Entity::find()
            .filter(owner_condition_on(
                owners,
                sync_horizon::Column::OwnerType,
                sync_horizon::Column::OwnerId,
            ))
            .all(self.reader())
            .await
            .store()?;
        sync_horizon::to_vector(rows)
    }

    /// [`ItemStore::changes_since`] with a cursor per owner, in one query.
    ///
    /// Owners that hold the same vector (every owner that is new to the device holds the empty
    /// one) share one branch of the condition, so a first sync is a single branch whatever the
    /// number of spaces. The branches are `OR`ed, in chunks of [`GROUPS_PER_QUERY`] because
    /// SQLite limits how deep one expression may nest. Ordering, the extra row that says whether
    /// more follow and the prefix argument are those of `changes_since`; the page is the first
    /// `limit` of every chunk's rows, see [`EachPage::merge`].
    async fn changes_since_each(
        &self,
        owners: &[(Owner, VersionVector)],
        limit: u32,
    ) -> Result<EachPage, StoreError> {
        let limit = limit.max(1);
        let page_len = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut parts = Vec::new();
        for chunk in group_by_cursor(owners).chunks(GROUPS_PER_QUERY) {
            let mut any = Condition::any();
            for (group, since) in chunk {
                let mut branch = Condition::all().add(owner_condition(group));
                if !since.is_empty() {
                    branch = branch.add(uncovered_condition(since));
                }
                any = any.add(branch);
            }
            let mut rows = items::Entity::find()
                .filter(any)
                .filter(not_held())
                .order_by_asc(items::Column::Origin)
                .order_by_asc(items::Column::Seq)
                .limit(u64::from(limit) + 1)
                .all(self.reader())
                .await
                .store()?;
            let more = rows.len() > page_len;
            rows.truncate(page_len);
            let found = rows
                .into_iter()
                .map(items::Model::into_domain)
                .collect::<Result<Vec<_>, _>>()?;
            parts.push((found, more));
        }
        Ok(EachPage::merge(parts, limit))
    }

    async fn latest_each(
        &self,
        owners: &[Owner],
    ) -> Result<Vec<(Owner, VersionVector)>, StoreError> {
        if owners.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(i16, Uuid, Uuid, i64)> = items::Entity::find()
            .select_only()
            .column(items::Column::OwnerType)
            .column(items::Column::OwnerId)
            .column(items::Column::Origin)
            .column_as(items::Column::Seq.max(), "max_seq")
            .filter(owner_condition(owners))
            .filter(not_held())
            .group_by(items::Column::OwnerType)
            .group_by(items::Column::OwnerId)
            .group_by(items::Column::Origin)
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        vectors_by_owner(owners, rows)
    }

    /// The held items of each collection that its vector doesn't cover, in the order and with the
    /// prefix argument of `changes_since`: one query per collection, as few collections have any
    /// held item, and then the first `limit` of all of them.
    async fn held_since_each(
        &self,
        collections: &[(CollectionId, VersionVector)],
        limit: u32,
    ) -> Result<HeldPage, StoreError> {
        let limit = limit.max(1);
        let page_len = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut found: Vec<(CollectionId, Item)> = Vec::new();
        let mut more = false;
        for (collection, since) in collections {
            let mut query = items::Entity::find()
                .filter(Condition::all().add(Expr::exists(held_row())))
                .filter(Condition::all().add(Expr::exists(in_collection(*collection))));
            if !since.is_empty() {
                query = query.filter(uncovered_condition(since));
            }
            let mut rows = query
                .order_by_asc(items::Column::Origin)
                .order_by_asc(items::Column::Seq)
                .limit(u64::from(limit) + 1)
                .all(self.reader())
                .await
                .store()?;
            more |= rows.len() > page_len;
            rows.truncate(page_len);
            for row in rows {
                found.push((*collection, row.into_domain()?));
            }
        }
        found.sort_by_key(|(_, item)| (item.change.origin, item.change.seq));
        if found.len() > page_len {
            found.truncate(page_len);
            more = true;
        }
        Ok(HeldPage { items: found, more })
    }

    async fn held_latest_each(
        &self,
        collections: &[CollectionId],
    ) -> Result<Vec<(CollectionId, VersionVector)>, StoreError> {
        let mut each = Vec::with_capacity(collections.len());
        for collection in collections {
            let rows: Vec<(Uuid, i64)> = items::Entity::find()
                .select_only()
                .column(items::Column::Origin)
                .column_as(items::Column::Seq.max(), "max_seq")
                .filter(Condition::all().add(Expr::exists(held_row())))
                .filter(Condition::all().add(Expr::exists(in_collection(*collection))))
                .group_by(items::Column::Origin)
                .into_tuple()
                .all(self.reader())
                .await
                .store()?;
            each.push((*collection, vector_of(rows)?));
        }
        Ok(each)
    }

    /// Not filtered for held items: the horizon is made of purged tombstones, and a held item is
    /// live, so no held item is behind it.
    async fn purged_each(
        &self,
        owners: &[Owner],
    ) -> Result<Vec<(Owner, VersionVector)>, StoreError> {
        if owners.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sync_horizon::Entity::find()
            .filter(owner_condition_on(
                owners,
                sync_horizon::Column::OwnerType,
                sync_horizon::Column::OwnerId,
            ))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| (row.owner_type, row.owner_id, row.origin, row.purged_through));
        vectors_by_owner(owners, rows)
    }

    async fn purge_tombstones(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let txn = self.writer().begin().await.store()?;
        match purge_in(&txn, before).await {
            Ok(purged) => {
                txn.commit().await.store()?;
                Ok(purged)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed purge failed");
                }
                Err(err)
            }
        }
    }
}

impl SqlStore {
    /// `put` for one or more drafts in one transaction: all are stored or none is.
    async fn write_drafts(&self, drafts: Vec<ItemDraft>) -> Result<Vec<Item>, StoreError> {
        if drafts.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.writer().begin().await.store()?;
        match write_in(&txn, self.origin(), drafts).await {
            Ok(stored) => {
                txn.commit().await.store()?;
                Ok(stored)
            }
            Err(err) => {
                // Dropping the transaction would roll back too; doing it here hands the writer
                // connection back clean before the next write asks for it.
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed write failed");
                }
                Err(err)
            }
        }
    }
}

/// The body of a write transaction.
pub(super) async fn write_in(
    txn: &DatabaseTransaction,
    origin: ServerId,
    drafts: Vec<ItemDraft>,
) -> Result<Vec<Item>, StoreError> {
    lock_meta(txn).await?;
    let meta = server_meta::Entity::find_by_id(server_meta::ROW_ID)
        .one(txn)
        .await
        .store()?
        .ok_or_else(|| StoreError::Backend("server_meta has no row".to_owned()))?;

    let mut seq = meta.next_seq;
    let mut hlc = Hlc(from_i64(meta.last_hlc, "hlc")?);
    let mut stored = Vec::with_capacity(drafts.len());
    for draft in drafts {
        stored.push(write_one(txn, origin, draft, seq, &mut hlc).await?);
        seq += 1;
    }

    server_meta::Entity::update_many()
        .col_expr(server_meta::Column::NextSeq, Expr::value(seq))
        .col_expr(
            server_meta::Column::LastHlc,
            Expr::value(to_i64(hlc.0, "hlc")?),
        )
        .filter(server_meta::Column::Id.eq(server_meta::ROW_ID))
        .exec(txn)
        .await
        .store()?;
    // Whatever wrote these items, the tags of their older revisions go with the write.
    let written: Vec<Uuid> = stored.iter().map(|item| item.id.0).collect();
    super::dedup::clear_in(txn, &written).await?;
    Ok(stored)
}

/// Releases a held item that the write `item` has just replaced, when the write may release it
/// (docs/crypto.md, I4): a tombstone, or a revision whose `key_version` is the current one of
/// `collection`, the collection it was written into. Any other write leaves the item held, however
/// it got here: the use cases refuse one under an old key version (I2) before they store it, and
/// this check keeps a caller that doesn't from lifting the hold. The write is a new change at a
/// new sequence number, so every cursor receives the released item as that change.
pub(super) async fn release_written(
    txn: &DatabaseTransaction,
    item: &Item,
    collection: Option<CollectionId>,
) -> Result<(), StoreError> {
    if !matches!(item.owner, Owner::Space(_)) {
        return Ok(());
    }
    if !item.is_tombstone() {
        let Some(collection) = collection else {
            return Ok(());
        };
        let current = collections::Entity::find_by_id(collection.0)
            .one(txn)
            .await
            .store()?
            .map(|row| row.key_version);
        if current != Some(i64::from(item.key_version)) {
            return Ok(());
        }
    }
    held::Entity::delete_many()
        .filter(held::Column::ItemId.eq(item.id.0))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// Takes the `server_meta` row's lock by rewriting a column with its own value.
async fn lock_meta(txn: &DatabaseTransaction) -> Result<(), StoreError> {
    server_meta::Entity::update_many()
        .col_expr(
            server_meta::Column::LastHlc,
            Expr::col(server_meta::Column::LastHlc),
        )
        .filter(server_meta::Column::Id.eq(server_meta::ROW_ID))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// Checks one draft against what is stored, then writes the item and its change at `seq`.
async fn write_one(
    txn: &DatabaseTransaction,
    origin: ServerId,
    draft: ItemDraft,
    seq: i64,
    hlc: &mut Hlc,
) -> Result<Item, StoreError> {
    let stored = items::Entity::find_by_id(draft.id.0)
        .one(txn)
        .await
        .store()?;
    write_over(txn, origin, draft, seq, hlc, stored).await
}

/// How far ahead of this server's clock a draft's time may pull the HLC, in milliseconds: the
/// 300 seconds of skew a receiving server allows a change record (docs/federation.md).
const HLC_SKEW_MS: u64 = 300_000;

/// [`write_one`] given the row it read. The update must change exactly that row: one that
/// changed none means the row was replaced or purged after it was read, and the write is refused
/// as a conflict instead of being reported as stored.
async fn write_over(
    txn: &DatabaseTransaction,
    origin: ServerId,
    draft: ItemDraft,
    seq: i64,
    hlc: &mut Hlc,
    stored: Option<items::Model>,
) -> Result<Item, StoreError> {
    let (owner_type, owner_id) = items::owner_parts(draft.owner);

    if let Some(row) = &stored
        && (row.owner_type != owner_type || row.owner_id != owner_id)
    {
        // The id is some other owner's item. Say it is taken, and nothing about that item.
        return Err(StoreError::Duplicate);
    }
    let current = stored
        .as_ref()
        .map(|row| from_i64(row.revision, "revision").map(Revision))
        .transpose()?;
    if current != draft.expected {
        return Err(StoreError::Conflict {
            item: draft.id,
            current,
        });
    }

    // Not before the last HLC, and not before the time the draft was made, but never further
    // ahead than a receiving server accepts: the draft's time is the client's, and a far-future
    // one would pin this server's clock there and break the order of every later write.
    let ceiling = unix_millis(OffsetDateTime::now_utc()).saturating_add(HLC_SKEW_MS);
    *hlc = hlc.tick(unix_millis(draft.updated_at).min(ceiling));
    let change = ChangeId {
        origin,
        seq: from_i64(seq, "sequence number")?,
        hlc: *hlc,
    };
    let item = draft.into_item(change);

    let row = items::active(&item)?;
    if stored.is_some() {
        let updated = items::Entity::update_many()
            .set(items::ActiveModel { id: NotSet, ..row })
            .filter(items::Column::Id.eq(item.id.0))
            .exec(txn)
            .await
            .store()?;
        if updated.rows_affected != 1 {
            let now_stored = items::Entity::find_by_id(item.id.0)
                .one(txn)
                .await
                .store()?;
            let current = now_stored
                .map(|row| from_i64(row.revision, "revision").map(Revision))
                .transpose()?;
            return Err(StoreError::Conflict {
                item: item.id,
                current,
            });
        }
    } else {
        items::Entity::insert(row).exec(txn).await.store()?;
    }
    changes::Entity::insert(changes::active(&item)?)
        .exec(txn)
        .await
        .store()?;
    Ok(item)
}

/// Deletes tombstones deleted before `before` and records, per owner and origin, the highest
/// sequence number purged, so a cursor of that owner older than that knows it must start a full
/// sync.
async fn purge_in(txn: &DatabaseTransaction, before: OffsetDateTime) -> Result<u64, StoreError> {
    // The same lock every write takes first, so on PostgreSQL and MySQL a purge never runs
    // between a writer's read of a row and its update of it (and the other way round).
    lock_meta(txn).await?;
    let old = Condition::all()
        .add(items::Column::DeletedAt.is_not_null())
        .add(items::Column::DeletedAt.lt(utc(before)));

    let highest: Vec<(i16, Uuid, Uuid, i64)> = items::Entity::find()
        .select_only()
        .column(items::Column::OwnerType)
        .column(items::Column::OwnerId)
        .column(items::Column::Origin)
        .column_as(items::Column::Seq.max(), "max_seq")
        .filter(old.clone())
        .group_by(items::Column::OwnerType)
        .group_by(items::Column::OwnerId)
        .group_by(items::Column::Origin)
        .into_tuple()
        .all(txn)
        .await
        .store()?;
    if highest.is_empty() {
        return Ok(0);
    }

    for (owner_type, owner_id, origin, max_seq) in highest {
        let horizon = sync_horizon::Entity::find_by_id((owner_type, owner_id, origin))
            .one(txn)
            .await
            .store()?;
        match horizon {
            Some(row) if row.purged_through >= max_seq => {}
            Some(_) => {
                sync_horizon::Entity::update_many()
                    .col_expr(sync_horizon::Column::PurgedThrough, Expr::value(max_seq))
                    .filter(sync_horizon::Column::OwnerType.eq(owner_type))
                    .filter(sync_horizon::Column::OwnerId.eq(owner_id))
                    .filter(sync_horizon::Column::Origin.eq(origin))
                    .exec(txn)
                    .await
                    .store()?;
            }
            None => {
                let fresh = sync_horizon::ActiveModel {
                    owner_type: Set(owner_type),
                    owner_id: Set(owner_id),
                    origin: Set(origin),
                    purged_through: Set(max_seq),
                };
                sync_horizon::Entity::insert(fresh)
                    .exec(txn)
                    .await
                    .store()?;
            }
        }
    }

    let deleted = items::Entity::delete_many()
        .filter(old)
        .exec(txn)
        .await
        .store()?;
    Ok(deleted.rows_affected)
}

/// `SELECT 1 FROM space_held_items WHERE space_held_items.item_id = items.id`: the item at hand is
/// held back by a key replacement.
fn held_row() -> SelectStatement {
    // Only here: with `ExprTrait` in scope, `Column::eq` would be ambiguous.
    use sea_orm::sea_query::ExprTrait;
    Query::select()
        .expr(Expr::val(1))
        .from(held::Entity)
        .and_where(
            Expr::col((held::Entity, held::Column::ItemId))
                .equals((items::Entity, items::Column::Id)),
        )
        .take()
}

/// `SELECT 1 FROM item_collections WHERE item_collections.item_id = items.id AND
/// item_collections.collection_id = <collection>`: the item at hand is in `collection`.
fn in_collection(collection: CollectionId) -> SelectStatement {
    // Only here: with `ExprTrait` in scope, `Column::eq` would be ambiguous.
    use sea_orm::sea_query::ExprTrait;
    Query::select()
        .expr(Expr::val(1))
        .from(item_collections::Entity)
        .and_where(
            Expr::col((item_collections::Entity, item_collections::Column::ItemId))
                .equals((items::Entity, items::Column::Id)),
        )
        .and_where(
            Expr::col((
                item_collections::Entity,
                item_collections::Column::CollectionId,
            ))
            .eq(Expr::val(collection.0)),
        )
        .take()
}

/// Rows of `items` that no key replacement holds back. A held item is kept but not served
/// (docs/crypto.md, I3), so every read a device syncs from leaves it out, the newest-change
/// reads (`latest`) included: a cursor can't be asked to cover a change it was never sent.
fn not_held() -> Condition {
    Condition::all().add(Expr::not_exists(held_row()))
}

/// Rows of `items` that belong to any of `owners`.
fn owner_condition(owners: &[Owner]) -> Condition {
    owner_condition_on(owners, items::Column::OwnerType, items::Column::OwnerId)
}

/// Rows that belong to any of `owners`, given the columns of a table that name an owner.
fn owner_condition_on<T: ColumnTrait, I: ColumnTrait>(
    owners: &[Owner],
    type_column: T,
    id_column: I,
) -> Condition {
    let mut users = Vec::new();
    let mut spaces = Vec::new();
    for owner in owners {
        match owner {
            Owner::User(user) => users.push(user.0),
            Owner::Space(space) => spaces.push(space.0),
        }
    }
    let mut any = Condition::any();
    if !users.is_empty() {
        any = any.add(
            Condition::all()
                .add(type_column.eq(i16::from(Owner::TYPE_USER)))
                .add(id_column.is_in(users)),
        );
    }
    if !spaces.is_empty() {
        any = any.add(
            Condition::all()
                .add(type_column.eq(i16::from(Owner::TYPE_SPACE)))
                .add(id_column.is_in(spaces)),
        );
    }
    any
}

/// Rows whose change `since` does not cover: for an origin the vector knows, a higher sequence
/// number than its entry; for an origin it has never seen, any.
fn uncovered_condition(since: &VersionVector) -> Condition {
    let mut any = Condition::any();
    let mut known = Vec::new();
    for (origin, seen) in since.iter() {
        known.push(origin.0);
        any = any.add(
            Condition::all()
                .add(items::Column::Origin.eq(origin.0))
                .add(items::Column::Seq.gt(i64::try_from(seen).unwrap_or(i64::MAX))),
        );
    }
    any.add(items::Column::Origin.is_not_in(known))
}

/// The owners grouped by the vector they hold, so owners with the same cursor share a condition.
fn group_by_cursor(owners: &[(Owner, VersionVector)]) -> Vec<(Vec<Owner>, &VersionVector)> {
    let mut groups: Vec<(Vec<Owner>, &VersionVector)> = Vec::new();
    for (owner, since) in owners {
        match groups.iter_mut().find(|group| group.1 == since) {
            Some(group) => group.0.push(*owner),
            None => groups.push((vec![*owner], since)),
        }
    }
    groups
}

/// One vector per requested owner, in the order given, from rows of
/// `(owner type, owner id, origin, sequence)`. An owner without rows gets the empty vector.
fn vectors_by_owner(
    owners: &[Owner],
    rows: impl IntoIterator<Item = (i16, Uuid, Uuid, i64)>,
) -> Result<Vec<(Owner, VersionVector)>, StoreError> {
    let mut entries: BTreeMap<Owner, Vec<(ServerId, u64)>> = BTreeMap::new();
    for (owner_type, owner_id, origin, seq) in rows {
        entries
            .entry(items::owner_from(owner_type, owner_id)?)
            .or_default()
            .push((ServerId(origin), from_i64(seq, "sequence number")?));
    }
    Ok(owners
        .iter()
        .map(|owner| {
            let vector: VersionVector = entries
                .remove(owner)
                .unwrap_or_default()
                .into_iter()
                .collect();
            (*owner, vector)
        })
        .collect())
}

fn vector_of(rows: Vec<(Uuid, i64)>) -> Result<VersionVector, StoreError> {
    let mut entries = Vec::with_capacity(rows.len());
    for (origin, seq) in rows {
        entries.push((ServerId(origin), from_i64(seq, "sequence number")?));
    }
    Ok(entries.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::UserId;

    #[test]
    fn a_vector_comes_from_per_origin_maxima() {
        let a = ServerId::random();
        let b = ServerId::random();
        let v = vector_of(vec![(a.0, 5), (b.0, 9)]).expect("valid");
        assert_eq!(v.get(a), 5);
        assert_eq!(v.get(b), 9);
        assert!(vector_of(vec![(a.0, -1)]).is_err());
    }

    fn ghost_row(owner: UserId) -> items::Model {
        items::Model {
            id: Uuid::new_v4(),
            owner_type: i16::from(Owner::TYPE_USER),
            owner_id: owner.0,
            kind: "login".to_owned(),
            format: "kem1".to_owned(),
            revision: 1,
            key_version: 1,
            ciphertext: Some(vec![1; 40]),
            item_key: Some(vec![2; 60]),
            deleted_at: None,
            updated_at: utc(time::macros::datetime!(2026-06-01 12:00:00 UTC)),
            origin: Uuid::new_v4(),
            seq: 1,
            hlc: 1,
        }
    }

    #[tokio::test]
    async fn an_update_that_changes_no_row_is_a_conflict_not_a_stored_write() {
        // The writer read this row, but by the time it updates the row is gone, as when a purge
        // on another connection removed it. No row changes, so nothing was stored.
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects");
        let owner = UserId::random();
        let ghost = ghost_row(owner);
        let id = ItemId(ghost.id);
        let draft = ItemDraft {
            id,
            owner: Owner::User(owner),
            kind: kemlock_domain::ItemKind::try_from("login".to_owned()).expect("a valid kind"),
            format: kemlock_domain::ItemFormat::Kem1,
            expected: Some(Revision(1)),
            revision: Revision(2),
            key_version: 1,
            ciphertext: Some(vec![3; 40]),
            item_key: Some(vec![4; 60]),
            deleted_at: None,
            updated_at: time::macros::datetime!(2026-06-02 12:00:00 UTC),
        };
        let txn = store.writer().begin().await.expect("begins");
        let mut hlc = Hlc(0);
        let result = write_over(&txn, store.origin(), draft, 1, &mut hlc, Some(ghost)).await;
        assert_eq!(
            result,
            Err(StoreError::Conflict {
                item: id,
                current: None,
            })
        );
        txn.rollback().await.expect("rolls back");
    }

    #[test]
    fn conditions_build_for_several_owners_and_origins() {
        // Building must not panic, whatever mix of owners and origins comes in.
        let owners = [
            Owner::User(UserId::random()),
            Owner::Space(kemlock_domain::SpaceId::random()),
        ];
        let _ = owner_condition(&owners);
        let since: VersionVector = [(ServerId::random(), 4), (ServerId::random(), 1)]
            .into_iter()
            .collect();
        let _ = uncovered_condition(&since);
        let _ = uncovered_condition(&VersionVector::new());
    }
}
