//! The federation ports (`PeerRepo`, `VaultRepo`, `ReplicaStore`) on `SqlStore`.
//!
//! Replication state lives beside the items: `peers`, `vault_federation`, `peer_cursors`,
//! `peer_log_switches`, `home_records`, and per version `change_meta` (lineage and the origin's
//! signature) and `item_siblings` (versions held beside an item's head). A write that touches
//! versions (`apply`, `export_*`, `resolve_siblings`, `store_signature`) is one transaction on the
//! writer that starts by locking the `server_meta` row, as item writes do, so replication and
//! device writes queue instead of interleaving. It decides with `kemlock_federation::conflict`,
//! the same code the in-memory store uses.

use crate::convert::{corrupt, from_i64, to_i64};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::federation::{
    change_meta, home_records, item_siblings, peer_cursors, peer_log_switches, peers,
    vault_federation,
};
use crate::tables::federation_keys::{
    peer_key_history, peer_pending_addresses, peer_trusted_addresses,
};
use crate::tables::federation_wiring::federation_erasures;
use crate::tables::items::{self, owner_parts};
use crate::tables::{changes, server_meta};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Item, ItemId, Owner, Revision, ServerId, VersionVector};
use kemlock_federation::FedError;
use kemlock_federation::change::{ChangeRecord, MAX_LINEAGE};
use kemlock_federation::conflict::{self, Rank, Version};
use kemlock_federation::hashtree::{Leaf, leaf_digest};
use kemlock_federation::home::VaultFederation;
use kemlock_federation::ports::{
    ApplyOutcome, ExportPage, Exported, LogSwitches, Peer, PeerRepo, PeerState, ReplicaStore,
    StoredHomeRecord, VaultRepo,
};
use kemlock_federation::wire::{ChangeKey, pack_keys, unpack_keys};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, Condition, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn fed(e: FedError) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn key_of(origin: Uuid, seq: i64) -> Result<ChangeKey, StoreError> {
    Ok(ChangeKey {
        origin: ServerId(origin),
        seq: from_i64(seq, "sequence number")?,
    })
}

/// Commits when the work succeeded and rolls back when it didn't.
async fn finish<T>(
    txn: DatabaseTransaction,
    result: Result<T, StoreError>,
) -> Result<T, StoreError> {
    match result {
        Ok(value) => {
            txn.commit().await.store()?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback) = txn.rollback().await {
                tracing::warn!(%rollback, "rollback after a failed federation write failed");
            }
            Err(err)
        }
    }
}

/// Takes the `server_meta` row's lock by rewriting a column with its own value, as item writes do.
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

fn items_of(owner: Owner) -> Condition {
    let (owner_type, owner_id) = owner_parts(owner);
    Condition::all()
        .add(items::Column::OwnerType.eq(owner_type))
        .add(items::Column::OwnerId.eq(owner_id))
}

fn siblings_of(owner: Owner) -> Condition {
    let (owner_type, owner_id) = owner_parts(owner);
    Condition::all()
        .add(item_siblings::Column::OwnerType.eq(owner_type))
        .add(item_siblings::Column::OwnerId.eq(owner_id))
}

/// Head rows whose change `since` does not cover.
fn uncovered_items(since: &VersionVector) -> Condition {
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

/// Sibling rows whose change `since` does not cover.
fn uncovered_siblings(since: &VersionVector) -> Condition {
    let mut any = Condition::any();
    let mut known = Vec::new();
    for (origin, seen) in since.iter() {
        known.push(origin.0);
        any = any.add(
            Condition::all()
                .add(item_siblings::Column::Origin.eq(origin.0))
                .add(item_siblings::Column::Seq.gt(i64::try_from(seen).unwrap_or(i64::MAX))),
        );
    }
    any.add(item_siblings::Column::Origin.is_not_in(known))
}

/// The head of an item and its siblings.
async fn held_versions(
    txn: &DatabaseTransaction,
    id: ItemId,
) -> Result<(Option<Item>, Vec<Item>), StoreError> {
    let head = items::Entity::find_by_id(id.0)
        .one(txn)
        .await
        .store()?
        .map(items::Model::into_domain)
        .transpose()?;
    let siblings = item_siblings::Entity::find()
        .filter(item_siblings::Column::ItemId.eq(id.0))
        .all(txn)
        .await
        .store()?
        .into_iter()
        .map(item_siblings::Model::into_item)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((head, siblings))
}

fn keys_of(items: &[Item]) -> HashSet<ChangeKey> {
    items.iter().map(|i| ChangeKey::of(&i.change)).collect()
}

/// A change's stored lineage and signature.
async fn meta_of(
    txn: &DatabaseTransaction,
    key: ChangeKey,
) -> Result<Option<(Vec<ChangeKey>, Option<Vec<u8>>)>, StoreError> {
    let row = change_meta::Entity::find_by_id((key.origin.0, to_i64(key.seq, "sequence number")?))
        .one(txn)
        .await
        .store()?;
    row.map(|r| {
        unpack_keys(&r.lineage)
            .map(|l| (l, r.signature))
            .map_err(fed)
    })
    .transpose()
}

/// The lineage of a change this server accepted: every earlier change of the item in the log
/// except the versions currently held as siblings, nearest first.
async fn derive_lineage(
    txn: &DatabaseTransaction,
    item: &Item,
    siblings: &HashSet<ChangeKey>,
) -> Result<Vec<ChangeKey>, StoreError> {
    let own = ChangeKey::of(&item.change);
    let rows = changes::Entity::find()
        .filter(changes::Column::ItemId.eq(item.id.0))
        .filter(changes::Column::Hlc.lt(to_i64(item.change.hlc.0, "hlc")?))
        .order_by_desc(changes::Column::Hlc)
        .order_by_desc(changes::Column::Origin)
        .order_by_desc(changes::Column::Seq)
        .limit(u64::try_from(MAX_LINEAGE + siblings.len() + 1).unwrap_or(u64::MAX))
        .all(txn)
        .await
        .store()?;
    let mut lineage = Vec::new();
    for row in rows {
        let key = key_of(row.origin, row.seq)?;
        if key == own || siblings.contains(&key) {
            continue;
        }
        lineage.push(key);
        if lineage.len() == MAX_LINEAGE {
            break;
        }
    }
    Ok(lineage)
}

/// The lineage and signature of a version, fixing the lineage of a change this server accepted
/// the first time it is needed.
async fn ensure_meta(
    txn: &DatabaseTransaction,
    server: ServerId,
    item: &Item,
    siblings: &HashSet<ChangeKey>,
) -> Result<(Vec<ChangeKey>, Option<Vec<u8>>), StoreError> {
    let key = ChangeKey::of(&item.change);
    if let Some(meta) = meta_of(txn, key).await? {
        return Ok(meta);
    }
    if item.change.origin != server {
        return Ok((Vec::new(), None));
    }
    let lineage = derive_lineage(txn, item, siblings).await?;
    change_meta::Entity::insert(change_meta::ActiveModel {
        origin: Set(key.origin.0),
        seq: Set(to_i64(key.seq, "sequence number")?),
        lineage: Set(pack_keys(&lineage)),
        signature: Set(None),
    })
    .exec(txn)
    .await
    .store()?;
    Ok((lineage, None))
}

async fn export_in(
    txn: &DatabaseTransaction,
    server: ServerId,
    owner: Owner,
    since: &VersionVector,
    limit: u32,
) -> Result<ExportPage, StoreError> {
    lock_meta(txn).await?;
    let limit = limit.max(1);
    let page_len = usize::try_from(limit).unwrap_or(usize::MAX);

    let mut head_query = items::Entity::find().filter(items_of(owner));
    let mut sibling_query = item_siblings::Entity::find().filter(siblings_of(owner));
    if !since.is_empty() {
        head_query = head_query.filter(uncovered_items(since));
        sibling_query = sibling_query.filter(uncovered_siblings(since));
    }
    let heads = head_query
        .order_by_asc(items::Column::Origin)
        .order_by_asc(items::Column::Seq)
        .limit(u64::from(limit) + 1)
        .all(txn)
        .await
        .store()?;
    let siblings = sibling_query
        .order_by_asc(item_siblings::Column::Origin)
        .order_by_asc(item_siblings::Column::Seq)
        .limit(u64::from(limit) + 1)
        .all(txn)
        .await
        .store()?;

    let mut versions: Vec<Item> = Vec::with_capacity(heads.len() + siblings.len());
    for row in heads {
        versions.push(row.into_domain()?);
    }
    for row in siblings {
        versions.push(row.into_item()?);
    }
    // Each list is a prefix of its uncovered rows in (origin, seq) order, so the first `limit` of
    // the merged list is a prefix of all of them.
    versions.sort_by_key(|i| ChangeKey::of(&i.change));
    let more = versions.len() > page_len;
    versions.truncate(page_len);

    let mut next = since.clone();
    let mut entries = Vec::with_capacity(versions.len());
    for item in versions {
        next.observe(&item.change);
        let (_, siblings) = held_versions(txn, item.id).await?;
        let (lineage, signature) = ensure_meta(txn, server, &item, &keys_of(&siblings)).await?;
        entries.push(Exported {
            item,
            lineage,
            signature,
        });
    }
    Ok(ExportPage {
        entries,
        next,
        more,
    })
}

async fn export_items_in(
    txn: &DatabaseTransaction,
    server: ServerId,
    owner: Owner,
    ids: &[ItemId],
) -> Result<Vec<Exported>, StoreError> {
    lock_meta(txn).await?;
    let mut out = Vec::new();
    for id in ids {
        let (head, siblings) = held_versions(txn, *id).await?;
        let sibling_keys = keys_of(&siblings);
        for item in head.into_iter().chain(siblings) {
            if item.owner != owner {
                continue;
            }
            let (lineage, signature) = ensure_meta(txn, server, &item, &sibling_keys).await?;
            out.push(Exported {
                item,
                lineage,
                signature,
            });
        }
    }
    Ok(out)
}

async fn store_signature_in(
    txn: &DatabaseTransaction,
    key: ChangeKey,
    lineage: &[ChangeKey],
    signature: &[u8],
) -> Result<(), StoreError> {
    lock_meta(txn).await?;
    let seq = to_i64(key.seq, "sequence number")?;
    let row = change_meta::Entity::find_by_id((key.origin.0, seq))
        .one(txn)
        .await
        .store()?;
    match row {
        Some(row) if row.signature.is_none() => {
            change_meta::Entity::update_many()
                .col_expr(
                    change_meta::Column::Signature,
                    Expr::value(signature.to_vec()),
                )
                .filter(change_meta::Column::Origin.eq(key.origin.0))
                .filter(change_meta::Column::Seq.eq(seq))
                .exec(txn)
                .await
                .store()?;
        }
        Some(_) => {}
        None => {
            change_meta::Entity::insert(change_meta::ActiveModel {
                origin: Set(key.origin.0),
                seq: Set(seq),
                lineage: Set(pack_keys(lineage)),
                signature: Set(Some(signature.to_vec())),
            })
            .exec(txn)
            .await
            .store()?;
        }
    }
    Ok(())
}

async fn apply_in(
    txn: &DatabaseTransaction,
    server: ServerId,
    record: &ChangeRecord,
    signature: &[u8],
    rank: Rank,
) -> Result<ApplyOutcome, StoreError> {
    lock_meta(txn).await?;
    let key = record.key();
    let seq = to_i64(key.seq, "sequence number")?;
    // Every change is applied once: one that is in the log, held or since replaced, is done.
    if changes::Entity::find_by_id((key.origin.0, seq))
        .one(txn)
        .await
        .store()?
        .is_some()
    {
        return Ok(ApplyOutcome::Duplicate);
    }
    let incoming = record.to_item().map_err(fed)?;

    let (head, siblings) = held_versions(txn, record.item).await?;
    if head.as_ref().is_some_and(|h| h.owner != record.owner) {
        // The id belongs to another owner here: say it is taken, and nothing about that item.
        return Err(StoreError::Duplicate);
    }
    // An item keeps the format and the kind it was made with: a record that says otherwise (a `bw`
    // label on a `kem1` item, to slip past the writer checks) is refused, whoever signed it.
    if head
        .iter()
        .chain(siblings.iter())
        .any(|held| held.format != incoming.format || held.kind != incoming.kind)
    {
        return Ok(ApplyOutcome::Refused);
    }
    let sibling_keys = keys_of(&siblings);
    let mut held_items: Vec<Item> = head.iter().cloned().collect();
    held_items.extend(siblings);
    let mut held = Vec::with_capacity(held_items.len());
    for item in &held_items {
        // A local version's lineage is fixed before anything that could change it joins the log.
        let (lineage, _) = ensure_meta(txn, server, item, &sibling_keys).await?;
        held.push(Version {
            key: ChangeKey::of(&item.change),
            hlc: item.change.hlc,
            revision: item.revision,
            lineage,
        });
    }
    let held_head = head.as_ref().map(|h| ChangeKey::of(&h.change));
    let merge = conflict::merge_ranked(&held, held_head, &Version::of(record), rank);
    if merge.regressed {
        // A version replaces the head only at a higher revision (docs/federation.md, "Rollback").
        return Ok(ApplyOutcome::Refused);
    }
    if !merge.kept {
        return Ok(ApplyOutcome::Duplicate);
    }

    let mut by_key: HashMap<ChangeKey, Item> = held_items
        .into_iter()
        .map(|i| (ChangeKey::of(&i.change), i))
        .collect();
    by_key.insert(key, incoming.clone());
    let new_head = by_key.remove(&merge.head).ok_or_else(|| {
        StoreError::Backend("a merge named a version it was not given".to_owned())
    })?;
    let new_siblings: Vec<Item> = merge
        .siblings
        .iter()
        .filter_map(|k| by_key.remove(k))
        .collect();

    let head_row = items::active(&new_head)?;
    if head.is_some() {
        items::Entity::update_many()
            .set(items::ActiveModel {
                id: NotSet,
                ..head_row
            })
            .filter(items::Column::Id.eq(record.item.0))
            .exec(txn)
            .await
            .store()?;
    } else {
        items::Entity::insert(head_row).exec(txn).await.store()?;
    }
    item_siblings::Entity::delete_many()
        .filter(item_siblings::Column::ItemId.eq(record.item.0))
        .exec(txn)
        .await
        .store()?;
    for sibling in &new_siblings {
        item_siblings::Entity::insert(item_siblings::active(sibling)?)
            .exec(txn)
            .await
            .store()?;
    }
    changes::Entity::insert(changes::active(&incoming)?)
        .exec(txn)
        .await
        .store()?;
    change_meta::Entity::insert(change_meta::ActiveModel {
        origin: Set(key.origin.0),
        seq: Set(seq),
        lineage: Set(pack_keys(&record.lineage)),
        signature: Set(Some(signature.to_vec())),
    })
    .exec(txn)
    .await
    .store()?;
    if record.write.is_some() {
        // A signed write makes the owner signed-only here too (docs/crypto.md, "Signed item
        // writes").
        super::items::mark_signed_only(txn, record.owner, incoming.updated_at).await?;
    }

    // A later write here must carry an HLC time after the one just received.
    let meta = server_meta::Entity::find_by_id(server_meta::ROW_ID)
        .one(txn)
        .await
        .store()?
        .ok_or_else(|| StoreError::Backend("server_meta has no row".to_owned()))?;
    if record.change.hlc.0 > from_i64(meta.last_hlc, "hlc")? {
        server_meta::Entity::update_many()
            .col_expr(
                server_meta::Column::LastHlc,
                Expr::value(to_i64(record.change.hlc.0, "hlc")?),
            )
            .filter(server_meta::Column::Id.eq(server_meta::ROW_ID))
            .exec(txn)
            .await
            .store()?;
    }
    Ok(if merge.head == key {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Sibling
    })
}

async fn resolve_in(
    txn: &DatabaseTransaction,
    server: ServerId,
    owner: Owner,
    id: ItemId,
) -> Result<u64, StoreError> {
    lock_meta(txn).await?;
    let (head, siblings) = held_versions(txn, id).await?;
    let Some(head) = head else {
        return Ok(0);
    };
    if head.owner != owner || siblings.is_empty() {
        return Ok(0);
    }
    let sibling_keys = keys_of(&siblings);
    let (lineage, signature) = ensure_meta(txn, server, &head, &sibling_keys).await?;
    if signature.is_some() {
        return Err(StoreError::Backend(
            "the head was already sent to a peer, so it can no longer replace its siblings"
                .to_owned(),
        ));
    }
    // The siblings go to the front of the lineage, latest first.
    let mut ordered = siblings.clone();
    ordered.sort_by_key(|i| std::cmp::Reverse((i.change.hlc, ChangeKey::of(&i.change))));
    let mut combined: Vec<ChangeKey> = ordered.iter().map(|i| ChangeKey::of(&i.change)).collect();
    for key in lineage {
        if !combined.contains(&key) {
            combined.push(key);
        }
    }
    combined.truncate(MAX_LINEAGE);
    let head_key = ChangeKey::of(&head.change);
    change_meta::Entity::update_many()
        .col_expr(
            change_meta::Column::Lineage,
            Expr::value(pack_keys(&combined)),
        )
        .filter(change_meta::Column::Origin.eq(head_key.origin.0))
        .filter(change_meta::Column::Seq.eq(to_i64(head_key.seq, "sequence number")?))
        .exec(txn)
        .await
        .store()?;
    item_siblings::Entity::delete_many()
        .filter(item_siblings::Column::ItemId.eq(id.0))
        .exec(txn)
        .await
        .store()?;
    Ok(siblings.len() as u64)
}

impl ReplicaStore for SqlStore {
    fn server_id(&self) -> ServerId {
        self.origin()
    }

    async fn export_since(
        &self,
        owner: Owner,
        since: &VersionVector,
        limit: u32,
    ) -> Result<ExportPage, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let result = export_in(&txn, self.origin(), owner, since, limit).await;
        finish(txn, result).await
    }

    async fn export_items(
        &self,
        owner: Owner,
        items: &[ItemId],
    ) -> Result<Vec<Exported>, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let result = export_items_in(&txn, self.origin(), owner, items).await;
        finish(txn, result).await
    }

    async fn store_signature(
        &self,
        key: ChangeKey,
        lineage: &[ChangeKey],
        signature: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let result = store_signature_in(&txn, key, lineage, signature).await;
        finish(txn, result).await
    }

    async fn apply_ranked(
        &self,
        record: &ChangeRecord,
        signature: &[u8],
        rank: Rank,
    ) -> Result<ApplyOutcome, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let result = apply_in(&txn, self.origin(), record, signature, rank).await;
        finish(txn, result).await
    }

    async fn holds_change(&self, key: ChangeKey) -> Result<bool, StoreError> {
        Ok(changes::Entity::find_by_id((
            key.origin.0,
            to_i64(key.seq, "sequence number")?,
        ))
        .one(self.reader())
        .await
        .store()?
        .is_some())
    }

    async fn owner_signed_only(&self, owner: Owner) -> Result<bool, StoreError> {
        kemlock_app::ports::ItemStore::signed_writes_required(self, owner).await
    }

    async fn leaves(&self, owner: Owner) -> Result<Vec<Leaf>, StoreError> {
        let heads: Vec<(Uuid, Uuid, i64, i64)> = items::Entity::find()
            .select_only()
            .column(items::Column::Id)
            .column(items::Column::Origin)
            .column(items::Column::Seq)
            .column(items::Column::Revision)
            .filter(items_of(owner))
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let siblings: Vec<(Uuid, Uuid, i64, i64)> = item_siblings::Entity::find()
            .select_only()
            .column(item_siblings::Column::ItemId)
            .column(item_siblings::Column::Origin)
            .column(item_siblings::Column::Seq)
            .column(item_siblings::Column::Revision)
            .filter(siblings_of(owner))
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let mut by_item: HashMap<Uuid, Vec<(ChangeKey, Revision)>> = HashMap::new();
        for (id, origin, seq, revision) in heads.into_iter().chain(siblings) {
            by_item.entry(id).or_default().push((
                key_of(origin, seq)?,
                Revision(from_i64(revision, "revision")?),
            ));
        }
        let mut leaves: Vec<Leaf> = by_item
            .into_iter()
            .map(|(id, versions)| {
                let item = ItemId(id);
                Leaf {
                    item,
                    digest: leaf_digest(item, &versions),
                }
            })
            .collect();
        leaves.sort_by_key(|l| l.item);
        Ok(leaves)
    }

    async fn latest(&self, owner: Owner) -> Result<VersionVector, StoreError> {
        let heads: Vec<(Uuid, i64)> = items::Entity::find()
            .select_only()
            .column(items::Column::Origin)
            .column_as(items::Column::Seq.max(), "max_seq")
            .filter(items_of(owner))
            .group_by(items::Column::Origin)
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let siblings: Vec<(Uuid, i64)> = item_siblings::Entity::find()
            .select_only()
            .column(item_siblings::Column::Origin)
            .column_as(item_siblings::Column::Seq.max(), "max_seq")
            .filter(siblings_of(owner))
            .group_by(item_siblings::Column::Origin)
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        let mut vector = VersionVector::new();
        for (origin, seq) in heads.into_iter().chain(siblings) {
            let key = key_of(origin, seq)?;
            vector.merge(&std::iter::once((key.origin, key.seq)).collect());
        }
        Ok(vector)
    }

    async fn siblings(&self, owner: Owner, item: ItemId) -> Result<Vec<Item>, StoreError> {
        item_siblings::Entity::find()
            .filter(item_siblings::Column::ItemId.eq(item.0))
            .filter(siblings_of(owner))
            .order_by_asc(item_siblings::Column::Origin)
            .order_by_asc(item_siblings::Column::Seq)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(item_siblings::Model::into_item)
            .collect()
    }

    async fn resolve_siblings(&self, owner: Owner, item: ItemId) -> Result<u64, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let result = resolve_in(&txn, self.origin(), owner, item).await;
        finish(txn, result).await
    }
}

impl PeerRepo for SqlStore {
    async fn insert_peer(&self, peer: &Peer) -> Result<(), StoreError> {
        peers::Entity::insert(peers::active(peer)?)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn get_peer(&self, id: ServerId) -> Result<Option<Peer>, StoreError> {
        peers::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(peers::Model::into_domain)
            .transpose()
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StoreError> {
        peers::Entity::find()
            .order_by_asc(peers::Column::PairedAt)
            .order_by_asc(peers::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(peers::Model::into_domain)
            .collect()
    }

    async fn set_peer_state(&self, id: ServerId, state: PeerState) -> Result<(), StoreError> {
        let done = peers::Entity::update_many()
            .col_expr(peers::Column::State, Expr::value(state.as_str().to_owned()))
            .filter(peers::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if done.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn touch_peer(&self, id: ServerId, at: u64) -> Result<(), StoreError> {
        let done = peers::Entity::update_many()
            .col_expr(
                peers::Column::LastSeen,
                Expr::value(to_i64(at, "last_seen")?),
            )
            .filter(peers::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if done.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn remove_peer(&self, id: ServerId) -> Result<bool, StoreError> {
        // What the peer was still to be told has no one to tell it.
        federation_erasures::Entity::delete_many()
            .filter(federation_erasures::Column::Peer.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        peer_cursors::Entity::delete_many()
            .filter(peer_cursors::Column::Peer.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        self.insight_forget(id).await?;
        peer_key_history::Entity::delete_many()
            .filter(peer_key_history::Column::Peer.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        peer_pending_addresses::Entity::delete_many()
            .filter(peer_pending_addresses::Column::Peer.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        peer_trusted_addresses::Entity::delete_many()
            .filter(peer_trusted_addresses::Column::Peer.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        peer_log_switches::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        let done = peers::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(done.rows_affected > 0)
    }

    async fn log_switches(&self, id: ServerId) -> Result<LogSwitches, StoreError> {
        Ok(peer_log_switches::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(|row| LogSwitches {
                send: row.send,
                pull: row.pull,
            })
            .unwrap_or_default())
    }

    async fn set_log_switches(
        &self,
        id: ServerId,
        switches: LogSwitches,
    ) -> Result<(), StoreError> {
        let exists = peer_log_switches::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if exists {
            peer_log_switches::Entity::update_many()
                .col_expr(peer_log_switches::Column::Send, Expr::value(switches.send))
                .col_expr(peer_log_switches::Column::Pull, Expr::value(switches.pull))
                .filter(peer_log_switches::Column::Peer.eq(id.0))
                .exec(self.writer())
                .await
                .store()?;
        } else {
            peer_log_switches::Entity::insert(peer_log_switches::ActiveModel {
                peer: Set(id.0),
                send: Set(switches.send),
                pull: Set(switches.pull),
            })
            .exec(self.writer())
            .await
            .store()?;
        }
        Ok(())
    }
}

impl VaultRepo for SqlStore {
    async fn get_vault(&self, owner: Owner) -> Result<Option<VaultFederation>, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        vault_federation::Entity::find_by_id((owner_type, owner_id))
            .one(self.reader())
            .await
            .store()?
            .map(vault_federation::Model::into_domain)
            .transpose()
    }

    async fn put_vault(&self, vault: &VaultFederation) -> Result<(), StoreError> {
        let row = vault_federation::active(vault)?;
        let (owner_type, owner_id) = owner_parts(vault.owner);
        let exists = vault_federation::Entity::find_by_id((owner_type, owner_id))
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if exists {
            vault_federation::Entity::update_many()
                .set(vault_federation::ActiveModel {
                    owner_type: NotSet,
                    owner_id: NotSet,
                    ..row
                })
                .filter(vault_federation::Column::OwnerType.eq(owner_type))
                .filter(vault_federation::Column::OwnerId.eq(owner_id))
                .exec(self.writer())
                .await
                .store()?;
        } else {
            vault_federation::Entity::insert(row)
                .exec(self.writer())
                .await
                .store()?;
        }
        Ok(())
    }

    async fn list_vaults(&self) -> Result<Vec<VaultFederation>, StoreError> {
        vault_federation::Entity::find()
            .order_by_asc(vault_federation::Column::OwnerType)
            .order_by_asc(vault_federation::Column::OwnerId)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(vault_federation::Model::into_domain)
            .collect()
    }

    async fn peer_cursor(&self, peer: ServerId, vault: Owner) -> Result<VersionVector, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        match peer_cursors::Entity::find_by_id((peer.0, owner_type, owner_id))
            .one(self.reader())
            .await
            .store()?
        {
            Some(row) => VersionVector::from_cursor_bytes(&row.cursor_bytes)
                .map_err(|_| corrupt("peer cursor")),
            None => Ok(VersionVector::new()),
        }
    }

    async fn set_peer_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
        cursor: &VersionVector,
    ) -> Result<(), StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let bytes = cursor.to_cursor_bytes();
        let exists = peer_cursors::Entity::find_by_id((peer.0, owner_type, owner_id))
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if exists {
            peer_cursors::Entity::update_many()
                .col_expr(peer_cursors::Column::CursorBytes, Expr::value(bytes))
                .filter(peer_cursors::Column::Peer.eq(peer.0))
                .filter(peer_cursors::Column::OwnerType.eq(owner_type))
                .filter(peer_cursors::Column::OwnerId.eq(owner_id))
                .exec(self.writer())
                .await
                .store()?;
        } else {
            peer_cursors::Entity::insert(peer_cursors::ActiveModel {
                peer: Set(peer.0),
                owner_type: Set(owner_type),
                owner_id: Set(owner_id),
                cursor_bytes: Set(bytes),
            })
            .exec(self.writer())
            .await
            .store()?;
        }
        Ok(())
    }

    async fn put_home_record(&self, stored: &StoredHomeRecord) -> Result<bool, StoreError> {
        let (owner_type, owner_id) = owner_parts(stored.record.vault);
        let idx = to_i64(stored.record.index, "home record index")?;
        let exists = home_records::Entity::find_by_id((owner_type, owner_id, idx))
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if exists {
            return Ok(false);
        }
        home_records::Entity::insert(home_records::active(stored)?)
            .exec(self.writer())
            .await
            .store()?;
        Ok(true)
    }

    async fn home_records(
        &self,
        vault: Owner,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredHomeRecord>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        home_records::Entity::find()
            .filter(home_records::Column::OwnerType.eq(owner_type))
            .filter(home_records::Column::OwnerId.eq(owner_id))
            .filter(home_records::Column::Idx.gt(i64::try_from(after).unwrap_or(i64::MAX)))
            .order_by_asc(home_records::Column::Idx)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(home_records::Model::into_domain)
            .collect()
    }

    async fn quarantined(&self, vault: Owner) -> Result<Vec<StoredHomeRecord>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        home_records::Entity::find()
            .filter(home_records::Column::OwnerType.eq(owner_type))
            .filter(home_records::Column::OwnerId.eq(owner_id))
            .filter(home_records::Column::Status.eq("quarantined"))
            .order_by_asc(home_records::Column::Idx)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(home_records::Model::into_domain)
            .collect()
    }
}
