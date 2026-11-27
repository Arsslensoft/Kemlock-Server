//! `SpaceRepo` on the space tables, `items` and `item_collections`.
//!
//! Every write is one transaction on the writer. `SpaceChanges` are applied removals first, then
//! upserts; an upsert is a delete and an insert of the same key inside the transaction, which every
//! backend does the same way. A space item is written with `items`' own transaction body
//! (`write_in`), so its change id, sequence number and optimistic revision check are exactly an
//! ordinary item's, and its collection is recorded in the same transaction.

use super::items::{release_written, write_in};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::items as item_rows;
use crate::tables::space_chain::held;
use crate::tables::space_recovery;
use crate::tables::space_tables::{
    collection_grants, collection_keys, collections, group_members, groups, item_collections,
    members, spaces,
};
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::{
    ExternalChangeMode, KeyReplacement, OWNER_REQUIRED, PendingExternal, SpaceChanges,
    SpaceItemInfo, SpaceRepo,
};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, Grantee, Group, GroupId, KeyCopy, Member,
    MemberState, Space, SpaceRole, SpaceState,
};
use kemlock_domain::{Item, ItemDraft, ItemId, Owner, SpaceId, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::{Expr, Query};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionTrait,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

impl SpaceRepo for SqlStore {
    async fn load(&self, id: SpaceId) -> Result<Option<SpaceState>, StoreError> {
        let db = self.reader();
        let Some(space) = spaces::Entity::find_by_id(id.0).one(db).await.store()? else {
            return Ok(None);
        };
        let members = members::Entity::find()
            .filter(members::Column::SpaceId.eq(id.0))
            .order_by_asc(members::Column::InvitedAt)
            .order_by_asc(members::Column::UserId)
            .all(db)
            .await
            .store()?
            .into_iter()
            .map(members::Model::into_domain)
            .collect::<Result<Vec<Member>, StoreError>>()?;

        let group_rows = groups::Entity::find()
            .filter(groups::Column::SpaceId.eq(id.0))
            .order_by_asc(groups::Column::CreatedAt)
            .order_by_asc(groups::Column::Id)
            .all(db)
            .await
            .store()?;
        let group_ids: Vec<Uuid> = group_rows.iter().map(|g| g.id).collect();
        let mut by_group: BTreeMap<Uuid, BTreeSet<UserId>> = BTreeMap::new();
        if !group_ids.is_empty() {
            let rows = group_members::Entity::find()
                .filter(group_members::Column::GroupId.is_in(group_ids))
                .all(db)
                .await
                .store()?;
            for row in rows {
                by_group
                    .entry(row.group_id)
                    .or_default()
                    .insert(UserId(row.user_id));
            }
        }
        let groups: Vec<Group> = group_rows
            .into_iter()
            .map(|g| {
                let members = by_group.remove(&g.id).unwrap_or_default();
                g.into_domain(members)
            })
            .collect();

        let collections = collections::Entity::find()
            .filter(collections::Column::SpaceId.eq(id.0))
            .order_by_asc(collections::Column::CreatedAt)
            .order_by_asc(collections::Column::Id)
            .all(db)
            .await
            .store()?
            .into_iter()
            .map(collections::Model::into_domain)
            .collect::<Result<Vec<Collection>, StoreError>>()?;
        let collection_ids: Vec<Uuid> = collections.iter().map(|c| c.id.0).collect();
        let grants = if collection_ids.is_empty() {
            Vec::new()
        } else {
            collection_grants::Entity::find()
                .filter(collection_grants::Column::CollectionId.is_in(collection_ids))
                .all(db)
                .await
                .store()?
                .into_iter()
                .map(collection_grants::Model::into_domain)
                .collect::<Result<Vec<CollectionGrant>, StoreError>>()?
        };

        Ok(Some(SpaceState {
            space: space.into_domain()?,
            members,
            groups,
            collections,
            grants,
        }))
    }

    async fn spaces_binding_here(&self, ids: &[SpaceId]) -> Result<Vec<SpaceId>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let (space_type, _) = crate::tables::items::owner_parts(Owner::Space(ids[0]));
        let foreign: BTreeSet<Uuid> = crate::tables::federation::vault_federation::Entity::find()
            .filter(crate::tables::federation::vault_federation::Column::OwnerType.eq(space_type))
            .filter(
                crate::tables::federation::vault_federation::Column::OwnerId
                    .is_in(ids.iter().map(|id| id.0).collect::<Vec<Uuid>>()),
            )
            .filter(crate::tables::federation::vault_federation::Column::Home.ne(self.origin().0))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| row.owner_id)
            .collect();
        Ok(ids
            .iter()
            .copied()
            .filter(|id| !foreign.contains(&id.0))
            .collect())
    }

    async fn memberships(&self, user: UserId) -> Result<Vec<Member>, StoreError> {
        members::Entity::find()
            .filter(members::Column::UserId.eq(user.0))
            .order_by_asc(members::Column::InvitedAt)
            .order_by_asc(members::Column::SpaceId)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(members::Model::into_domain)
            .collect()
    }

    async fn spaces(&self, ids: &[SpaceId]) -> Result<Vec<Space>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = ids.iter().map(|id| id.0).collect();
        spaces::Entity::find()
            .filter(spaces::Column::Id.is_in(ids))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(spaces::Model::into_domain)
            .collect()
    }

    async fn collection_space(&self, id: CollectionId) -> Result<Option<SpaceId>, StoreError> {
        Ok(collections::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .map(|row| SpaceId(row.space_id)))
    }

    async fn group_space(&self, id: GroupId) -> Result<Option<SpaceId>, StoreError> {
        Ok(groups::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .map(|row| SpaceId(row.space_id)))
    }

    async fn key_copies(&self, space: SpaceId, user: UserId) -> Result<Vec<KeyCopy>, StoreError> {
        let ids = collection_ids(self.reader(), space.0).await?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        collection_keys::Entity::find()
            .filter(collection_keys::Column::CollectionId.is_in(ids))
            .filter(collection_keys::Column::UserId.eq(user.0))
            .order_by_asc(collection_keys::Column::CollectionId)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(collection_keys::Model::into_domain)
            .collect()
    }

    async fn holders(&self, space: SpaceId) -> Result<Vec<(CollectionId, UserId)>, StoreError> {
        let ids = collection_ids(self.reader(), space.0).await?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = collection_keys::Entity::find()
            .filter(collection_keys::Column::CollectionId.is_in(ids))
            .all(self.reader())
            .await
            .store()?;
        Ok(rows
            .into_iter()
            .map(|row| (CollectionId(row.collection_id), UserId(row.user_id)))
            .collect())
    }

    async fn space_items(&self, space: SpaceId) -> Result<Vec<SpaceItemInfo>, StoreError> {
        let rows = item_rows::Entity::find()
            .filter(item_rows::Column::OwnerType.eq(i16::from(Owner::TYPE_SPACE)))
            .filter(item_rows::Column::OwnerId.eq(space.0))
            .all(self.reader())
            .await
            .store()?;
        let links: BTreeMap<Uuid, Uuid> = item_collections::Entity::find()
            .filter(item_collections::Column::SpaceId.eq(space.0))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| (row.item_id, row.collection_id))
            .collect();
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let item = row.into_domain()?;
            out.push(SpaceItemInfo {
                id: item.id,
                collection: links.get(&item.id.0).map(|c| CollectionId(*c)),
                format: item.format,
                key_version: item.key_version,
                revision: item.revision,
                deleted: item.is_tombstone(),
            });
        }
        Ok(out)
    }

    async fn item_collections(
        &self,
        items: &[ItemId],
    ) -> Result<Vec<(ItemId, CollectionId)>, StoreError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = items.iter().map(|id| id.0).collect();
        let rows = item_collections::Entity::find()
            .filter(item_collections::Column::ItemId.is_in(ids))
            .all(self.reader())
            .await
            .store()?;
        Ok(rows
            .into_iter()
            .map(|row| (ItemId(row.item_id), CollectionId(row.collection_id)))
            .collect())
    }

    async fn create(&self, changes: SpaceChanges) -> Result<(), StoreError> {
        self.write_changes(changes, true).await
    }

    /// Changes from every caller but a Kemlock chain append: on a space with a chain they are
    /// queued or refused instead of applied (see `external_apply`).
    async fn apply(&self, changes: SpaceChanges) -> Result<(), StoreError> {
        self.external_apply(changes, false).await
    }

    async fn put_item(
        &self,
        draft: ItemDraft,
        collection: CollectionId,
    ) -> Result<Item, StoreError> {
        let Owner::Space(space) = draft.owner else {
            return Err(StoreError::Backend(
                "a space item must be owned by a space".to_owned(),
            ));
        };
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let mut stored = write_in(&txn, self.origin(), vec![draft]).await?;
            let item = stored
                .pop()
                .ok_or_else(|| StoreError::Backend("a write returned no item".to_owned()))?;
            link_item(&txn, item.id, space, collection).await?;
            release_written(&txn, &item, Some(collection)).await?;
            Ok::<Item, StoreError>(item)
        }
        .await;
        finish(txn, outcome, "a failed space item write").await
    }

    /// Reads `space_policy_settings`, the table `PolicyRepo` keeps; a space has its policies in one
    /// place only.
    async fn require_sso_of(&self, ids: &[SpaceId]) -> Result<Vec<SpaceId>, StoreError> {
        self.spaces_requiring_sso(ids).await
    }

    /// Writes `space_policy_settings` and leaves the space's other policies as they are.
    async fn set_require_sso(&self, space: SpaceId, on: bool) -> Result<(), StoreError> {
        self.upsert_require_sso(space, on).await
    }

    async fn put_items(
        &self,
        writes: Vec<(ItemDraft, Option<CollectionId>)>,
    ) -> Result<Vec<Item>, StoreError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        let (drafts, collection_of): (Vec<ItemDraft>, Vec<Option<CollectionId>>) =
            writes.into_iter().unzip();
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            let stored = write_in(&txn, self.origin(), drafts).await?;
            for (item, collection) in stored.iter().zip(collection_of) {
                if let (Owner::Space(space), Some(collection)) = (item.owner, collection) {
                    link_item(&txn, item.id, space, collection).await?;
                    release_written(&txn, item, Some(collection)).await?;
                }
            }
            Ok::<Vec<Item>, StoreError>(stored)
        }
        .await;
        finish(txn, outcome, "a failed batch of items").await
    }

    async fn is_chained(&self, space: SpaceId) -> Result<bool, StoreError> {
        self.space_has_chain(space).await
    }

    async fn chain_confirmed_members(
        &self,
        space: SpaceId,
    ) -> Result<Option<BTreeSet<UserId>>, StoreError> {
        kemlock_app::spaces::chain_confirmed(self, space).await
    }

    async fn external_change_mode(&self) -> Result<ExternalChangeMode, StoreError> {
        self.read_external_mode().await
    }

    async fn queue_external(&self, change: PendingExternal) -> Result<(), StoreError> {
        self.write_pending(change).await
    }

    async fn hold_items(&self, space: SpaceId, items: &[ItemId]) -> Result<(), StoreError> {
        self.write_held(space, items).await
    }

    async fn held_items(&self, space: SpaceId) -> Result<Vec<ItemId>, StoreError> {
        self.read_held(space).await
    }

    async fn held_collections(
        &self,
        spaces: &[SpaceId],
    ) -> Result<Vec<(SpaceId, CollectionId)>, StoreError> {
        if spaces.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = spaces.iter().map(|space| space.0).collect();
        let held_ids = Query::select()
            .expr(Expr::col((held::Entity, held::Column::ItemId)))
            .from(held::Entity)
            .take();
        let rows: Vec<(Uuid, Uuid)> = item_collections::Entity::find()
            .select_only()
            .column(item_collections::Column::SpaceId)
            .column(item_collections::Column::CollectionId)
            .distinct()
            .filter(item_collections::Column::SpaceId.is_in(ids))
            .filter(item_collections::Column::ItemId.in_subquery(held_ids))
            .into_tuple()
            .all(self.reader())
            .await
            .store()?;
        Ok(rows
            .into_iter()
            .map(|(space, collection)| (SpaceId(space), CollectionId(collection)))
            .collect())
    }

    async fn replace_keys(&self, replacement: KeyReplacement) -> Result<Vec<Item>, StoreError> {
        let KeyReplacement { changes, writes } = replacement;
        let space = changes.space_id;
        let (drafts, collection_of): (Vec<ItemDraft>, Vec<CollectionId>) =
            writes.into_iter().unzip();
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            apply_in(&txn, changes, false).await?;
            if drafts.is_empty() {
                return Ok(Vec::new());
            }
            let stored = write_in(&txn, self.origin(), drafts).await?;
            for (item, collection) in stored.iter().zip(collection_of) {
                link_item(&txn, item.id, space, collection).await?;
            }
            Ok::<Vec<Item>, StoreError>(stored)
        }
        .await;
        finish(txn, outcome, "a failed key replacement").await
    }
}

impl SqlStore {
    /// As `write_changes` for a space that exists, but refuses (`OWNER_REQUIRED`) a change that
    /// leaves a space that had a confirmed owner with members but none of them a confirmed owner.
    /// A change that removes every member (an organization's deletion) leaves no space to manage
    /// and passes. The use cases check the state they read, and two owners removing each other at
    /// the same moment each pass; this checks the state written, in the same transaction. The owner
    /// gate makes such changes take turns on PostgreSQL and MySQL, whose writer pool has several
    /// connections and whose transactions would each still see the other's owner.
    pub(crate) async fn write_changes_keeping_owner(
        &self,
        changes: SpaceChanges,
    ) -> Result<(), StoreError> {
        let space = changes.space_id.0;
        let touches_members = !changes.members.is_empty() || !changes.members_removed.is_empty();
        let _gate = if touches_members {
            Some(self.owner_gate().await)
        } else {
            None
        };
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            // The gate orders the changes of this process; several servers on one PostgreSQL or
            // MySQL order them on the space row, which each transaction locks before it counts the
            // owners. SQLite has the one writer connection and no row locks.
            if touches_members && self.writer().get_database_backend() != DbBackend::Sqlite {
                spaces::Entity::find_by_id(space)
                    .lock_exclusive()
                    .one(&txn)
                    .await
                    .store()?;
            }
            let had_owner = touches_members && has_confirmed_owner(&txn, space).await?;
            apply_in(&txn, changes, false).await?;
            if had_owner
                && !has_confirmed_owner(&txn, space).await?
                && has_any_member(&txn, space).await?
            {
                return Err(StoreError::Backend(OWNER_REQUIRED.to_owned()));
            }
            Ok::<(), StoreError>(())
        }
        .await;
        finish(txn, outcome, "a failed space change").await
    }

    pub(crate) async fn write_changes(
        &self,
        changes: SpaceChanges,
        creating: bool,
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = apply_in(&txn, changes, creating).await;
        finish(txn, outcome, "a failed space change").await
    }
}

/// Commits when `outcome` is good, rolls back when it isn't, and hands `outcome` on.
pub(super) async fn finish<T>(
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

/// Whether the space has any member row.
async fn has_any_member<C: ConnectionTrait>(db: &C, space: Uuid) -> Result<bool, StoreError> {
    Ok(members::Entity::find()
        .filter(members::Column::SpaceId.eq(space))
        .one(db)
        .await
        .store()?
        .is_some())
}

/// Whether the space has a confirmed owner.
async fn has_confirmed_owner<C: ConnectionTrait>(db: &C, space: Uuid) -> Result<bool, StoreError> {
    Ok(members::Entity::find()
        .filter(members::Column::SpaceId.eq(space))
        .filter(members::Column::Role.eq(SpaceRole::Owner.as_str()))
        .filter(members::Column::State.eq(MemberState::Confirmed.as_str()))
        .one(db)
        .await
        .store()?
        .is_some())
}

/// The ids of a space's collections.
async fn collection_ids<C: ConnectionTrait>(db: &C, space: Uuid) -> Result<Vec<Uuid>, StoreError> {
    Ok(collections::Entity::find()
        .filter(collections::Column::SpaceId.eq(space))
        .all(db)
        .await
        .store()?
        .into_iter()
        .map(|c| c.id)
        .collect())
}

/// The ids of a space's groups.
async fn group_ids<C: ConnectionTrait>(db: &C, space: Uuid) -> Result<Vec<Uuid>, StoreError> {
    Ok(groups::Entity::find()
        .filter(groups::Column::SpaceId.eq(space))
        .all(db)
        .await
        .store()?
        .into_iter()
        .map(|g| g.id)
        .collect())
}

/// Records that `item` is in `collection`, replacing an earlier record.
pub(super) async fn link_item(
    txn: &DatabaseTransaction,
    item: ItemId,
    space: SpaceId,
    collection: CollectionId,
) -> Result<(), StoreError> {
    item_collections::Entity::delete_many()
        .filter(item_collections::Column::ItemId.eq(item.0))
        .exec(txn)
        .await
        .store()?;
    item_collections::Entity::insert(item_collections::ActiveModel {
        item_id: Set(item.0),
        space_id: Set(space.0),
        collection_id: Set(collection.0),
    })
    .exec(txn)
    .await
    .store()?;
    Ok(())
}

/// The body of a change transaction: removals first, then upserts.
pub(super) async fn apply_in(
    txn: &DatabaseTransaction,
    changes: SpaceChanges,
    creating: bool,
) -> Result<(), StoreError> {
    let space = changes.space_id.0;
    ensure_changes_are_here(txn, space, &changes).await?;

    // Removals.
    for user in &changes.members_removed {
        let in_space = collection_ids(txn, space).await?;
        delete_recovery_box(txn, space, user.0).await?;
        members::Entity::delete_many()
            .filter(members::Column::SpaceId.eq(space))
            .filter(members::Column::UserId.eq(user.0))
            .exec(txn)
            .await
            .store()?;
        if !in_space.is_empty() {
            collection_grants::Entity::delete_many()
                .filter(collection_grants::Column::CollectionId.is_in(in_space.clone()))
                .filter(
                    collection_grants::Column::GranteeType.eq(collection_grants::GRANTEE_MEMBER),
                )
                .filter(collection_grants::Column::GranteeId.eq(user.0))
                .exec(txn)
                .await
                .store()?;
            collection_keys::Entity::delete_many()
                .filter(collection_keys::Column::CollectionId.is_in(in_space))
                .filter(collection_keys::Column::UserId.eq(user.0))
                .exec(txn)
                .await
                .store()?;
        }
        let in_groups = group_ids(txn, space).await?;
        if !in_groups.is_empty() {
            group_members::Entity::delete_many()
                .filter(group_members::Column::GroupId.is_in(in_groups))
                .filter(group_members::Column::UserId.eq(user.0))
                .exec(txn)
                .await
                .store()?;
        }
    }
    for group in &changes.groups_removed {
        delete_group(txn, space, group.0).await?;
    }
    for collection in &changes.collections_removed {
        collection_grants::Entity::delete_many()
            .filter(collection_grants::Column::CollectionId.eq(collection.0))
            .exec(txn)
            .await
            .store()?;
        collection_keys::Entity::delete_many()
            .filter(collection_keys::Column::CollectionId.eq(collection.0))
            .exec(txn)
            .await
            .store()?;
        item_collections::Entity::delete_many()
            .filter(item_collections::Column::CollectionId.eq(collection.0))
            .exec(txn)
            .await
            .store()?;
        collections::Entity::delete_many()
            .filter(collections::Column::Id.eq(collection.0))
            .filter(collections::Column::SpaceId.eq(space))
            .exec(txn)
            .await
            .store()?;
    }
    for (collection, grantee) in &changes.grants_removed {
        delete_grant(txn, collection.0, *grantee).await?;
    }
    for (collection, user) in &changes.key_copies_removed {
        delete_key_copy(txn, collection.0, user.0).await?;
    }

    // Upserts.
    match &changes.space {
        Some(row) if creating => {
            spaces::Entity::insert(spaces::active(row))
                .exec(txn)
                .await
                .store()?;
        }
        Some(row) => {
            spaces::Entity::update_many()
                .set(spaces::ActiveModel {
                    id: NotSet,
                    ..spaces::active(row)
                })
                .filter(spaces::Column::Id.eq(row.id.0))
                .exec(txn)
                .await
                .store()?;
        }
        None if creating => {
            return Err(StoreError::Backend("a new space needs its row".to_owned()));
        }
        None => {}
    }
    for member in &changes.members {
        if member.state == MemberState::Revoked {
            delete_recovery_box(txn, member.space.0, member.user.0).await?;
        }
        members::Entity::delete_many()
            .filter(members::Column::SpaceId.eq(member.space.0))
            .filter(members::Column::UserId.eq(member.user.0))
            .exec(txn)
            .await
            .store()?;
        members::Entity::insert(members::active(member))
            .exec(txn)
            .await
            .store()?;
    }
    for group in &changes.groups {
        delete_group(txn, space, group.id.0).await?;
        groups::Entity::insert(groups::active(group))
            .exec(txn)
            .await
            .store()?;
        for user in &group.members {
            group_members::Entity::insert(group_members::ActiveModel {
                group_id: Set(group.id.0),
                user_id: Set(user.0),
            })
            .exec(txn)
            .await
            .store()?;
        }
    }
    for collection in &changes.collections {
        collections::Entity::delete_many()
            .filter(collections::Column::Id.eq(collection.id.0))
            .filter(collections::Column::SpaceId.eq(space))
            .exec(txn)
            .await
            .store()?;
        collections::Entity::insert(collections::active(collection))
            .exec(txn)
            .await
            .store()?;
    }
    for grant in &changes.grants {
        delete_grant(txn, grant.collection.0, grant.grantee).await?;
        collection_grants::Entity::insert(collection_grants::active(grant))
            .exec(txn)
            .await
            .store()?;
    }
    for copy in &changes.key_copies {
        delete_key_copy(txn, copy.collection.0, copy.user.0).await?;
        collection_keys::Entity::insert(collection_keys::active(copy))
            .exec(txn)
            .await
            .store()?;
    }
    Ok(())
}

/// Deletes a member's recovery box: it goes when they leave or are removed.
pub(super) async fn delete_recovery_box(
    txn: &DatabaseTransaction,
    space: Uuid,
    user: Uuid,
) -> Result<(), StoreError> {
    space_recovery::Entity::delete_many()
        .filter(space_recovery::Column::SpaceId.eq(space))
        .filter(space_recovery::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// Refuses (`Duplicate`) changes that name a collection or group of another space, or a row that
/// says it belongs to another space. Collection and group ids are chosen by clients and are
/// unique across spaces, and the tables have no foreign keys, so a delete or an upsert by id alone
/// would move or wipe the other space's row, its grants and its key copies.
async fn ensure_changes_are_here(
    txn: &DatabaseTransaction,
    space: Uuid,
    changes: &SpaceChanges,
) -> Result<(), StoreError> {
    let foreign_row = changes.space.as_ref().is_some_and(|s| s.id.0 != space)
        || changes.members.iter().any(|m| m.space.0 != space)
        || changes.groups.iter().any(|g| g.space.0 != space)
        || changes.collections.iter().any(|c| c.space.0 != space);
    if foreign_row {
        return Err(StoreError::Duplicate);
    }

    let mut collection_ids: Vec<Uuid> = Vec::new();
    collection_ids.extend(changes.collections.iter().map(|c| c.id.0));
    collection_ids.extend(changes.collections_removed.iter().map(|c| c.0));
    collection_ids.extend(changes.grants.iter().map(|g| g.collection.0));
    collection_ids.extend(changes.grants_removed.iter().map(|(c, _)| c.0));
    collection_ids.extend(changes.key_copies.iter().map(|k| k.collection.0));
    collection_ids.extend(changes.key_copies_removed.iter().map(|(c, _)| c.0));
    if !collection_ids.is_empty() {
        let foreign = collections::Entity::find()
            .filter(collections::Column::Id.is_in(collection_ids))
            .filter(collections::Column::SpaceId.ne(space))
            .one(txn)
            .await
            .store()?;
        if foreign.is_some() {
            return Err(StoreError::Duplicate);
        }
    }

    let mut group_ids: Vec<Uuid> = Vec::new();
    group_ids.extend(changes.groups.iter().map(|g| g.id.0));
    group_ids.extend(changes.groups_removed.iter().map(|g| g.0));
    let grantees = changes
        .grants
        .iter()
        .map(|g| g.grantee)
        .chain(changes.grants_removed.iter().map(|(_, grantee)| *grantee));
    for grantee in grantees {
        if let Grantee::Group(group) = grantee {
            group_ids.push(group.0);
        }
    }
    if !group_ids.is_empty() {
        let foreign = groups::Entity::find()
            .filter(groups::Column::Id.is_in(group_ids))
            .filter(groups::Column::SpaceId.ne(space))
            .one(txn)
            .await
            .store()?;
        if foreign.is_some() {
            return Err(StoreError::Duplicate);
        }
    }
    Ok(())
}

/// Deletes a group of `space`, its members and the grants made to it.
async fn delete_group(
    txn: &DatabaseTransaction,
    space: Uuid,
    group: Uuid,
) -> Result<(), StoreError> {
    group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(group))
        .exec(txn)
        .await
        .store()?;
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::GranteeType.eq(collection_grants::GRANTEE_GROUP))
        .filter(collection_grants::Column::GranteeId.eq(group))
        .exec(txn)
        .await
        .store()?;
    groups::Entity::delete_many()
        .filter(groups::Column::Id.eq(group))
        .filter(groups::Column::SpaceId.eq(space))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

async fn delete_grant(
    txn: &DatabaseTransaction,
    collection: Uuid,
    grantee: kemlock_domain::spaces::Grantee,
) -> Result<(), StoreError> {
    let (grantee_type, grantee_id) = collection_grants::grantee_parts(grantee);
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::CollectionId.eq(collection))
        .filter(collection_grants::Column::GranteeType.eq(grantee_type))
        .filter(collection_grants::Column::GranteeId.eq(grantee_id))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

async fn delete_key_copy(
    txn: &DatabaseTransaction,
    collection: Uuid,
    user: Uuid,
) -> Result<(), StoreError> {
    collection_keys::Entity::delete_many()
        .filter(collection_keys::Column::CollectionId.eq(collection))
        .filter(collection_keys::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}
