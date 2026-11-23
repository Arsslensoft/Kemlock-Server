//! What the admin console shows beyond the federation rows, on `SqlStore`: the vaults homed here
//! with their owner, member count and size, when a server last wrote to one, what is known of a
//! peer's descriptor, and the record of a peer's key mismatch.
//!
//! `FedAdminRepo` is implemented in `federation_wiring`; its new methods call the helpers here.

use crate::convert::utc;
use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::attachments::{self, READY};
use crate::tables::federation_insight::{
    mismatch_active, peer_mismatches, peer_security, security_active,
};
use crate::tables::federation_wiring::replicated_accounts;
use crate::tables::items::{self, owner_parts};
use crate::tables::space_tables::{members, spaces};
use crate::tables::users;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Owner, ServerId, SpaceId, UserId};
use kemlock_federation::insight::{MismatchRecord, PeerSecurityRecord, VaultInfo};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use uuid::Uuid;

/// The two columns an owner is made of, as the tables hold them.
type OwnerKey = (i16, Uuid);

fn bytes(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

impl SqlStore {
    /// The stored size of each owner's live items plus its ready attachments, in bytes; one owner
    /// when `only` is given.
    async fn vault_sizes(&self, only: Option<Owner>) -> Result<HashMap<OwnerKey, u64>, StoreError> {
        let db = self.reader();
        let mut sizes: HashMap<OwnerKey, u64> = HashMap::new();

        let mut items_query = items::Entity::find()
            .select_only()
            .column(items::Column::OwnerType)
            .column(items::Column::OwnerId)
            .expr_as(
                Expr::cust("CAST(COALESCE(SUM(LENGTH(ciphertext)), 0) AS BIGINT)"),
                "bytes",
            )
            .filter(items::Column::DeletedAt.is_null())
            .group_by(items::Column::OwnerType)
            .group_by(items::Column::OwnerId);
        let mut files_query = attachments::Entity::find()
            .select_only()
            .column(attachments::Column::OwnerType)
            .column(attachments::Column::OwnerId)
            .expr_as(
                Expr::cust("CAST(COALESCE(SUM(size), 0) AS BIGINT)"),
                "bytes",
            )
            .filter(attachments::Column::Status.eq(READY))
            .group_by(attachments::Column::OwnerType)
            .group_by(attachments::Column::OwnerId);
        if let Some(owner) = only {
            let (owner_type, owner_id) = owner_parts(owner);
            items_query = items_query
                .filter(items::Column::OwnerType.eq(owner_type))
                .filter(items::Column::OwnerId.eq(owner_id));
            files_query = files_query
                .filter(attachments::Column::OwnerType.eq(owner_type))
                .filter(attachments::Column::OwnerId.eq(owner_id));
        }
        let from_items = items_query
            .into_tuple::<(i16, Uuid, i64)>()
            .all(db)
            .await
            .store()?;
        let from_files = files_query
            .into_tuple::<(i16, Uuid, i64)>()
            .all(db)
            .await
            .store()?;
        for (owner_type, owner_id, n) in from_items.into_iter().chain(from_files) {
            let total = sizes.entry((owner_type, owner_id)).or_default();
            *total = total.saturating_add(bytes(n));
        }
        Ok(sizes)
    }

    /// Every account that is not a copy of another server's, and every space, with what the
    /// console lists of them. A space has no email and its name is ciphertext, so it carries
    /// neither.
    pub(super) async fn insight_local_vaults(&self) -> Result<Vec<VaultInfo>, StoreError> {
        let db = self.reader();
        let copies: HashSet<Uuid> = replicated_accounts::Entity::find()
            .select_only()
            .column(replicated_accounts::Column::UserId)
            .into_tuple::<Uuid>()
            .all(db)
            .await
            .store()?
            .into_iter()
            .collect();
        let accounts: Vec<(Uuid, String)> = users::Entity::find()
            .select_only()
            .column(users::Column::Id)
            .column(users::Column::Email)
            .order_by_asc(users::Column::Email)
            .into_tuple::<(Uuid, String)>()
            .all(db)
            .await
            .store()?;
        let space_ids: Vec<Uuid> = spaces::Entity::find()
            .select_only()
            .column(spaces::Column::Id)
            .order_by_asc(spaces::Column::CreatedAt)
            .order_by_asc(spaces::Column::Id)
            .into_tuple::<Uuid>()
            .all(db)
            .await
            .store()?;
        let member_counts: HashMap<Uuid, i64> = members::Entity::find()
            .select_only()
            .column(members::Column::SpaceId)
            .column_as(members::Column::UserId.count(), "n")
            .filter(members::Column::State.ne("revoked"))
            .group_by(members::Column::SpaceId)
            .into_tuple::<(Uuid, i64)>()
            .all(db)
            .await
            .store()?
            .into_iter()
            .collect();
        let sizes = self.vault_sizes(None).await?;
        let size_of = |owner: Owner| sizes.get(&owner_parts(owner)).copied().unwrap_or_default();

        let mut out = Vec::new();
        for (id, email) in accounts {
            if copies.contains(&id) {
                continue;
            }
            let vault = Owner::User(UserId(id));
            out.push(VaultInfo {
                vault,
                owner_email: Some(email),
                members: 1,
                size_bytes: size_of(vault),
            });
        }
        for id in space_ids {
            let vault = Owner::Space(SpaceId(id));
            out.push(VaultInfo {
                vault,
                owner_email: None,
                members: member_counts.get(&id).copied().map_or(0, bytes),
                size_bytes: size_of(vault),
            });
        }
        Ok(out)
    }

    /// The console's line for one vault, or `None` when this server holds no such account or
    /// space.
    pub(super) async fn insight_vault_info(
        &self,
        vault: Owner,
    ) -> Result<Option<VaultInfo>, StoreError> {
        let db = self.reader();
        let size = self
            .vault_sizes(Some(vault))
            .await?
            .get(&owner_parts(vault))
            .copied()
            .unwrap_or_default();
        match vault {
            Owner::User(user) => {
                let email = users::Entity::find_by_id(user.0)
                    .select_only()
                    .column(users::Column::Email)
                    .into_tuple::<String>()
                    .one(db)
                    .await
                    .store()?;
                Ok(email.map(|email| VaultInfo {
                    vault,
                    owner_email: Some(email),
                    members: 1,
                    size_bytes: size,
                }))
            }
            Owner::Space(space) => {
                let held = spaces::Entity::find_by_id(space.0)
                    .select_only()
                    .column(spaces::Column::Id)
                    .into_tuple::<Uuid>()
                    .one(db)
                    .await
                    .store()?
                    .is_some();
                if !held {
                    return Ok(None);
                }
                let count = members::Entity::find()
                    .filter(members::Column::SpaceId.eq(space.0))
                    .filter(members::Column::State.ne("revoked"))
                    .count(db)
                    .await
                    .store()?;
                Ok(Some(VaultInfo {
                    vault,
                    owner_email: None,
                    members: count,
                    size_bytes: size,
                }))
            }
        }
    }

    pub(super) async fn insight_newest_change(
        &self,
        vault: Owner,
        origin: ServerId,
    ) -> Result<Option<u64>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let newest = items::Entity::find()
            .select_only()
            .column(items::Column::UpdatedAt)
            .filter(items::Column::OwnerType.eq(owner_type))
            .filter(items::Column::OwnerId.eq(owner_id))
            .filter(items::Column::Origin.eq(origin.0))
            .order_by_desc(items::Column::UpdatedAt)
            .limit(1)
            .into_tuple::<OffsetDateTime>()
            .one(self.reader())
            .await
            .store()?;
        Ok(newest.and_then(|t| u64::try_from(utc(t).unix_timestamp()).ok()))
    }

    pub(super) async fn insight_put_security(
        &self,
        record: &PeerSecurityRecord,
    ) -> Result<(), StoreError> {
        let conflict = OnConflict::column(peer_security::Column::Peer)
            .update_columns([
                peer_security::Column::Descriptor,
                peer_security::Column::FetchedAt,
                peer_security::Column::KemKeyId,
                peer_security::Column::KemFirstSeen,
                peer_security::Column::Suite,
            ])
            .to_owned();
        match peer_security::Entity::insert(security_active(record)?)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    pub(super) async fn insight_security(
        &self,
        peer: ServerId,
    ) -> Result<Option<PeerSecurityRecord>, StoreError> {
        peer_security::Entity::find_by_id(peer.0)
            .one(self.reader())
            .await
            .store()?
            .map(peer_security::Model::into_domain)
            .transpose()
    }

    pub(super) async fn insight_put_mismatch(
        &self,
        record: &MismatchRecord,
    ) -> Result<(), StoreError> {
        let conflict = OnConflict::column(peer_mismatches::Column::Peer)
            .update_columns([
                peer_mismatches::Column::OfferedKey,
                peer_mismatches::Column::FirstAt,
                peer_mismatches::Column::LastAt,
                peer_mismatches::Column::Attempts,
                peer_mismatches::Column::Source,
                peer_mismatches::Column::KeptBlockingAt,
                peer_mismatches::Column::KeptBlockingBy,
            ])
            .to_owned();
        match peer_mismatches::Entity::insert(mismatch_active(record)?)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    pub(super) async fn insight_mismatch(
        &self,
        peer: ServerId,
    ) -> Result<Option<MismatchRecord>, StoreError> {
        peer_mismatches::Entity::find_by_id(peer.0)
            .one(self.reader())
            .await
            .store()?
            .map(peer_mismatches::Model::into_domain)
            .transpose()
    }

    /// Forgets what is kept of a peer's descriptor and mismatch: called when the peer is removed.
    pub(super) async fn insight_forget(&self, peer: ServerId) -> Result<(), StoreError> {
        peer_security::Entity::delete_by_id(peer.0)
            .exec(self.writer())
            .await
            .store()?;
        peer_mismatches::Entity::delete_by_id(peer.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
