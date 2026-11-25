//! `ProfileRepo` on `sso_identities` and `email_changes`.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::email_changes;
use crate::tables::sso::identities;
use kemlock_app::ports::StoreError;
use kemlock_app::profile::ProfileRepo;
use kemlock_domain::{EmailChange, UserId};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

impl ProfileRepo for SqlStore {
    async fn has_sso_identity(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(identities::Entity::find()
            .filter(identities::Column::UserId.eq(user.0))
            .one(self.reader())
            .await
            .store()?
            .is_some())
    }

    /// An upsert on the account: a new ask replaces the one before, whose link stops working.
    async fn put_email_change(&self, change: &EmailChange) -> Result<(), StoreError> {
        let conflict = OnConflict::column(email_changes::Column::UserId)
            .update_columns([
                email_changes::Column::Email,
                email_changes::Column::TokenHash,
                email_changes::Column::OpaqueRecord,
                email_changes::Column::KdfMemoryKib,
                email_changes::Column::KdfIterations,
                email_changes::Column::KdfParallelism,
                email_changes::Column::KdfSalt,
                email_changes::Column::WrappedRootKey,
                email_changes::Column::RequestedAt,
                email_changes::Column::ExpiresAt,
            ])
            .to_owned();
        let written = email_changes::Entity::insert(email_changes::active(change))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match written {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn email_change_of(&self, user: UserId) -> Result<Option<EmailChange>, StoreError> {
        email_changes::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map(email_changes::Model::into_domain)
            .transpose()
    }

    /// Reads the change by its token's hash, then deletes that row on the hash and the account
    /// together: only the caller whose delete removed it gets the change, so a link opened twice
    /// at once works once.
    async fn take_email_change(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<EmailChange>, StoreError> {
        let Some(row) = email_changes::Entity::find()
            .filter(email_changes::Column::TokenHash.eq(token_hash.to_vec()))
            .one(self.writer())
            .await
            .store()?
        else {
            return Ok(None);
        };
        let removed = email_changes::Entity::delete_many()
            .filter(email_changes::Column::UserId.eq(row.user_id))
            .filter(email_changes::Column::TokenHash.eq(token_hash.to_vec()))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        if removed == 0 {
            return Ok(None);
        }
        row.into_domain().map(Some)
    }

    async fn remove_email_change(&self, user: UserId) -> Result<(), StoreError> {
        email_changes::Entity::delete_many()
            .filter(email_changes::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
