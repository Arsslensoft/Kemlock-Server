//! `SpaceRecoveryRepo` on `space_recovery_boxes`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::owner_lock::begin_locked;
use crate::store::SqlStore;
use crate::tables::space_recovery;
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::{RecoveryBox, SpaceRecoveryRepo};
use kemlock_domain::{SpaceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use time::OffsetDateTime;

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Backend("a recovery box's key seq is too large".to_owned()))
}

fn bad(what: &str) -> StoreError {
    StoreError::Backend(format!("a stored recovery box is malformed: {what}"))
}

impl SpaceRecoveryRepo for SqlStore {
    async fn recovery_box(
        &self,
        space: SpaceId,
        user: UserId,
    ) -> Result<Option<RecoveryBox>, StoreError> {
        let Some(row) = space_recovery::Entity::find_by_id((space.0, user.0))
            .one(self.reader())
            .await
            .store()?
        else {
            return Ok(None);
        };
        Ok(Some(RecoveryBox {
            space,
            user,
            key_seq: u64::try_from(row.key_seq).map_err(|_| bad("key seq"))?,
            sealed: row.sealed,
            enrolled_at: OffsetDateTime::from_unix_timestamp(row.enrolled_at)
                .map_err(|_| bad("time"))?,
        }))
    }

    /// Delete then insert in one transaction: a replacement leaves exactly one row.
    async fn put_recovery_box(&self, recovery: RecoveryBox) -> Result<(), StoreError> {
        let key_seq = to_i64(recovery.key_seq)?;
        // The box is a wrap of the member's root key: written under the member's lock.
        let txn = begin_locked(self, recovery.user).await?;
        space_recovery::Entity::delete_many()
            .filter(space_recovery::Column::SpaceId.eq(recovery.space.0))
            .filter(space_recovery::Column::UserId.eq(recovery.user.0))
            .exec(&txn)
            .await
            .store()?;
        space_recovery::Entity::insert(space_recovery::ActiveModel {
            space_id: Set(recovery.space.0),
            user_id: Set(recovery.user.0),
            key_seq: Set(key_seq),
            sealed: Set(recovery.sealed),
            enrolled_at: Set(utc(recovery.enrolled_at).unix_timestamp()),
        })
        .exec(&txn)
        .await
        .store()?;
        txn.commit().await.store()?;
        Ok(())
    }

    async fn delete_recovery_box(&self, space: SpaceId, user: UserId) -> Result<bool, StoreError> {
        let result = space_recovery::Entity::delete_many()
            .filter(space_recovery::Column::SpaceId.eq(space.0))
            .filter(space_recovery::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected > 0)
    }
}
