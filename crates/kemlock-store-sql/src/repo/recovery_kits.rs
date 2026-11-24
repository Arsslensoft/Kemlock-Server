//! `RecoveryKitRepo` on `recovery_kits`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::recovery_kits;
use kemlock_app::ports::StoreError;
use kemlock_app::recovery_kit::RecoveryKitRepo;
use kemlock_domain::{RecoveryKit, UserId};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

impl RecoveryKitRepo for SqlStore {
    async fn recovery_kit(&self, user: UserId) -> Result<Option<RecoveryKit>, StoreError> {
        recovery_kits::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map(recovery_kits::Model::into_domain)
            .transpose()
    }

    async fn insert_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> Result<bool, StoreError> {
        let inserted = recovery_kits::Entity::insert(recovery_kits::active(user, kit))
            .on_conflict(
                OnConflict::column(recovery_kits::Column::UserId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => Ok(true),
            // The account has a kit already: the conflict did nothing.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(false),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn replace_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> Result<bool, StoreError> {
        let updated = recovery_kits::Entity::update_many()
            .set(recovery_kits::active(user, kit))
            .filter(recovery_kits::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok(updated > 0)
    }

    async fn remove_recovery_kit(&self, user: UserId) -> Result<bool, StoreError> {
        let removed = recovery_kits::Entity::delete_many()
            .filter(recovery_kits::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok(removed > 0)
    }
}
