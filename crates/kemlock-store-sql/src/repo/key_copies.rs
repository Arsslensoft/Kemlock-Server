//! `KeyCopyRepo` on `device_key_copies`.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::device_key_copies;
use kemlock_app::devices::KeyCopyRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::DeviceId;
use kemlock_domain::unlock::DeviceKeyCopy;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

impl KeyCopyRepo for SqlStore {
    async fn key_copy(&self, device: DeviceId) -> Result<Option<DeviceKeyCopy>, StoreError> {
        device_key_copies::Entity::find_by_id(device.0)
            .one(self.reader())
            .await
            .store()?
            .map(device_key_copies::Model::into_domain)
            .transpose()
    }

    /// An upsert that keeps the first `created_at`. A device that doesn't exist is `NotFound`
    /// (the foreign key refuses the row).
    async fn put_key_copy(&self, copy: &DeviceKeyCopy) -> Result<(), StoreError> {
        let conflict = OnConflict::column(device_key_copies::Column::DeviceId)
            .update_columns([
                device_key_copies::Column::WrappedKey,
                device_key_copies::Column::Protection,
                device_key_copies::Column::UpdatedAt,
            ])
            .to_owned();
        let inserted = device_key_copies::Entity::insert(device_key_copies::active(copy))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn remove_key_copy(&self, device: DeviceId) -> Result<(), StoreError> {
        device_key_copies::Entity::delete_many()
            .filter(device_key_copies::Column::DeviceId.eq(device.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
