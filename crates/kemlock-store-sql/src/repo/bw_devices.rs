//! `BwDeviceRepo` on `bw_devices`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::bw_devices::{self, Column};
use kemlock_app::bw_events::{BwDevice, BwDeviceRepo, BwPushToken};
use kemlock_app::ports::StoreError;
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

impl BwDeviceRepo for SqlStore {
    async fn note_bw_device(
        &self,
        device: DeviceId,
        user: UserId,
        identifier: Uuid,
        device_type: i32,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        // A device already known keeps its push columns: they are not in the update list.
        let conflict = OnConflict::column(Column::DeviceId)
            .update_columns([
                Column::UserId,
                Column::Identifier,
                Column::DeviceType,
                Column::UpdatedAt,
            ])
            .to_owned();
        // A device that does not exist is `NotFound` (the foreign key refuses the row).
        match bw_devices::Entity::insert(bw_devices::noted(
            device,
            user,
            identifier,
            device_type,
            at,
        ))
        .on_conflict(conflict)
        .exec(self.writer())
        .await
        {
            // MySQL counts a replaced row with identical values as zero rows affected.
            Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn bw_device(&self, device: DeviceId) -> Result<Option<BwDevice>, StoreError> {
        Ok(bw_devices::Entity::find_by_id(device.0)
            .one(self.reader())
            .await
            .store()?
            .map(bw_devices::Model::into_domain))
    }

    async fn bw_devices_by_identifier(
        &self,
        identifier: Uuid,
    ) -> Result<Vec<BwDevice>, StoreError> {
        Ok(bw_devices::Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(bw_devices::Model::into_domain)
            .collect())
    }

    async fn set_bw_push(
        &self,
        device: DeviceId,
        push: Option<BwPushToken>,
    ) -> Result<(), StoreError> {
        let (push_uuid, push_token) = match push {
            Some(p) => (Some(p.push_uuid), Some(p.token)),
            None => (None, None),
        };
        let updated = bw_devices::Entity::update_many()
            .set(bw_devices::ActiveModel {
                push_uuid: Set(push_uuid),
                push_token: Set(push_token),
                ..Default::default()
            })
            .filter(Column::DeviceId.eq(device.0))
            .exec(self.writer())
            .await
            .store()?;
        // MySQL counts a row set to the values it had as zero rows affected.
        if updated.rows_affected == 0 && self.bw_device(device).await?.is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn bw_user_has_push(&self, user: UserId) -> Result<bool, StoreError> {
        let phones = bw_devices::Entity::find()
            .filter(Column::UserId.eq(user.0))
            .filter(Column::PushToken.is_not_null())
            .count(self.reader())
            .await
            .store()?;
        Ok(phones > 0)
    }
}
