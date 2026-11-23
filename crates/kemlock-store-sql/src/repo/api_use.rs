//! `ApiUseRepo` on `device_api_use`.

use crate::convert::utc;
use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::device_api_use::{self, Column};
use kemlock_app::api_use::{ApiUseRepo, USE_GRANULARITY};
use kemlock_app::ports::StoreError;
use kemlock_domain::DeviceId;
use kemlock_domain::api_use::{ApiKind, DeviceApiUse};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

impl ApiUseRepo for SqlStore {
    /// First `UPDATE … SET <column> = ? WHERE device_id = ? AND (<column> IS NULL OR <column> < ?)`,
    /// which is all an authenticated request costs once a minute has passed. When it changes
    /// nothing, either the device has no row yet or its column is recent: an insert that does
    /// nothing on conflict covers the first and leaves the second alone.
    async fn record_use(
        &self,
        device: DeviceId,
        api: ApiKind,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let at = utc(at);
        let (column, mut row) = match api {
            ApiKind::Kemlock => (
                Column::KemlockUsedAt,
                device_api_use::ActiveModel {
                    device_id: NotSet,
                    kemlock_used_at: Set(Some(at)),
                    bitwarden_used_at: NotSet,
                },
            ),
            ApiKind::Bitwarden => (
                Column::BitwardenUsedAt,
                device_api_use::ActiveModel {
                    device_id: NotSet,
                    kemlock_used_at: NotSet,
                    bitwarden_used_at: Set(Some(at)),
                },
            ),
        };
        let moved = device_api_use::Entity::update_many()
            .set(row.clone())
            .filter(Column::DeviceId.eq(device.0))
            .filter(
                Condition::any()
                    .add(column.is_null())
                    .add(column.lt(at - USE_GRANULARITY)),
            )
            .exec(self.writer())
            .await
            .store()?;
        if moved.rows_affected > 0 {
            return Ok(());
        }
        row.device_id = Set(device.0);
        let inserted = device_api_use::Entity::insert(row)
            .on_conflict(OnConflict::column(Column::DeviceId).do_nothing().to_owned())
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => Ok(()),
            // The row was there already (the conflict did nothing); MySQL and SQLite report it so.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            // A device that is gone: the foreign key refuses the row.
            Err(err) => Err(map_db(err)),
        }
    }

    async fn uses_of(&self, devices: &[DeviceId]) -> Result<Vec<DeviceApiUse>, StoreError> {
        if devices.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = devices.iter().map(|d| d.0).collect();
        Ok(device_api_use::Entity::find()
            .filter(Column::DeviceId.is_in(ids))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(device_api_use::Model::into_domain)
            .collect())
    }
}
