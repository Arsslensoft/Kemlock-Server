//! `DeviceRepo` on `devices`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{devices, refresh_tokens};
use kemlock_app::ports::{DeviceRepo, StoreError};
use kemlock_domain::{Device, DeviceId, UserId};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait};
use time::OffsetDateTime;

impl DeviceRepo for SqlStore {
    async fn get(&self, id: DeviceId) -> Result<Option<Device>, StoreError> {
        devices::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(devices::Model::into_domain)
            .transpose()
    }

    async fn upsert(&self, device: &Device) -> Result<(), StoreError> {
        let conflict = OnConflict::column(devices::Column::Id)
            .update_columns([
                devices::Column::UserId,
                devices::Column::Name,
                devices::Column::Kind,
                devices::Column::DpopJkt,
                devices::Column::CreatedAt,
                devices::Column::LastSeenAt,
            ])
            .to_owned();
        let inserted = devices::Entity::insert(devices::active(device))
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

    async fn touch_seen(
        &self,
        id: DeviceId,
        jkt: &str,
        at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        // One statement that names the key, so a key cleared a moment ago is not put back.
        let updated = devices::Entity::update_many()
            .col_expr(devices::Column::LastSeenAt, Expr::value(utc(at)))
            .filter(devices::Column::Id.eq(id.0))
            .filter(devices::Column::DpopJkt.eq(jkt))
            .exec(self.writer())
            .await
            .store()?;
        if updated.rows_affected == 1 {
            return Ok(true);
        }
        // MySQL counts a row written with the value it had as not affected.
        Ok(devices::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .is_some_and(|row| row.dpop_jkt.as_deref() == Some(jkt)))
    }

    async fn touch_last_seen(&self, id: DeviceId, at: OffsetDateTime) -> Result<(), StoreError> {
        devices::Entity::update_many()
            .col_expr(devices::Column::LastSeenAt, Expr::value(utc(at)))
            .filter(devices::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn list(&self, user: UserId) -> Result<Vec<Device>, StoreError> {
        devices::Entity::find()
            .filter(devices::Column::UserId.eq(user.0))
            .order_by_asc(devices::Column::CreatedAt)
            .order_by_asc(devices::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(devices::Model::into_domain)
            .collect()
    }

    async fn remove(&self, id: DeviceId) -> Result<(), StoreError> {
        // The foreign key cascades too; deleting the tokens first keeps this right on a database
        // where it was created without the cascade.
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            refresh_tokens::Entity::delete_many()
                .filter(refresh_tokens::Column::DeviceId.eq(id.0))
                .exec(&txn)
                .await
                .store()?;
            devices::Entity::delete_by_id(id.0)
                .exec(&txn)
                .await
                .store()?;
            Ok::<(), StoreError>(())
        }
        .await;
        match outcome {
            Ok(()) => txn.commit().await.store(),
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed device removal failed");
                }
                Err(err)
            }
        }
    }
}
