//! `DeviceRepo` on `devices`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{devices, refresh_tokens};
use kemlock_app::ports::{DeviceRepo, StoreError};
use kemlock_domain::{Device, DeviceId, UserId};
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::Expr;
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

    /// Inserts the device, or updates it when the id is the same account's. An id that is another
    /// account's is `Duplicate`, however the two requests raced: the update names the account, so
    /// a device is never moved between accounts (the use case checks the owner first, but reads and
    /// writes are separate statements).
    async fn upsert(&self, device: &Device) -> Result<(), StoreError> {
        // A few rounds, for a row that is deleted between the insert and the update.
        for _ in 0..3 {
            match devices::Entity::insert(devices::active(device))
                .exec(self.writer())
                .await
            {
                Ok(_) => return Ok(()),
                Err(err) if is_unique_violation(&err) => {}
                Err(err) => return Err(map_db(err)),
            }
            let updated = devices::Entity::update_many()
                .set(devices::ActiveModel {
                    id: NotSet,
                    user_id: NotSet,
                    ..devices::active(device)
                })
                .filter(devices::Column::Id.eq(device.id.0))
                .filter(devices::Column::UserId.eq(device.user.0))
                .exec(self.writer())
                .await
                .store()?;
            if updated.rows_affected > 0 {
                return Ok(());
            }
            // MySQL counts a row written with the values it had as not affected.
            match devices::Entity::find_by_id(device.id.0)
                .one(self.writer())
                .await
                .store()?
            {
                Some(row) if row.user_id == device.user.0 => return Ok(()),
                Some(_) => return Err(StoreError::Duplicate),
                None => {}
            }
        }
        Err(StoreError::Duplicate)
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

    async fn upsert_description(&self, device: &Device) -> Result<(), StoreError> {
        let updated = devices::Entity::update_many()
            .col_expr(devices::Column::Name, Expr::value(device.name.clone()))
            .col_expr(
                devices::Column::Kind,
                Expr::value(devices::kind_str(device.kind).to_owned()),
            )
            .col_expr(devices::Column::LastSeenAt, Expr::value(utc(device.last_seen_at)))
            .filter(devices::Column::Id.eq(device.id.0))
            .filter(devices::Column::UserId.eq(device.user.0))
            .exec(self.writer())
            .await
            .store()?;
        if updated.rows_affected > 0 {
            return Ok(());
        }
        // Nothing changed: the device is new, or MySQL counted a row written with the same values.
        if devices::Entity::find_by_id(device.id.0)
            .one(self.writer())
            .await
            .store()?
            .is_some()
        {
            return Ok(());
        }
        self.upsert(device).await
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
