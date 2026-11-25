//! `CustomFieldRepo` on `custom_fields`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::{custom_fields, settings};
use kemlock_app::admin::CustomFieldRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::{CustomField, CustomFieldId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, TransactionTrait,
};

/// The row every insert writes first. Its writer holds the row until its transaction ends, so two
/// inserts take turns: the second counts what the first stored, and the cap holds.
const CAP_LOCK: &str = "custom_fields.cap_lock";

impl CustomFieldRepo for SqlStore {
    async fn custom_fields(&self) -> Result<Vec<CustomField>, StoreError> {
        custom_fields::Entity::find()
            .order_by_asc(custom_fields::Column::CreatedAt)
            .order_by_asc(custom_fields::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(custom_fields::Model::into_domain)
            .collect()
    }

    async fn custom_field(&self, id: CustomFieldId) -> Result<Option<CustomField>, StoreError> {
        custom_fields::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(custom_fields::Model::into_domain)
            .transpose()
    }

    async fn insert_custom_field(
        &self,
        field: &CustomField,
        limit: usize,
    ) -> Result<bool, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            // Take the lock row first: a count made before it could be stale by the time the
            // field is stored. (SQLite has one writer, so there it only costs a write.)
            let lock = settings::Entity::insert(settings::ActiveModel {
                key: Set(CAP_LOCK.to_owned()),
                value: Set(field.id.to_string()),
            })
            .on_conflict(
                OnConflict::column(settings::Column::Key)
                    .update_column(settings::Column::Value)
                    .to_owned(),
            )
            .exec(&txn)
            .await;
            match lock {
                Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {}
                Err(err) => return Err(map_db(err)),
            }
            let held = custom_fields::Entity::find().count(&txn).await.store()?;
            if held >= u64::try_from(limit).unwrap_or(u64::MAX) {
                return Ok(false);
            }
            custom_fields::Entity::insert(custom_fields::active(field))
                .exec(&txn)
                .await
                .store()?;
            Ok::<bool, StoreError>(true)
        }
        .await;
        match outcome {
            Ok(stored) => {
                txn.commit().await.store()?;
                Ok(stored)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed custom field insert failed");
                }
                Err(err)
            }
        }
    }

    async fn update_custom_field(&self, field: &CustomField) -> Result<(), StoreError> {
        let row = custom_fields::ActiveModel {
            id: NotSet,
            created_at: NotSet,
            ..custom_fields::active(field)
        };
        let updated = custom_fields::Entity::update_many()
            .set(row)
            .filter(custom_fields::Column::Id.eq(field.id.0))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        if updated == 0 {
            // MySQL counts a row whose values did not change as zero rows affected.
            let exists = custom_fields::Entity::find_by_id(field.id.0)
                .one(self.writer())
                .await
                .store()?
                .is_some();
            if !exists {
                return Err(StoreError::NotFound);
            }
        }
        Ok(())
    }

    async fn remove_custom_field(&self, id: CustomFieldId) -> Result<bool, StoreError> {
        let removed = custom_fields::Entity::delete_many()
            .filter(custom_fields::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok(removed > 0)
    }
}
