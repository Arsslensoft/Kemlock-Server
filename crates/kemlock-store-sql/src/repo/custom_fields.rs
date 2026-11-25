//! `CustomFieldRepo` on `custom_fields`.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::custom_fields;
use kemlock_app::admin::CustomFieldRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::{CustomField, CustomFieldId};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

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

    async fn insert_custom_field(&self, field: &CustomField) -> Result<(), StoreError> {
        custom_fields::Entity::insert(custom_fields::active(field))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
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
