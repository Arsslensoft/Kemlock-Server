//! `custom_fields`: the fields an admin offers for the items.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{CustomField, CustomFieldId, FieldKinds, FieldType};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "custom_fields")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    /// The name in lowercase, unique.
    pub name_key: String,
    /// `text`, `hidden` or `checkbox`.
    pub field_type: String,
    /// `*`, or item kinds joined by commas.
    pub kinds: String,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<CustomField, StoreError> {
        Ok(CustomField {
            id: CustomFieldId(self.id),
            name: self.name,
            field_type: FieldType::parse(&self.field_type)
                .ok_or_else(|| corrupt("custom field type"))?,
            kinds: FieldKinds::from_stored(&self.kinds)
                .ok_or_else(|| corrupt("custom field kinds"))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

pub(crate) fn active(field: &CustomField) -> ActiveModel {
    ActiveModel {
        id: Set(field.id.0),
        name: Set(field.name.clone()),
        name_key: Set(field.name_key()),
        field_type: Set(field.field_type.as_str().to_owned()),
        kinds: Set(field.kinds.to_stored()),
        created_at: Set(utc(field.created_at)),
        updated_at: Set(utc(field.updated_at)),
    }
}
