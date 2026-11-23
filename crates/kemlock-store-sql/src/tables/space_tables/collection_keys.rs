//! `collection_keys`: each collection's key, sealed to every member who may hold it.

use crate::convert::from_i64_u32;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use kemlock_domain::spaces::{CollectionId, KeyCopy};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "collection_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub key_version: i64,
    pub sealed: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<KeyCopy, StoreError> {
        Ok(KeyCopy {
            collection: CollectionId(self.collection_id),
            user: UserId(self.user_id),
            key_version: from_i64_u32(self.key_version, "collection key version")?,
            sealed: self.sealed,
        })
    }
}

pub(crate) fn active(copy: &KeyCopy) -> ActiveModel {
    ActiveModel {
        collection_id: Set(copy.collection.0),
        user_id: Set(copy.user.0),
        key_version: Set(i64::from(copy.key_version)),
        sealed: Set(copy.sealed.clone()),
    }
}
