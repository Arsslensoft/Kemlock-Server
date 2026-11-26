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
    pub sealed_by: Option<Uuid>,
    pub sealed_by_key_version: Option<i64>,
    pub sealed_signature: Option<Vec<u8>>,
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
            sealed_by: super::members::sealed_by_of(
                self.sealed_by,
                self.sealed_by_key_version,
                self.sealed_signature,
            )?,
        })
    }
}

pub(crate) fn active(copy: &KeyCopy) -> ActiveModel {
    ActiveModel {
        collection_id: Set(copy.collection.0),
        user_id: Set(copy.user.0),
        key_version: Set(i64::from(copy.key_version)),
        sealed: Set(copy.sealed.clone()),
        sealed_by: Set(copy.sealed_by.as_ref().map(|s| s.by.0)),
        sealed_by_key_version: Set(copy.sealed_by.as_ref().map(|s| i64::from(s.key_version))),
        sealed_signature: Set(copy.sealed_by.as_ref().map(|s| s.signature.clone())),
    }
}
