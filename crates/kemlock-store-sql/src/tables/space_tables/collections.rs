//! `collections`: a space's collections, nested by `parent_id`, each with its own key version.

use crate::convert::{from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::{Collection, CollectionId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "collections")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub space_id: Uuid,
    pub parent_id: Option<Uuid>,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    pub key_version: i64,
    /// Set while the collection's key awaits replacement and its writes are paused.
    pub stale_since: Option<TimeDateTimeWithTimeZone>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Collection, StoreError> {
        Ok(Collection {
            id: CollectionId(self.id),
            space: SpaceId(self.space_id),
            parent: self.parent_id.map(CollectionId),
            name: self.name,
            key_version: from_i64_u32(self.key_version, "collection key version")?,
            stale_since: self.stale_since,
            created_at: self.created_at,
        })
    }
}

pub(crate) fn active(collection: &Collection) -> ActiveModel {
    ActiveModel {
        id: Set(collection.id.0),
        space_id: Set(collection.space.0),
        parent_id: Set(collection.parent.map(|p| p.0)),
        name: Set(collection.name.clone()),
        key_version: Set(i64::from(collection.key_version)),
        stale_since: Set(collection.stale_since.map(utc)),
        created_at: Set(utc(collection.created_at)),
    }
}
