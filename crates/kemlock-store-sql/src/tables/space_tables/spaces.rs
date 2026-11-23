//! `spaces`: a space, its encrypted name and the version of its space key.

use crate::convert::{from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::Space;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "spaces")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    pub key_version: i64,
    /// Set while the space key awaits replacement and writes are paused.
    pub keys_pending_since: Option<TimeDateTimeWithTimeZone>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Space, StoreError> {
        Ok(Space {
            id: SpaceId(self.id),
            name: self.name,
            key_version: from_i64_u32(self.key_version, "space key version")?,
            keys_pending_since: self.keys_pending_since,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Every column set, the id included. An update drops the id with
/// `ActiveModel { id: NotSet, ..active(space) }`.
pub(crate) fn active(space: &Space) -> ActiveModel {
    ActiveModel {
        id: Set(space.id.0),
        name: Set(space.name.clone()),
        key_version: Set(i64::from(space.key_version)),
        keys_pending_since: Set(space.keys_pending_since.map(utc)),
        created_at: Set(utc(space.created_at)),
        updated_at: Set(utc(space.updated_at)),
    }
}
