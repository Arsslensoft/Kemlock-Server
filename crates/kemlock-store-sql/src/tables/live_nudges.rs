//! `live_nudges`: "a change reached this owner", appended by every replica and polled by every
//! replica on a database with no notification channel.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "live_nudges")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    pub owner_type: i16,
    pub owner_id: Uuid,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
