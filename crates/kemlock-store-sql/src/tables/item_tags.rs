//! `item_tags`: the duplicate tags a device uploaded, one row per (owner, tag, item).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "item_tags")]
pub struct Model {
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_type: i16,
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_id: Uuid,
    /// The tag, 32 bytes.
    #[sea_orm(primary_key, auto_increment = false)]
    pub tag: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub item_id: Uuid,
    /// The revision of the item the tag was made for.
    pub item_revision: i64,
    /// The owner's dedup key version it was made under.
    pub key_version: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
