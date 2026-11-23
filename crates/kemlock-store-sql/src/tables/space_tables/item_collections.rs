//! `item_collections`: the collection each space item is in. It is metadata beside the item, kept
//! apart so `items` and the domain's `Item` stay as they are.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "item_collections")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub item_id: Uuid,
    pub space_id: Uuid,
    pub collection_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
