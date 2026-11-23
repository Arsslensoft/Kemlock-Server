//! `bw_docs`: opaque JSON documents of the Bitwarden API, by scope, kind and key.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_docs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub doc_key: String,
    pub body: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
