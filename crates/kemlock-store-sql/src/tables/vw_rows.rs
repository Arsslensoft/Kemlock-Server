//! `vw_rows`: Vaultwarden rows kept as they were (see the migration).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vw_rows")]
pub struct Model {
    /// The Vaultwarden table's name.
    #[sea_orm(primary_key, auto_increment = false)]
    pub table_name: String,
    /// The row's primary key, the key columns joined with `/`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub row_key: String,
    /// A JSON object keyed by column name, or `sealed:` and the base64url of it sealed under
    /// `server.key`.
    pub data: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
