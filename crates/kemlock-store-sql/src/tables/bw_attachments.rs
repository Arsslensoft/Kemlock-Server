//! `bw_attachments`: the attachments of imported ciphers, one row per Vaultwarden attachment.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_attachments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub item_id: Uuid,
    /// The file name, encrypted by the client.
    pub file_name: String,
    pub size: i64,
    /// The attachment's key, wrapped by the cipher key.
    pub akey: Option<String>,
    /// Where the file is under the data folder: `attachments/<cipher>/<attachment>`.
    pub storage_key: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
