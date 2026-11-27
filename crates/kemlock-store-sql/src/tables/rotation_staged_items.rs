//! `rotation_staged_items`: items re-encrypted for a root-key rotation, kept apart until the
//! install (docs/crypto.md, "Rotating the root key").

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "rotation_staged_items")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub item_id: Uuid,
    pub rotation_id: Uuid,
    pub base_revision: i64,
    pub ciphertext: Vec<u8>,
    pub item_key: Vec<u8>,
    /// The account's signature of the write the rotation makes of the item, in its stored form.
    pub write_sig: Option<Vec<u8>>,
    pub staged_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
