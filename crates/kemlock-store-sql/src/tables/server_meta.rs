//! `server_meta`: one row holding this server's id, its next sequence number and its last HLC.

use sea_orm::entity::prelude::*;

/// The only row's id; the primary key keeps a second row from ever existing.
pub(crate) const ROW_ID: i32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "server_meta")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub server_id: Uuid,
    pub created_at: TimeDateTimeWithTimeZone,
    /// The sequence number the next accepted write takes; starts at 1.
    pub next_seq: i64,
    /// The HLC time of the last accepted write; 0 before any.
    pub last_hlc: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
