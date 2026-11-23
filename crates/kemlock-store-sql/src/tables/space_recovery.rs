//! `space_recovery_boxes`: a member's root key sealed to a space's recovery key.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_recovery_boxes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub key_seq: i64,
    pub sealed: Vec<u8>,
    /// Unix seconds.
    pub enrolled_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
