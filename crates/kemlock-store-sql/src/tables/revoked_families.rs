//! `revoked_families`: refresh-token families that were revoked. The row, not the deletion of the
//! family's tokens, is what ends a family: a token inserted into a revoked family by a rotation
//! that was racing the revocation is dead on arrival.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "revoked_families")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub family: Uuid,
    pub revoked_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
