//! `two_factor_recovery`: an account's two-step recovery code, sealed under `server.key`.

use crate::convert::utc;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "two_factor_recovery")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// The code as upper-case base32 text, sealed with the purpose `two-step-recovery`.
    pub sealed_code: Vec<u8>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) fn active(user: Uuid, sealed: &[u8], at: OffsetDateTime) -> ActiveModel {
    ActiveModel {
        user_id: Set(user),
        sealed_code: Set(sealed.to_vec()),
        created_at: Set(utc(at)),
    }
}
