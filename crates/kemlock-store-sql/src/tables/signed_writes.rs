//! `signed_writes`: the owners that accept signed `kem1` writes only (docs/crypto.md, "Signed item
//! writes"), and since when. A row is added in the transaction of the first signed write for the
//! owner, or when the owner asks, and never removed while the owner exists.

use crate::convert::utc;
use crate::tables::items::owner_parts;
use kemlock_domain::Owner;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signed_writes")]
pub struct Model {
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_type: i16,
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_id: Uuid,
    pub since: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The row that marks `owner` as signed-only since `at`.
pub(crate) fn active(owner: Owner, at: OffsetDateTime) -> ActiveModel {
    let (owner_type, owner_id) = owner_parts(owner);
    ActiveModel {
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        since: Set(utc(at)),
    }
}
