//! `vw_import_ids`: the user and space ids the move from Vaultwarden created (see the migration).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vw_import_ids")]
pub struct Model {
    /// `user` or `space`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub imported_at: TimeDateTimeWithTimeZone,
    /// When the import last wrote it.
    pub written_at: TimeDateTimeWithTimeZone,
    /// For an account: the revision date of its Bitwarden record after that write, so a later
    /// change by the API shows. Absent for a space and for a backfilled account.
    pub revision_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
