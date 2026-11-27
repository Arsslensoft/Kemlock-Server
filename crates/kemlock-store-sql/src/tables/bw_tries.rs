//! `bw_tries`: how many tries an account's secret has had in the window it is in
//! (`kemlock_app::bitwarden::BwTryRepo`).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_tries")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// What was tried: `second-step`, `email-login`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    pub tries: i64,
    /// Unix seconds of the first try of the window.
    pub window_start: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
