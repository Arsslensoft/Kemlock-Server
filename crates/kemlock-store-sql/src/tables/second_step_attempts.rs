//! `second_step_attempts`: per account, the count of second-step attempts that limits guessing a
//! code, kept in the database so it holds across restarts and replicas. No row means no attempts.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "second_step_attempts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// When the current window began (Unix seconds).
    pub window_start: i64,
    /// Attempts reserved in the window.
    pub count: i64,
    /// How many waits in a row were started.
    pub level: i64,
    /// Attempts are refused until this time (Unix seconds).
    pub blocked_until: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
