//! Moves what `space_policies` holds into `space_policy_settings` and drops it.
//!
//! The first slice kept a space's "Require SSO" in its own table, `space_policies`; the policies
//! work then made `space_policy_settings`, which has a column for every typed policy, Require SSO
//! among them. Two tables for the one setting could disagree (the sign-in checks read one and the
//! policy routes the other), so `space_policy_settings` is now the only one. Each row of the old
//! table is copied: a space with no row in the new table gets one, with Require SSO as it was and
//! every other policy off, and a space that has one keeps it, with Require SSO turned on if the
//! old row had it on (the sign-in checks were enforcing it). Then the old table is dropped.
//!
//! Rows are copied one at a time with the query builder, not one `INSERT ... SELECT`, so the time
//! and boolean values are written the way the rest of the store writes them on every backend.

use crate::convert::utc;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, Value};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// The columns of `space_policy_settings` a copied row sets; the nullable ones stay null.
const COPIED: [&str; 17] = [
    "space_id",
    "require_sso",
    "two_step",
    "single_space",
    "disable_export",
    "disable_send",
    "always_show_email",
    "no_pin_unlock",
    "central_ownership",
    "no_card_items",
    "mp_on",
    "mp_require_upper",
    "mp_require_lower",
    "mp_require_numbers",
    "mp_require_special",
    "mp_enforce_on_login",
    "updated_at",
];

fn custom(error: impl std::fmt::Debug) -> DbErr {
    DbErr::Custom(format!("{error:?}"))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // A database that never had the table (this migration ran before and stopped after the
        // drop, on MySQL, which has no transactional DDL) has nothing left to copy.
        if manager.has_table("space_policies").await? {
            let db = manager.get_connection();
            let old = db
                .query_all(
                    &Query::select()
                        .columns([Alias::new("space_id"), Alias::new("require_sso")])
                        .from(Alias::new("space_policies"))
                        .to_owned(),
                )
                .await?;
            let now = utc(OffsetDateTime::now_utc());
            for row in old {
                let space: Uuid = row.try_get("", "space_id").map_err(custom)?;
                let on: bool = row.try_get("", "require_sso").map_err(custom)?;

                let present = db
                    .query_all(
                        &Query::select()
                            .column(Alias::new("space_id"))
                            .from(Alias::new("space_policy_settings"))
                            .and_where(Expr::col(Alias::new("space_id")).eq(space))
                            .to_owned(),
                    )
                    .await?;
                if present.is_empty() {
                    let mut cells = vec![Value::Uuid(Some(space)), Value::Bool(Some(on))];
                    cells.extend((0..COPIED.len() - 3).map(|_| Value::Bool(Some(false))));
                    cells.push(Value::TimeDateTimeWithTimeZone(Some(now)));
                    let mut insert = Query::insert();
                    insert
                        .into_table(Alias::new("space_policy_settings"))
                        .columns(COPIED.map(Alias::new))
                        .values(cells.into_iter().map(Expr::val))
                        .map_err(custom)?;
                    manager.exec_stmt(insert.to_owned()).await?;
                } else if on {
                    manager
                        .exec_stmt(
                            Query::update()
                                .table(Alias::new("space_policy_settings"))
                                .value(Alias::new("require_sso"), true)
                                .and_where(Expr::col(Alias::new("space_id")).eq(space))
                                .to_owned(),
                        )
                        .await?;
                }
            }
        }

        manager
            .drop_table(Table::drop().table("space_policies").if_exists().to_owned())
            .await
    }
}
