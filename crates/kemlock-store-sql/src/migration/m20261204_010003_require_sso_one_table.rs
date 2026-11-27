//! Moves "Require single sign-on" of Bitwarden organizations into `space_policy_settings`.
//!
//! The Bitwarden API used to keep the policy of type 4 only as a document in `bw_docs`, and the
//! Kemlock sign-in checks read only `space_policy_settings`, so a member bound on one side signed in
//! through the other. The Bitwarden API now writes and reads the table, which is the one place the
//! setting lives. Every organization whose type 4 document says `enabled` gets Require SSO turned on
//! in the table: a space with no row gets one with every other policy off, and a space that has one
//! keeps it. (A setting the table had on and the document did not is left on: it was enforced.)
//!
//! Rows are written one at a time with the query builder, as `merge_space_policies` did, so the
//! time and boolean values are written the way the rest of the store writes them on every backend.

use crate::convert::utc;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, Value};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// The columns of `space_policy_settings` a new row sets; the nullable ones stay null.
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
        // Both tables exist on every database that reaches here; a missing one has nothing to move.
        if !manager.has_table("bw_docs").await?
            || !manager.has_table("space_policy_settings").await?
        {
            return Ok(());
        }
        let db = manager.get_connection();
        let documents = db
            .query_all(
                &Query::select()
                    .columns([Alias::new("scope"), Alias::new("body")])
                    .from(Alias::new("bw_docs"))
                    .and_where(Expr::col(Alias::new("kind")).eq("policy"))
                    .and_where(Expr::col(Alias::new("doc_key")).eq("4"))
                    .to_owned(),
            )
            .await?;
        let now = utc(OffsetDateTime::now_utc());
        for row in documents {
            let space: Uuid = row.try_get("", "scope").map_err(custom)?;
            let body: String = row.try_get("", "body").map_err(custom)?;
            let enabled = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|doc| doc.get("enabled").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
            if !enabled {
                continue;
            }
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
                let mut cells = vec![Value::Uuid(Some(space)), Value::Bool(Some(true))];
                cells.extend((0..COPIED.len() - 3).map(|_| Value::Bool(Some(false))));
                cells.push(Value::TimeDateTimeWithTimeZone(Some(now)));
                let mut insert = Query::insert();
                insert
                    .into_table(Alias::new("space_policy_settings"))
                    .columns(COPIED.map(Alias::new))
                    .values(cells.into_iter().map(Expr::val))
                    .map_err(custom)?;
                manager.exec_stmt(insert.to_owned()).await?;
            } else {
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
        Ok(())
    }
}
