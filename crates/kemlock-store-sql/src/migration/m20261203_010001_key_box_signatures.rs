//! `members.sealed_by`, `members.sealed_by_key_version`, `members.sealed_signature` and the same
//! three on `collection_keys`: who sealed a key copy, at which key version of theirs, and their
//! `sig1` signature over the box (docs/crypto.md, "Signed key boxes").
//!
//! Every column is null for the copies that exist now: they were sealed before keys were signed,
//! and clients treat them by the rule for such boxes. The server writes the three together or not at
//! all.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// The tables that hold a sealed key copy.
const TABLES: [&str; 2] = ["members", "collection_keys"];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            // `has_column` guards each one: an `ADD COLUMN` that stopped half way on MySQL (no
            // transactional DDL) must be able to run again.
            if !manager.has_column(table, "sealed_by").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(table)
                            .add_column(c::uuid_null("sealed_by"))
                            .to_owned(),
                    )
                    .await?;
            }
            if !manager.has_column(table, "sealed_by_key_version").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(table)
                            .add_column(c::big_integer_null("sealed_by_key_version"))
                            .to_owned(),
                    )
                    .await?;
            }
            if !manager.has_column(table, "sealed_signature").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(table)
                            .add_column(c::blob_null("sealed_signature"))
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}
