//! `email_changes.key_version`: the account's key version when the change was asked for. The change
//! holds a wrap of the root key made then; a root-key rotation replaces the root key, so a wrap
//! made before it must never be put back. The rotation's install deletes the pending change, and
//! opening a link whose version is not the account's is refused.
//!
//! The changes that are pending now get version 0, which no account that has keys holds: they were
//! asked for before the version was kept, may predate a rotation, and are refused when opened. The
//! person asks again (the link lives a day).

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        if !manager.has_column("email_changes", "key_version").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table("email_changes")
                        .add_column(c::big_integer("key_version").default(0).take())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
