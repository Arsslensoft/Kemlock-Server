//! `push_tokens.kind` from 8 to 16 characters: `unifiedpush` (a UnifiedPush endpoint) is 11.
//!
//! SQLite doesn't enforce a text column's length, so nothing changes there. PostgreSQL and MySQL
//! do; re-running the change is harmless, so a migration that stopped half way can run again.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table("push_tokens")
                    .modify_column(ColumnDef::new("kind").string_len(16).not_null())
                    .to_owned(),
            )
            .await
    }
}
