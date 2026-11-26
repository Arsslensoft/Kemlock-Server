//! `bw_accounts.api_key` from 64 characters to text: a key sealed under `server.key` is stored as
//! `sealed:` and the base64url of the sealed value, about 90 characters, so a sealed key no longer
//! fits `varchar(64)` and every update of an account failed on PostgreSQL and MySQL.
//!
//! SQLite doesn't enforce a text column's length, so nothing changes there. Re-running the change
//! is harmless, so a migration that stopped half way can run again.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

fn widen() -> TableAlterStatement {
    Table::alter()
        .table("bw_accounts")
        .modify_column(ColumnDef::new("api_key").text().null())
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        manager.alter_table(widen()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_column_becomes_text_on_the_servers_that_limit_it() {
        let postgres = widen().to_string(PostgresQueryBuilder);
        assert!(postgres.contains("\"api_key\" TYPE text"), "{postgres}");
        let mysql = widen().to_string(MysqlQueryBuilder);
        assert!(mysql.contains("`api_key` text"), "{mysql}");
    }
}
