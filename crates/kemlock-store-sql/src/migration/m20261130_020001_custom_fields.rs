//! `custom_fields`: the fields an admin offers for the items.
//!
//! A row is a name, a type and the item types it applies to. None of it is secret, so it is kept in
//! the clear; the values live in the encrypted item bodies and never reach the server. `name_key`
//! is the name in lowercase, unique, so two fields can't differ only by case. Both name columns are
//! compared exactly (a binary collation on MySQL), so `Café` and `Cafe` stay two fields there too.

use super::cols::{exact_text_col, time_col};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

fn custom_fields_table(backend: DbBackend) -> TableCreateStatement {
    Table::create()
        .table("custom_fields")
        .if_not_exists()
        .col(c::uuid("id").primary_key().take())
        .col(exact_text_col(backend, "name", 64, false))
        .col(exact_text_col(backend, "name_key", 256, true))
        .col(c::string_len("field_type", 16))
        .col(c::string_len("kinds", 256))
        .col(time_col(backend, "created_at", false))
        .col(time_col(backend, "updated_at", false))
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        manager.create_table(custom_fields_table(backend)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_compares_both_names_exactly() {
        let sql = custom_fields_table(DbBackend::MySql).to_string(MysqlQueryBuilder);
        for column in ["name", "name_key"] {
            let wanted = format!("`{column}` varchar(");
            let at = sql.find(&wanted).unwrap_or_else(|| panic!("{column} in {sql}"));
            let definition = &sql[at..];
            let end = definition.find(',').unwrap_or(definition.len());
            assert!(
                definition[..end].contains("CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL"),
                "{column}: {sql}"
            );
        }
        // The unique key is on the exactly compared column.
        let key = &sql[sql.find("`name_key`").expect("name_key")..];
        assert!(key[..key.find(',').expect("a comma")].contains("UNIQUE KEY"), "{sql}");
    }

    #[test]
    fn the_other_backends_keep_plain_text_columns() {
        let sqlite = custom_fields_table(DbBackend::Sqlite).to_string(SqliteQueryBuilder);
        let postgres = custom_fields_table(DbBackend::Postgres).to_string(PostgresQueryBuilder);
        for sql in [sqlite, postgres] {
            assert!(!sql.contains("utf8mb4"), "{sql}");
            assert!(sql.contains("name_key"), "{sql}");
        }
    }
}
