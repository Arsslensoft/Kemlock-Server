//! Email and identifier columns compare exactly on MySQL.
//!
//! MySQL's default collation is accent- and case-insensitive: `straße@example.org` and
//! `strasse@example.org` are one address to it. With linking by email on, a look-alike identity at
//! the provider would then link to another person's account, and look-alike accounts would pick up
//! pending Bitwarden invitations and emergency grants meant for someone else. These columns become
//! `utf8mb4_bin` (see `cols::exact_text_col`), so two different strings are two different keys.
//!
//! SQLite and PostgreSQL compare text byte for byte already: nothing changes there. Making a
//! column binary again changes nothing, so a migration that stopped half way (MySQL commits each
//! `ALTER`) can run again.

use super::cols::exact_text_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

/// Table, column, length, nullable: every column that holds an address or an identifier given by
/// someone else and looked up or kept unique by its text.
const COLUMNS: &[(&str, &str, u32, bool)] = &[
    ("users", "email", 254, false),
    ("admin_invites", "email", 254, false),
    ("email_changes", "email", 254, false),
    ("emergency_access", "grantee_email", 254, false),
    ("sso_identities", "issuer", 255, false),
    ("sso_identities", "subject", 255, false),
    ("sso_identities", "email", 254, false),
    ("sso_sessions", "issuer", 255, false),
    ("sso_sessions", "subject", 255, false),
    ("sso_sessions", "session_id", 255, true),
    ("verified_domains", "domain", 253, false),
    // The Bitwarden documents are keyed by text: an invitation by the invitee's email, say.
    ("bw_docs", "doc_key", 255, false),
    ("vw_rows", "row_key", 255, false),
];

fn modify(
    table: &'static str,
    column: &'static str,
    len: u32,
    nullable: bool,
) -> TableAlterStatement {
    let def = if nullable {
        // `exact_text_col` is never null; a nullable column is the same type without `NOT NULL`.
        ColumnDef::new(column)
            .custom(Alias::new(format!(
                "varchar({len}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
            )))
            .null()
            .take()
    } else {
        exact_text_col(DbBackend::MySql, column, len, false)
    };
    Table::alter().table(table).modify_column(def).to_owned()
}

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::MySql {
            return Ok(());
        }
        for &(table, column, len, nullable) in COLUMNS {
            // A table or column a database lacks (an older schema restored by hand) is skipped.
            if !manager.has_column(table, column).await? {
                continue;
            }
            manager
                .alter_table(modify(table, column, len, nullable))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_column_becomes_binary_and_keeps_its_length_and_nullability() {
        let sql = modify("users", "email", 254, false).to_string(MysqlQueryBuilder);
        assert!(
            sql.contains("`email` varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL"),
            "{sql}"
        );
        let sql = modify("sso_sessions", "session_id", 255, true).to_string(MysqlQueryBuilder);
        assert!(
            sql.contains(
                "`session_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL"
            ),
            "{sql}"
        );
        assert!(!sql.contains("NOT NULL"), "{sql}");
    }
}
