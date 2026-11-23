//! `users`, `devices`, `refresh_tokens`, `revoked_families` and `two_factor`.

use super::cols::{big_blob, time_col};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// The `users` table. Every binary column here is under 64 KiB except the sealed private keys,
/// which the API accepts up to exactly 64 KiB (65,536 bytes): MySQL's `BLOB` holds 65,535, so
/// that column is a long blob there.
fn users_table(backend: DbBackend) -> TableCreateStatement {
    Table::create()
        .table("users")
        .if_not_exists()
        .col(c::uuid("id").primary_key().take())
        .col(c::string_len_uniq("email", 254))
        .col(c::text_null("name"))
        .col(c::string_len("mode", 16))
        .col(c::string_len("role", 16))
        .col(c::big_integer("kdf_memory_kib"))
        .col(c::big_integer("kdf_iterations"))
        .col(c::big_integer("kdf_parallelism"))
        .col(c::blob("kdf_salt"))
        .col(c::blob_null("opaque_record"))
        .col(c::blob("wrapped_root_key"))
        .col(c::blob("public_bundle"))
        .col(c::blob("bundle_signature"))
        .col(big_blob(backend, "sealed_private_keys", false))
        .col(c::big_integer("key_version"))
        .col(c::uuid("security_stamp"))
        .col(time_col(backend, "created_at", false))
        .col(time_col(backend, "updated_at", false))
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        manager.create_table(users_table(backend)).await?;

        manager
            .create_table(
                Table::create()
                    .table("devices")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::string_len("name", 255))
                    .col(c::string_len("kind", 32))
                    .col(c::string_len_null("dpop_jkt", 128))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "last_seen_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_devices_user_id")
                            .from("devices", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_devices_user_id")
                    .table("devices")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("refresh_tokens")
                    .if_not_exists()
                    .col(c::binary_len("hash", 32).primary_key().take())
                    .col(c::uuid("family"))
                    .col(c::uuid("user_id"))
                    .col(c::uuid("device_id"))
                    .col(c::uuid("security_stamp"))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "expires_at", false))
                    .col(time_col(backend, "used_at", true))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user_id")
                            .from("refresh_tokens", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_device_id")
                            .from("refresh_tokens", "device_id")
                            .to("devices", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_family")
                    .table("refresh_tokens")
                    .col("family")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_device_id")
                    .table("refresh_tokens")
                    .col("device_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // A family whose reuse was detected. A refresh token of a listed family is dead whatever
        // rows it has or gets later, so a rotation racing the revocation cannot leave a live
        // token behind.
        manager
            .create_table(
                Table::create()
                    .table("revoked_families")
                    .if_not_exists()
                    .col(c::uuid("family").primary_key().take())
                    .col(time_col(backend, "revoked_at", false))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("two_factor")
                    .if_not_exists()
                    .col(c::uuid("user_id"))
                    .col(c::string_len("method", 16))
                    .col(c::blob("sealed_secret"))
                    .col(c::boolean("enabled"))
                    // The newest TOTP step accepted at sign-in, so a code is good once.
                    .col(c::big_integer_null("last_used_step"))
                    .col(time_col(backend, "created_at", false))
                    .primary_key(Index::create().col("user_id").col("method"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_two_factor_user_id")
                            .from("two_factor", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_private_keys_fit_65536_bytes_on_mysql() {
        // A plain MySQL BLOB stops at 65,535 bytes; registration accepts exactly 64 KiB.
        let sql = users_table(DbBackend::MySql).to_string(MysqlQueryBuilder);
        assert!(sql.contains("`sealed_private_keys` longblob"), "{sql}");
        // The other binary columns are far below the limit and stay plain blobs.
        assert!(sql.contains("`public_bundle` blob"), "{sql}");
    }

    #[test]
    fn the_other_backends_keep_their_usual_blob() {
        for backend in [DbBackend::Sqlite, DbBackend::Postgres] {
            let sql = match backend {
                DbBackend::Postgres => users_table(backend).to_string(PostgresQueryBuilder),
                _ => users_table(backend).to_string(SqliteQueryBuilder),
            };
            assert!(!sql.contains("longblob"), "{sql}");
        }
    }
}
