//! `account_bundles`: every public-key bundle an account has had, by key version. A write is signed
//! under the bundle of the key version it names (docs/crypto.md, "Signed item writes"), so once an
//! account rotates its keys the bundles before the rotation must stay readable for as long as items
//! signed under them do.
//!
//! The store fills it wherever an account's bundle is written (`UserRepo::insert`, `update` and
//! `set_first_keys`), and `update` also keeps the bundle it replaces. The accounts that exist now
//! get a row for the bundle they hold.

use super::cols::{big_blob, time_col};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        let existed = manager.has_table("account_bundles").await?;
        manager
            .create_table(
                Table::create()
                    .table("account_bundles")
                    .if_not_exists()
                    .col(c::uuid("user_id"))
                    .col(c::big_integer("key_version"))
                    .col(big_blob(backend, "public_bundle", false))
                    .col(big_blob(backend, "bundle_signature", false))
                    .col(time_col(backend, "recorded_at", false))
                    .primary_key(Index::create().col("user_id").col("key_version"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_account_bundles_user_id")
                            .from("account_bundles", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        if !existed {
            manager
                .get_connection()
                .execute_unprepared(
                    "INSERT INTO account_bundles \
                     (user_id, key_version, public_bundle, bundle_signature, recorded_at) \
                     SELECT id, key_version, public_bundle, bundle_signature, updated_at \
                     FROM users WHERE key_version > 0",
                )
                .await?;
        }
        Ok(())
    }
}
