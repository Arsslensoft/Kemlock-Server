//! `email_changes`: an account's pending change of sign-in address, one row per account.
//!
//! The row holds what replaces the account's own once the link mailed to the new address is
//! opened: the address, the OPAQUE record registered under it, the KDF settings and the root-key
//! wrap made with it, and the SHA-256 of the link's token (never the token). It goes with the
//! account.

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        manager
            .create_table(
                Table::create()
                    .table("email_changes")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::string_len("email", 254))
                    .col(c::binary_len("token_hash", 32))
                    .col(c::blob("opaque_record"))
                    .col(c::big_integer("kdf_memory_kib"))
                    .col(c::big_integer("kdf_iterations"))
                    .col(c::big_integer("kdf_parallelism"))
                    .col(c::blob("kdf_salt"))
                    .col(c::blob("wrapped_root_key"))
                    .col(time_col(backend, "requested_at", false))
                    .col(time_col(backend, "expires_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_changes_user_id")
                            .from("email_changes", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // Opening a link finds its change by the token's hash.
        manager
            .create_index(
                Index::create()
                    .name("idx_email_changes_token_hash")
                    .table("email_changes")
                    .col("token_hash")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
