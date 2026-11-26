//! `email_confirmations`: an account held back until the link mailed to its address is opened
//! (`SIGNUPS_VERIFY`), one row per account.
//!
//! The row's existence is the hold: an account with none is confirmed, which is every account
//! that existed before this table did. It holds the SHA-256 of the link's token (never the token)
//! and when the link was made and runs out. It goes with the account.

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
                    .table("email_confirmations")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::binary_len("token_hash", 32))
                    .col(time_col(backend, "requested_at", false))
                    .col(time_col(backend, "expires_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_confirmations_user_id")
                            .from("email_confirmations", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // Opening a link finds its row by the token's hash.
        manager
            .create_index(
                Index::create()
                    .name("idx_email_confirmations_token_hash")
                    .table("email_confirmations")
                    .col("token_hash")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
