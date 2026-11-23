//! `vw_rows`, `bw_attachments` and `bw_account_extras`: what the move from Vaultwarden keeps that
//! no other table has a place for.
//!
//! `vw_rows` holds Vaultwarden rows as they were, one JSON object per row, for the tables whose
//! contents the server doesn't serve yet (policies, Sends, organization API keys, the per-user
//! state of organization ciphers) and as the lookup the second pass of a move reads. Tables with
//! secrets are stored sealed under `server.key`. `bw_attachments` is each cipher's attachment
//! list, so a cipher document can be rebuilt when its attachments change. `bw_account_extras`
//! holds the columns of a Vaultwarden user that `bw_accounts` has no field for.

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
                    .table("vw_rows")
                    .if_not_exists()
                    .col(c::string_len("table_name", 64))
                    .col(c::string_len("row_key", 255))
                    .col(c::text("data"))
                    .primary_key(Index::create().col("table_name").col("row_key"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("bw_attachments")
                    .if_not_exists()
                    .col(c::string_len("id", 64).primary_key().take())
                    .col(c::uuid("item_id"))
                    .col(c::text("file_name"))
                    .col(c::big_integer("size"))
                    .col(c::text_null("akey"))
                    .col(c::string_len("storage_key", 255))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_bw_attachments_item_id")
                    .table("bw_attachments")
                    .col("item_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("bw_account_extras")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::boolean("enabled"))
                    .col(time_col(backend, "verified_at", true))
                    .col(time_col(backend, "last_verifying_at", true))
                    .col(c::big_integer("login_verify_count"))
                    .col(c::text_null("email_new"))
                    .col(c::text_null("email_new_token"))
                    .col(c::text_null("stamp_exception"))
                    .col(c::text("equivalent_domains"))
                    .col(c::text("excluded_globals"))
                    .col(c::text_null("external_id"))
                    .col(c::text_null("key_id"))
                    .col(c::blob_null("sealed_totp_secret"))
                    .col(c::blob_null("sealed_totp_recover"))
                    .col(c::string_len("vw_security_stamp", 128))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_bw_account_extras_user_id")
                            .from("bw_account_extras", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
