//! `bw_accounts`: the Vaultwarden-style record of an account that signs in on the Bitwarden API.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table("bw_accounts")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::blob("password_hash"))
                    .col(c::blob("salt"))
                    .col(c::big_integer("password_iterations"))
                    .col(c::big_integer("kdf_type"))
                    .col(c::big_integer("kdf_iterations"))
                    .col(c::big_integer_null("kdf_memory"))
                    .col(c::big_integer_null("kdf_parallelism"))
                    .col(c::text("akey"))
                    .col(c::text_null("private_key"))
                    .col(c::text_null("public_key"))
                    .col(c::text_null("password_hint"))
                    .col(c::string_len_null("api_key", 64))
                    .col(c::string_len_null("avatar_color", 16))
                    .col(c::big_integer("revision_ms"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_bw_accounts_user_id")
                            .from("bw_accounts", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
