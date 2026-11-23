//! `sso_settings`, `sso_identities` and `verified_domains`.

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // One row: the provider connection. The primary key keeps a second row from existing.
        manager
            .create_table(
                Table::create()
                    .table("sso_settings")
                    .if_not_exists()
                    .col(c::integer("id").primary_key().take())
                    .col(c::boolean("enabled"))
                    .col(c::string_len("display_name", 100))
                    .col(c::string_len("issuer", 255))
                    .col(c::string_len("client_id", 255))
                    .col(c::blob_null("sealed_client_secret"))
                    .col(c::text("scopes"))
                    .col(c::boolean("allow_unknown_email_verification"))
                    .col(c::boolean("link_by_email"))
                    .col(c::boolean("create_accounts"))
                    .col(c::boolean("require_verified_domain"))
                    .col(c::text("group_rules"))
                    .col(time_col(backend, "updated_at", false))
                    .to_owned(),
            )
            .await?;

        // Issuer and subject name an account at a provider. Both are at most 255 characters
        // (a subject is by definition), so the key fits MySQL's index limit.
        manager
            .create_table(
                Table::create()
                    .table("sso_identities")
                    .if_not_exists()
                    .col(c::string_len("issuer", 255))
                    .col(c::string_len("subject", 255))
                    .col(c::uuid("user_id"))
                    .col(c::string_len("email", 254))
                    .col(time_col(backend, "linked_at", false))
                    .col(time_col(backend, "last_login_at", false))
                    .primary_key(Index::create().col("issuer").col("subject"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sso_identities_user_id")
                            .from("sso_identities", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sso_identities_user_id")
                    .table("sso_identities")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("verified_domains")
                    .if_not_exists()
                    .col(c::string_len("domain", 253).primary_key().take())
                    .col(c::string_len("token", 64))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "verified_at", true))
                    .to_owned(),
            )
            .await
    }
}
