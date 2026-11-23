//! `space_pending_changes`: member and grant changes that came from outside Kemlock clients (the
//! Bitwarden-compatible routes, SSO group sync) for a space that has a chain, kept for an Owner's
//! or Admin's app to sign as records. It replaces the first, plainer `space_chain_pending`, which
//! no release wrote to.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table("space_chain_pending")
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table("space_pending_changes")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("space_id"))
                    // `bitwarden` or `sso`.
                    .col(c::string_len("source", 16))
                    // Unix seconds.
                    .col(c::big_integer("queued_at"))
                    .col(c::uuid_null("requested_by"))
                    .col(c::string_len("via", 128))
                    .col(c::uuid("account"))
                    // `add-member`, `remove-member`, `role`, `grant-set` or `grant-remove`.
                    .col(c::string_len("kind", 16))
                    .col(c::string_len_null("role", 16))
                    .col(c::big_integer("custom"))
                    .col(c::uuid_null("collection"))
                    .col(c::string_len_null("permission", 32))
                    // An added member's grants: `<collection uuid>:<permission>`, comma separated.
                    .col(c::text("grants"))
                    // `pending`, `done` or `dropped`.
                    .col(c::string_len("status", 8))
                    .col(c::big_integer_null("done_at"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_space_pending_changes_space_id")
                    .table("space_pending_changes")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
