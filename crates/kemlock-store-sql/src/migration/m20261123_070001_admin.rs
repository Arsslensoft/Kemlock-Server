//! The admin console's tables: the address on an event, a disabled flag per account, invitations
//! to the server and the privacy requests queue.
//!
//! None of it changes a table the other areas own except `events`, which gains a nullable `ip`
//! (the client's address cut to its /24 or /48; nothing wrote one before).

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // SQLite has no `ADD COLUMN IF NOT EXISTS`, so ask first: a migration that stopped
        // half way on MySQL (no transactional DDL) can run again.
        if !manager.has_column("events", "ip").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table("events")
                        .add_column(c::string_len_null("ip", 64))
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_table(
                Table::create()
                    .table("admin_user_state")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(time_col(backend, "disabled_at", false))
                    .col(c::uuid("disabled_by"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_admin_user_state_user_id")
                            .from("admin_user_state", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("admin_invites")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::string_len_uniq("email", 254))
                    .col(c::uuid("invited_by"))
                    .col(c::binary_len("token_hash", 32))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "expires_at", false))
                    .col(time_col(backend, "last_sent_at", false))
                    .col(c::big_integer("sent"))
                    .col(time_col(backend, "accepted_at", true))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_admin_invites_token_hash")
                    .table("admin_invites")
                    .col("token_hash")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("compliance_requests")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::string_len("kind", 16))
                    .col(c::string_len("requester", 254))
                    .col(c::uuid_null("user_id"))
                    .col(time_col(backend, "received_at", false))
                    .col(time_col(backend, "due_at", false))
                    .col(c::boolean("extended"))
                    .col(c::string_len("status", 16))
                    .col(c::text_null("note"))
                    .col(time_col(backend, "closed_at", true))
                    .col(c::uuid_null("handled_by"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_compliance_requests_status_due")
                    .table("compliance_requests")
                    .col("status")
                    .col("due_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
