//! The privacy tables: the sign-in log, accounts waiting out their deletion grace period, and the
//! address columns of the event log.
//!
//! The log keeps an address truncated to its /24 or /48 in `ip`. `ip_full` holds the whole address
//! only while the admin keeps full addresses (off by default, up to 30 days); the retention job
//! empties it.

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // The two address columns of `events`. `has_column` guards them: an `ADD COLUMN` that
        // stopped half way on MySQL (no transactional DDL) must be able to run again.
        for name in ["ip", "ip_full"] {
            if !manager.has_column("events", name).await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table("events")
                            .add_column(c::string_len_null(name, 64))
                            .to_owned(),
                    )
                    .await?;
            }
        }

        manager
            .create_table(
                Table::create()
                    .table("sign_in_log")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid_null("user_id"))
                    .col(c::uuid_null("device_id"))
                    .col(c::string_len("method", 32))
                    .col(c::string_len("outcome", 16))
                    .col(time_col(backend, "at", false))
                    .col(c::string_len_null("ip", 64))
                    .col(c::string_len_null("ip_full", 64))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sign_in_log_at")
                    .table("sign_in_log")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sign_in_log_user_at")
                    .table("sign_in_log")
                    .col("user_id")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("pending_erasures")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(time_col(backend, "requested_at", false))
                    .col(time_col(backend, "due_at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_pending_erasures_due_at")
                    .table("pending_erasures")
                    .col("due_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
