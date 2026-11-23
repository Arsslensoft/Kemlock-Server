//! `events` and `settings`.

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
                    .table("events")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid_null("actor"))
                    .col(c::uuid_null("device"))
                    .col(c::string_len("action", 64))
                    .col(c::text_null("target"))
                    .col(time_col(backend, "at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_at")
                    .table("events")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_actor_at")
                    .table("events")
                    .col("actor")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("settings")
                    .if_not_exists()
                    .col(c::string_len("key", 128).primary_key().take())
                    .col(c::text("value"))
                    .to_owned(),
            )
            .await
    }
}
