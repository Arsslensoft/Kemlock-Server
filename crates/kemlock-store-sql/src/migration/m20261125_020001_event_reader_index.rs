//! An index on `events (action, at)`, for the event lists of the Bitwarden API.
//!
//! Those lists read one action's events in a time range, newest first, and narrow them by
//! organization, cipher or member in the event's target. Without this index every list scans the
//! whole log.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("idx_events_action_at")
                    .table("events")
                    .col("action")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
