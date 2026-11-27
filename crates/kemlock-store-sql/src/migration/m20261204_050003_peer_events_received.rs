//! `peer_events.received_ms`: when this server took the event, Unix milliseconds. The console lists
//! what peers sent by this, never by `at_ms`: that is the peer's own claim, and a peer could put its
//! events at the top of the list for ever (or push everyone else's down) by choosing it. Rows held
//! before this have 0 and sort as the oldest.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // `has_column` guards it: an `ADD COLUMN` that stopped half way on MySQL (no transactional
        // DDL) must be able to run again.
        if !manager.has_column("peer_events", "received_ms").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table("peer_events")
                        .add_column(c::big_integer("received_ms").default(0).take())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
