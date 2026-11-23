//! `peer_events`: the event log entries a peer sent for a federated vault, when the peer's Send
//! switch and this server's Pull switch for it were both on. Kept apart from this server's own
//! `events`, and gone with the peer.

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
                    .table("peer_events")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    // The event's id, a UUID v7: ids sort by time, so the newest one is the cursor.
                    .col(c::uuid("id"))
                    .col(c::big_integer("at_ms"))
                    .col(c::uuid_null("actor"))
                    .col(c::uuid_null("device"))
                    .col(c::string_len("action", 64))
                    .col(c::string_len_null("target", 256))
                    .primary_key(
                        Index::create()
                            .col("peer")
                            .col("owner_type")
                            .col("owner_id")
                            .col("id"),
                    )
                    .to_owned(),
            )
            .await
    }
}
