//! `peer_key_history` and `peer_pending_addresses`: the identity keys a peer used before its
//! current one (a revocation signed by one of them lately still counts), and the address change
//! that came with a peer's key rotation, held for this server's admin.

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
                    .table("peer_key_history")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    // 0 for the oldest.
                    .col(c::big_integer("position"))
                    .col(c::blob("identity_key"))
                    // Unix seconds this server replaced the key.
                    .col(c::big_integer("replaced_at"))
                    .primary_key(Index::create().col("peer").col("position"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table("peer_pending_addresses")
                    .if_not_exists()
                    .col(c::uuid("peer").primary_key().take())
                    .col(c::string_len("operator", 128))
                    // One address or suite a line, as `peers` keeps them.
                    .col(c::text("addresses"))
                    .col(c::text("suites"))
                    .col(c::big_integer("received_at"))
                    .to_owned(),
            )
            .await
    }
}
