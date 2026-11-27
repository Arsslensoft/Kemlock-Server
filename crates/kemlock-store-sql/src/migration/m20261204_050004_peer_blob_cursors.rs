//! `peer_blob_cursors`: where the list of a vault's attachments stopped last time with a peer, so a
//! vault with more attachments than one visit lists is listed in full over several visits.

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
                    .table("peer_blob_cursors")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    // The attachment id the next page asks after, 16 bytes.
                    .col(c::uuid("after"))
                    .primary_key(
                        Index::create()
                            .col("peer")
                            .col("owner_type")
                            .col("owner_id"),
                    )
                    .to_owned(),
            )
            .await
    }
}
