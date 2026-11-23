//! `federation_erasures`: the erasures a home still has to tell a replica about. When a home
//! erases a vault (an account's, or a space's that went with its last owner) its store queues one
//! row per replica in the same transaction, because the vault's federation settings, which name
//! the replicas, are deleted with it. The replication job sends each in the peer's next session and
//! deletes the row when the peer acknowledges.

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
                    .table("federation_erasures")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::big_integer("queued_at"))
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
