//! `federation_withheld`: the versions of a vault that this server was told not to send one peer
//! (an account cancelled the changes waiting for a peer that was offline). `upto` is a version
//! vector cursor: a version it covers is left out of what the peer pulls. Nothing is deleted.

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
                    .table("federation_withheld")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::blob("upto"))
                    // Unix seconds of the last cancel.
                    .col(c::big_integer("at"))
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
