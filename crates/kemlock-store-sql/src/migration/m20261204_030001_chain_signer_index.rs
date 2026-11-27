//! An index on `space_chain_records (space_id, signer, at)`, for the quota of the chain append.
//!
//! Every append counts the records one account signed in the last hour and day in a space. Without
//! this index each count walks every record of the space, which one member could make long.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("idx_space_chain_records_signer_at")
                    .table("space_chain_records")
                    .col("space_id")
                    .col("signer")
                    .col("at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
