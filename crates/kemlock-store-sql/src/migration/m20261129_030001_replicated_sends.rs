//! `federation_replicated_sends`: the Sends this server copied from another server of a vault. A
//! Send made on this server isn't listed here, so when the vault's home no longer holds a Send,
//! only a copy is deleted and a Send an owner made here stays.

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
                    .table("federation_replicated_sends")
                    .if_not_exists()
                    .col(c::uuid("send_id").primary_key().take())
                    // The server the copy came from.
                    .col(c::uuid("from_server"))
                    .to_owned(),
            )
            .await
    }
}
