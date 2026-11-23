//! `learned_keys`: the identity keys of servers this server is not paired with, as a peer that
//! holds the same vault vouched for them, so the changes that peer relays from those servers can be
//! checked against their origin signatures.

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
                    .table("learned_keys")
                    .if_not_exists()
                    .col(c::uuid("server").primary_key().take())
                    // A `sig1` public key.
                    .col(c::blob("identity_key"))
                    // The peer that vouched for it.
                    .col(c::uuid("via"))
                    .col(c::big_integer("learned_at"))
                    .to_owned(),
            )
            .await
    }
}
