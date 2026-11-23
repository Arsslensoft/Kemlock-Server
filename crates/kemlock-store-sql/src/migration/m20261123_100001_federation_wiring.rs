//! `peer_acknowledgements`, `vault_offers` and `replicated_accounts`: what an admin acknowledged
//! when pairing, the vaults other homes offered this server, and which accounts here are copies
//! of a home's.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The three acknowledgements an admin gives for a peer run by another operator, kept as
        // the record of the data sharing.
        manager
            .create_table(
                Table::create()
                    .table("peer_acknowledgements")
                    .if_not_exists()
                    .col(c::uuid("peer").primary_key().take())
                    .col(c::boolean("metadata"))
                    .col(c::boolean("deletion"))
                    .col(c::boolean("cross_border"))
                    .col(c::string_len("acknowledged_by", 128))
                    .col(c::big_integer("acknowledged_at"))
                    .to_owned(),
            )
            .await?;

        // A vault a home offered this server, until its admin answers.
        manager
            .create_table(
                Table::create()
                    .table("vault_offers")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::uuid("home"))
                    .col(c::big_integer("epoch"))
                    .col(c::blob("replicas"))
                    .col(c::string_len("state", 16))
                    .col(c::big_integer("received_at"))
                    .primary_key(Index::create().col("owner_type").col("owner_id"))
                    .to_owned(),
            )
            .await?;

        // An account here that is a copy of one at another server (a federated vault's member):
        // it has no OPAQUE record and signs in with its device keys.
        manager
            .create_table(
                Table::create()
                    .table("replicated_accounts")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::uuid("home"))
                    .col(c::big_integer("synced_at"))
                    .to_owned(),
            )
            .await
    }
}
