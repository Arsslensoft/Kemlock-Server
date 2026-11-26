//! `peer_trusted_addresses`: the addresses of a peer the admin typed when pairing. Only these may
//! be dialled over `http` or on a private network; any other address a descriptor lists must be
//! `https` and public (`kemlock_federation::addr`).
//!
//! Nothing is copied in for the peers there are now: the stored addresses don't say which one the
//! admin typed. A peer whose address is refused gets an entry in the admin's list of address
//! changes the first time a connection to it is, and approving it trusts what it lists.

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
                    .table("peer_trusted_addresses")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::string_len("address", 512))
                    .primary_key(Index::create().col("peer").col("address"))
                    .to_owned(),
            )
            .await
    }
}
