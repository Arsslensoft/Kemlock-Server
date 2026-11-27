//! `peer_held_rotations`: an identity-key rotation a peer signed, held for this server's admin. A
//! rotation is signed by the key it replaces, which may be stolen, so it pins nothing until the
//! admin confirms it.

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
                    .table("peer_held_rotations")
                    .if_not_exists()
                    .col(c::uuid("server"))
                    // SHA-256 of the new identity key, in hex: tells two rotations of one server
                    // apart.
                    .col(c::string_len("fingerprint", 64))
                    .col(c::big_integer("issued_at"))
                    .col(c::big_integer("received_at"))
                    .col(c::blob("envelope"))
                    .primary_key(Index::create().col("server").col("fingerprint"))
                    .to_owned(),
            )
            .await
    }
}
