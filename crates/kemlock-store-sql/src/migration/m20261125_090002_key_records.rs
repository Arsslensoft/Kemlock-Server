//! `key_records`: the newest signed rotation and revocation of each server's identity key that
//! this server holds, to pass on to its other peers.

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
                    .table("key_records")
                    .if_not_exists()
                    .col(c::uuid("server"))
                    // `rotation` or `revocation`.
                    .col(c::string_len("kind", 16))
                    .col(c::big_integer("issued_at"))
                    // The signed envelope, as it was received.
                    .col(c::blob("envelope"))
                    .primary_key(Index::create().col("server").col("kind"))
                    .to_owned(),
            )
            .await
    }
}
