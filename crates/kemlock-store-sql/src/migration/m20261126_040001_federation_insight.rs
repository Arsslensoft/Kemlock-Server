//! `peer_security` and `peer_mismatches`: what this server last learned of each peer's published
//! descriptor and KEM key, and the peers that offered an identity key other than the pinned one.

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
                    .table("peer_security")
                    .if_not_exists()
                    .col(c::uuid("peer").primary_key().take())
                    // The signed descriptor as the peer served it, kept after it verified.
                    .col(c::blob("descriptor"))
                    .col(c::big_integer("fetched_at"))
                    // `kem_key_id` of its KEM key, and when this server first saw that key.
                    .col(c::blob("kem_key_id"))
                    .col(c::big_integer("kem_first_seen"))
                    .col(c::string_len_null("suite", 64))
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table("peer_mismatches")
                    .if_not_exists()
                    .col(c::uuid("peer").primary_key().take())
                    .col(c::blob("offered_key"))
                    .col(c::big_integer("first_at"))
                    .col(c::big_integer("last_at"))
                    .col(c::big_integer("attempts"))
                    // The address this server dialled when it met the key.
                    .col(c::string_len("source", 256))
                    .col(c::big_integer_null("kept_blocking_at"))
                    .col(c::string_len_null("kept_blocking_by", 128))
                    .to_owned(),
            )
            .await
    }
}
