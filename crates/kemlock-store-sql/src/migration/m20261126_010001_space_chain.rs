//! The space chain's tables (docs/crypto.md, "Space chain"): `space_chain_records`, the append-only
//! list of a space's signed records; `space_chain_seals` and `space_chain_names`, the boxes and
//! sealed names the records committed, by `seq`; `space_chain_pending`, changes from outside
//! Kemlock clients kept for a space's admins to sign; and `space_held_items`, the live items a
//! key replacement left held.
//!
//! Nothing is ever updated or deleted in the first three while the space exists.

use super::cols::big_blob;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        manager
            .create_table(
                Table::create()
                    .table("space_chain_records")
                    .if_not_exists()
                    .col(c::uuid("space_id"))
                    .col(c::big_integer("seq"))
                    // The record's link (32 bytes), its epoch, its signer and its `at`.
                    .col(c::blob("link"))
                    .col(c::big_integer("epoch"))
                    .col(c::uuid("signer"))
                    .col(c::big_integer("at"))
                    // The exact record bytes (up to 192 KiB) and their signatures.
                    .col(big_blob(backend, "entry", false))
                    .col(c::blob("signature"))
                    .col(c::blob_null("cosignature"))
                    .primary_key(Index::create().col("space_id").col("seq"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("space_chain_seals")
                    .if_not_exists()
                    .col(c::uuid("space_id"))
                    .col(c::big_integer("seq"))
                    // `space` or `collection:<uuid>`.
                    .col(c::string_len("key_ref", 64))
                    .col(c::big_integer("version"))
                    .col(c::uuid("member"))
                    .col(c::big_integer("bundle_version"))
                    // The 1661-byte sealed box.
                    .col(c::blob("sealed"))
                    .primary_key(
                        Index::create()
                            .col("space_id")
                            .col("seq")
                            .col("key_ref")
                            .col("version")
                            .col("member"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("space_chain_names")
                    .if_not_exists()
                    .col(c::uuid("space_id"))
                    .col(c::big_integer("seq"))
                    // `space`, `collection:<uuid>` or `group:<uuid>`.
                    .col(c::string_len("target", 64))
                    .col(c::big_integer("version"))
                    .col(c::blob("name_hash"))
                    .col(c::blob("sealed"))
                    .primary_key(Index::create().col("space_id").col("seq").col("target"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("space_chain_pending")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("space_id"))
                    .col(c::string_len("kind", 32))
                    .col(c::uuid_null("subject"))
                    .col(c::text("detail"))
                    .col(c::big_integer("at"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_space_chain_pending_space_id")
                    .table("space_chain_pending")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("space_held_items")
                    .if_not_exists()
                    .col(c::uuid("item_id").primary_key().take())
                    .col(c::uuid("space_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_space_held_items_space_id")
                    .table("space_held_items")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
