//! `items`, `changes` and `sync_horizon` (per owner and origin): the vault's rows and the log that
//! syncs them.

use super::cols::{big_blob, time_col};
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
                    .table("items")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::string_len("kind", 64))
                    .col(c::string_len("format", 16))
                    .col(c::big_integer("revision"))
                    .col(c::big_integer("key_version"))
                    .col(big_blob(backend, "ciphertext", true))
                    .col(c::blob_null("item_key"))
                    .col(time_col(backend, "deleted_at", true))
                    .col(time_col(backend, "updated_at", false))
                    .col(c::uuid("origin"))
                    .col(c::big_integer("seq"))
                    .col(c::big_integer("hlc"))
                    .to_owned(),
            )
            .await?;
        // One change per (origin, seq): a sequence number is never reused.
        manager
            .create_index(
                Index::create()
                    .name("uq_items_origin_seq")
                    .table("items")
                    .col("origin")
                    .col("seq")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        // A delta sync reads one owner's items in (origin, seq) order.
        manager
            .create_index(
                Index::create()
                    .name("idx_items_owner_origin_seq")
                    .table("items")
                    .col("owner_type")
                    .col("owner_id")
                    .col("origin")
                    .col("seq")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        // The tombstone purge finds old deletions.
        manager
            .create_index(
                Index::create()
                    .name("idx_items_deleted_at")
                    .table("items")
                    .col("deleted_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("changes")
                    .if_not_exists()
                    .col(c::uuid("origin"))
                    .col(c::big_integer("seq"))
                    .col(c::big_integer("hlc"))
                    .col(c::uuid("item_id"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::big_integer("revision"))
                    .col(c::boolean("deleted"))
                    .col(time_col(backend, "at", false))
                    .primary_key(Index::create().col("origin").col("seq"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_changes_owner_origin_seq")
                    .table("changes")
                    .col("owner_type")
                    .col("owner_id")
                    .col("origin")
                    .col("seq")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("sync_horizon")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::uuid("origin"))
                    .col(c::big_integer("purged_through"))
                    .primary_key(
                        Index::create()
                            .col("owner_type")
                            .col("owner_id")
                            .col("origin"),
                    )
                    .to_owned(),
            )
            .await
    }
}
