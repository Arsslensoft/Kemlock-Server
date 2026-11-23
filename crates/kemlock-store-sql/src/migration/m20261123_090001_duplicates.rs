//! `item_tags`, `duplicate_dismissals` and `dedup_owners`: the duplicate cleaner's server side.
//!
//! `item_tags` holds the 32-byte tags a device uploads, keyed by (owner, tag, item), with the item
//! revision and dedup key version they were made for. Nothing here points at `items` with a
//! foreign key: a write clears the item's tags in its own transaction, and the group query only
//! counts a tag whose revision is the item's current one, so a tag can't outlive its revision.
//!
//! `dedup_owners` is the per-owner state the design puts in a `dedup_version` column of `users`
//! and `spaces`, plus the switch for server matching. It is a table keyed by owner so those two
//! tables and their types stay as they are; an owner with no row is at version 1 with matching
//! off.

use super::cols::time_col;
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
                    .table("item_tags")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::binary_len("tag", 32))
                    .col(c::uuid("item_id"))
                    .col(c::big_integer("item_revision"))
                    .col(c::big_integer("key_version"))
                    .primary_key(
                        Index::create()
                            .col("owner_type")
                            .col("owner_id")
                            .col("tag")
                            .col("item_id"),
                    )
                    .to_owned(),
            )
            .await?;
        // Replacing or clearing one item's tags.
        manager
            .create_index(
                Index::create()
                    .name("idx_item_tags_item_id")
                    .table("item_tags")
                    .col("item_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("duplicate_dismissals")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    // The group's item ids, 16 bytes each, sorted: at most 500 of them.
                    .col(c::blob("item_ids"))
                    .col(c::uuid("answered_by"))
                    .col(time_col(backend, "answered_at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_duplicate_dismissals_owner")
                    .table("duplicate_dismissals")
                    .col("owner_type")
                    .col("owner_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("dedup_owners")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::big_integer("dedup_version"))
                    .col(c::boolean("server_matching"))
                    .col(c::uuid_null("changed_by"))
                    .col(time_col(backend, "changed_at", true))
                    .primary_key(Index::create().col("owner_type").col("owner_id"))
                    .to_owned(),
            )
            .await
    }
}
