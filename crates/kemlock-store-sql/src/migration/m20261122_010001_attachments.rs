//! `attachments`: one row per file attached to an item, with the random id its bytes are stored
//! under in blob storage.
//!
//! There is no foreign key to `items`: a client uploads its files before it writes the item, so
//! a row may name an item that doesn't exist yet. The orphan purge removes rows whose item never
//! came or was purged.

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
                    .table("attachments")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("item_id"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::uuid("blob_id"))
                    .col(c::big_integer("size"))
                    .col(c::string_len("status", 16))
                    .col(time_col(backend, "created_at", false))
                    .to_owned(),
            )
            .await?;
        // Each blob belongs to one attachment.
        manager
            .create_index(
                Index::create()
                    .name("uq_attachments_blob_id")
                    .table("attachments")
                    .col("blob_id")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        // An item's files.
        manager
            .create_index(
                Index::create()
                    .name("idx_attachments_item_id")
                    .table("attachments")
                    .col("item_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        // The orphan purge reads the oldest rows first.
        manager
            .create_index(
                Index::create()
                    .name("idx_attachments_created_at")
                    .table("attachments")
                    .col("created_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
