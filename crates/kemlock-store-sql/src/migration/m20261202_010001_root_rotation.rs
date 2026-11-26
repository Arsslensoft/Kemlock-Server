//! Rotating the root key (docs/crypto.md, "Rotating the root key").
//!
//! `rotation_staged_items` holds the items a client re-encrypted under the new root key until the
//! install moves them onto the live items in one transaction: one row per account and item, tied to
//! the rotation attempt that staged it. `rotation_previous_keys` keeps an account's private keys
//! from before the last rotation, sealed under the new user key, until the client says its spaces
//! have moved to the new keys.

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
                    .table("rotation_staged_items")
                    .if_not_exists()
                    .col(c::uuid("user_id"))
                    .col(c::uuid("item_id"))
                    // The 16 random bytes of the rotation attempt, as a UUID's bytes.
                    .col(c::uuid("rotation_id"))
                    // The revision the client read; the item is written at the next one.
                    .col(c::big_integer("base_revision"))
                    .col(big_blob(backend, "ciphertext", false))
                    .col(c::blob("item_key"))
                    .col(time_col(backend, "staged_at", false))
                    .primary_key(Index::create().col("user_id").col("item_id"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_rotation_staged_items_user_id")
                            .from("rotation_staged_items", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table("rotation_previous_keys")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    // The key version the sealed pair was the account's.
                    .col(c::big_integer("key_version"))
                    .col(c::blob("sealed"))
                    .col(time_col(backend, "created_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_rotation_previous_keys_user_id")
                            .from("rotation_previous_keys", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
