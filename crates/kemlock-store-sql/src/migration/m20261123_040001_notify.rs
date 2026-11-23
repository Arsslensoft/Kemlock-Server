//! `push_tokens` (a device's token for the push relay) and `live_nudges` (the small log replicas
//! on MySQL poll to nudge each other's sockets). The relay installation is two `settings` rows.

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // One token per device; signing the device out deletes it.
        manager
            .create_table(
                Table::create()
                    .table("push_tokens")
                    .if_not_exists()
                    .col(c::uuid("device_id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::string_len("kind", 8))
                    .col(c::string_len("token", 512))
                    .col(time_col(backend, "updated_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_push_tokens_device_id")
                            .from("push_tokens", "device_id")
                            .to("devices", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_push_tokens_user")
                    .table("push_tokens")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Appended on every commit and read by id, so a replica that polls once a second sees
        // each entry once. Rows older than a minute are pruned.
        manager
            .create_table(
                Table::create()
                    .table("live_nudges")
                    .if_not_exists()
                    .col(c::big_pk_auto("id"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(time_col(backend, "created_at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_live_nudges_created")
                    .table("live_nudges")
                    .col("created_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
