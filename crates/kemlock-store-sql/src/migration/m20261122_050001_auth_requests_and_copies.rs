//! `auth_requests` (pending device approvals) and `device_key_copies` (trusted-device copies of
//! the root key, one per device).

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
                    .table("auth_requests")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::uuid("device_id"))
                    .col(c::string_len("device_name", 255))
                    .col(c::string_len("device_kind", 32))
                    .col(c::blob("public_key"))
                    .col(c::string_len("jkt", 128))
                    .col(c::string_len("ip", 64))
                    .col(c::string_len("state", 16))
                    .col(c::blob_null("sealed_key"))
                    .col(time_col(backend, "answered_at", true))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "expires_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_auth_requests_user_id")
                            .from("auth_requests", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_requests_user_id_created_at")
                    .table("auth_requests")
                    .col("user_id")
                    .col("created_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_requests_expires_at")
                    .table("auth_requests")
                    .col("expires_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("device_key_copies")
                    .if_not_exists()
                    .col(c::uuid("device_id").primary_key().take())
                    .col(c::blob("wrapped_key"))
                    .col(c::string_len("protection", 32))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "updated_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_device_key_copies_device_id")
                            .from("device_key_copies", "device_id")
                            .to("devices", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
