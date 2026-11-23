//! `bw_devices`: what the Bitwarden API keeps of a device beyond its row: the identifier the app
//! signs in with, its Bitwarden device type, and the phone's registration with Bitwarden's push
//! relay (the relay's id for it and the push token).

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // One row per device; removing the device removes its row.
        manager
            .create_table(
                Table::create()
                    .table("bw_devices")
                    .if_not_exists()
                    .col(c::uuid("device_id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::uuid("identifier"))
                    .col(c::integer("device_type"))
                    .col(c::uuid_null("push_uuid"))
                    .col(c::text_null("push_token"))
                    .col(time_col(backend, "updated_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_bw_devices_device_id")
                            .from("bw_devices", "device_id")
                            .to("devices", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // `clear-token` finds devices by identifier; a push looks an account's phones up by user.
        manager
            .create_index(
                Index::create()
                    .name("idx_bw_devices_identifier")
                    .table("bw_devices")
                    .col("identifier")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_bw_devices_user")
                    .table("bw_devices")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
