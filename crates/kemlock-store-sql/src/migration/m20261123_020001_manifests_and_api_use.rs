//! `signed_manifests` (the latest signed manifest of each owner) and `device_api_use` (when each
//! device last used the Kemlock API and the Bitwarden API).

use super::cols::{big_blob, time_col};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // The owner is its wire text, `user:<uuid>` or `space:<uuid>`, so a space's manifest needs
        // no new table. Only an account's own manifest is written for now, and an account that is
        // removed takes its manifests with it.
        manager
            .create_table(
                Table::create()
                    .table("signed_manifests")
                    .if_not_exists()
                    .col(c::string_len("owner", 48).primary_key().take())
                    .col(c::big_integer("counter"))
                    .col(big_blob(backend, "manifest", false))
                    .col(c::blob("signature"))
                    .col(c::uuid("signer_id"))
                    .col(time_col(backend, "stored_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_signed_manifests_signer_id")
                            .from("signed_manifests", "signer_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("device_api_use")
                    .if_not_exists()
                    .col(c::uuid("device_id").primary_key().take())
                    .col(time_col(backend, "kemlock_used_at", true))
                    .col(time_col(backend, "bitwarden_used_at", true))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_device_api_use_device_id")
                            .from("device_api_use", "device_id")
                            .to("devices", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
