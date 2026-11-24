//! `recovery_kits`: an account's Recovery Kit record, one row per account.
//!
//! The row holds the non-secret facts: the kit id, the key version the wrap is for, the root key
//! wrapped under the kit key and when it was made. The pieces and the kit key never reach the
//! server.

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
                    .table("recovery_kits")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::string_len("kit_id", 8))
                    .col(c::blob("wrapped_key"))
                    .col(c::big_integer("key_version"))
                    .col(time_col(backend, "created_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_recovery_kits_user_id")
                            .from("recovery_kits", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
