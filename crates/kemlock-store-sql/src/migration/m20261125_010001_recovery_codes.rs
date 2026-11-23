//! `two_factor_recovery`: an account's two-step recovery code, one row per account.
//!
//! Vaultwarden keeps it in `users.totp_recover`. An account moved from Vaultwarden keeps its code
//! in `bw_account_extras.sealed_totp_recover`, which is read until the code is spent; this table
//! holds the codes made here, sealed under `server.key`.

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
                    .table("two_factor_recovery")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::blob("sealed_code"))
                    .col(time_col(backend, "created_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_two_factor_recovery_user_id")
                            .from("two_factor_recovery", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
