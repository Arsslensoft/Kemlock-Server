//! `bw_user_key_ids`: the id of a Bitwarden account's user key, as its client reported it.
//!
//! Bitwarden clients from 2026.10 ask for it in `/api/sync` and, when the server holds none, send
//! it to `POST /api/accounts/key-management/user-key-id` once (Vaultwarden's `users.key_id`). An
//! account moved from Vaultwarden keeps its id in `bw_account_extras.key_id`, which is read first.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table("bw_user_key_ids")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::text("key_id"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_bw_user_key_ids_user_id")
                            .from("bw_user_key_ids", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
