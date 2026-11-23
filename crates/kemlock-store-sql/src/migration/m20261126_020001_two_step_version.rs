//! `two_step_versions`: per account, a counter that moves whenever a two-step method is turned on
//! or off, the recovery code is spent or an admin resets the account's two-step login.
//!
//! A Bitwarden app's "remember this device" token carries the counter it was issued under, so a
//! change to the methods (as Vaultwarden does, by clearing the remembered devices) makes every
//! earlier token useless. No row means the counter is 0.

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
                    .table("two_step_versions")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::big_integer("version"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_two_step_versions_user_id")
                            .from("two_step_versions", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
