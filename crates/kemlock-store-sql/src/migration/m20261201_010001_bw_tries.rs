//! `bw_tries`: per account and kind of secret, the tries made in the current window. The
//! Bitwarden API counts a try before it checks a second-step code or answers a request for an
//! emailed code, so an attacker can't guess at the speed of the network, from many addresses or
//! across a restart. The rows go with the account.

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
                    .table("bw_tries")
                    .if_not_exists()
                    .col(c::uuid("user_id"))
                    .col(c::string_len("kind", 24))
                    .col(c::big_integer("tries"))
                    .col(c::big_integer("window_start"))
                    .primary_key(Index::create().col("user_id").col("kind"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_bw_tries_user_id")
                            .from("bw_tries", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
