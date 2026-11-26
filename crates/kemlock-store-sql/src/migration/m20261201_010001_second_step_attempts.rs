//! `second_step_attempts`: per account, the count of second-step attempts (a code, a security key's
//! answer) that limits guessing, with the wait it earned.
//!
//! The count lived in each process's memory, so a restart forgot it and every replica of a
//! deployment kept its own. Here an attempt is reserved in one atomic step before the code is
//! looked at, whichever replica takes it. No row means no attempts; the row goes with the
//! account.

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
                    .table("second_step_attempts")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::big_integer("window_start"))
                    .col(c::big_integer("count"))
                    .col(c::big_integer("level"))
                    .col(c::big_integer("blocked_until"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_second_step_attempts_user_id")
                            .from("second_step_attempts", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
