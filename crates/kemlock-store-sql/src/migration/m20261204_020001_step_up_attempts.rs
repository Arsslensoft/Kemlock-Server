//! `step_up_attempts`: per account, the count of step-up proof attempts (a code or a security key's
//! answer that proves the owner before a sensitive change, and the admin console's step-up), with
//! the wait it earned.
//!
//! They shared the row of `second_step_attempts` with the sign-in second step, so anyone holding a
//! session could spend the owner's sign-in attempts by guessing at proofs and lock the owner's
//! second step. A row of their own keeps the two apart. Same shape; no row means no attempts, and
//! the row goes with the account.

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
                    .table("step_up_attempts")
                    .if_not_exists()
                    .col(c::uuid("user_id").primary_key().take())
                    .col(c::big_integer("window_start"))
                    .col(c::big_integer("count"))
                    .col(c::big_integer("level"))
                    .col(c::big_integer("blocked_until"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_step_up_attempts_user_id")
                            .from("step_up_attempts", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}
