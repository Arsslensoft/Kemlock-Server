//! `sso_identities.confirmed`: whether the provider's `amr` may stand in for the account's own
//! second step at sign-in. Every identity that exists now is confirmed (they were trusted so before
//! this column); a link made to an account that has a second step is written unconfirmed.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        if !manager.has_column("sso_identities", "confirmed").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table("sso_identities")
                        .add_column(c::boolean("confirmed").default(true).take())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
