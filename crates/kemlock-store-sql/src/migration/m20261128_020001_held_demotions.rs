//! `vault_federation.held_demotion`: a promotion another server signed that would make it the home
//! of a vault this server is the home of. It waits there, not applied, until this server's admin
//! accepts it (`kemlock_federation::home::VaultFederation::held_demotion`).

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // `has_column` guards it: an `ADD COLUMN` that stopped half way on MySQL (no transactional
        // DDL) must be able to run again.
        if !manager
            .has_column("vault_federation", "held_demotion")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table("vault_federation")
                        .add_column(c::blob_null("held_demotion"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
