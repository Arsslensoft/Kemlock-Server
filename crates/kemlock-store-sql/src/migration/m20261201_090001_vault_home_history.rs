//! `vault_federation.home_history`: the home of each earlier epoch of a vault, 24 bytes each
//! (`u64be(epoch)` and the server id), oldest first. A stale-epoch home record is kept only when
//! the server that signed it was the home of that epoch
//! (`kemlock_federation::home::VaultFederation::epoch_home`).

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
            .has_column("vault_federation", "home_history")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table("vault_federation")
                        .add_column(c::blob_null("home_history"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
