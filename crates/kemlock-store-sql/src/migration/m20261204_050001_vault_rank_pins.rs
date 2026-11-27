//! `vault_rank_pins`: the vaults this server ranks by revision for good. Once every server of a
//! vault's set has said it ranks by revision (`x-kemlock-signed-writes1`), the vault stays that
//! way here, whatever any server's descriptor says later: a server of the set that leaves the
//! capability out of its own descriptor can't turn rollback protection off for the others.

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
                    .table("vault_rank_pins")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::big_integer("pinned_at"))
                    .primary_key(Index::create().col("owner_type").col("owner_id"))
                    .to_owned(),
            )
            .await
    }
}
