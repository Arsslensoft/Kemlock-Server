//! `vw_import_ids`: the user and space ids the move from Vaultwarden created.
//!
//! The importer writes by Vaultwarden's own ids, so without a record of which ids it made it could
//! rewrite an account or a space that was never Vaultwarden's. A pass takes an id only when no row
//! of that id exists yet, or when this table says an earlier pass created it; anything else is
//! refused and reported. The rows carry no foreign key: an account or space that is later erased
//! leaves its mark behind, which only means that id is the import's if it ever came back.

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
                    .table("vw_import_ids")
                    .if_not_exists()
                    // `user` or `space`.
                    .col(c::string_len("kind", 16))
                    .col(c::uuid("id"))
                    .col(time_col(backend, "imported_at", false))
                    .primary_key(Index::create().col("kind").col("id"))
                    .to_owned(),
            )
            .await
    }
}
