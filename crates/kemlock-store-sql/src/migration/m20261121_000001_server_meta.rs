//! `server_meta` (this server's identity and counters) and `job_leases`.

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// `job_leases` is also created before the migrations run, because the migration lock is a row
/// in it; `if_not_exists` makes the two creations agree.
pub(crate) fn job_leases_table(backend: DbBackend) -> TableCreateStatement {
    Table::create()
        .table("job_leases")
        .if_not_exists()
        .col(c::string_len("name", 64).primary_key().take())
        .col(c::string_len("holder", 64))
        .col(time_col(backend, "expires_at", false))
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        manager
            .create_table(
                Table::create()
                    .table("server_meta")
                    .if_not_exists()
                    .col(c::integer("id").primary_key().take())
                    .col(c::uuid("server_id"))
                    .col(time_col(backend, "created_at", false))
                    .col(c::big_integer("next_seq"))
                    .col(c::big_integer("last_hlc"))
                    .to_owned(),
            )
            .await?;

        manager.create_table(job_leases_table(backend)).await
    }
}
