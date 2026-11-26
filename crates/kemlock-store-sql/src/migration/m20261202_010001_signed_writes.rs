//! Signed item writes (docs/crypto.md, "Signed item writes"): `items.write_sig` and
//! `item_siblings.write_sig` hold the writing account's signature of a `kem1` revision
//! (`writer (16) ‖ u32be(key version) ‖ signature`), and `signed_writes` lists the owners that
//! accept signed writes only.
//!
//! Nothing is filled in for what is stored now: those revisions were written unsigned, and an
//! owner becomes signed-only with its first signed write.

use super::cols::{big_blob, time_col};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        for table in ["items", "item_siblings"] {
            if !manager.has_column(table, "write_sig").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(table)
                            .add_column(big_blob(backend, "write_sig", true))
                            .to_owned(),
                    )
                    .await?;
            }
        }

        manager
            .create_table(
                Table::create()
                    .table("signed_writes")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(time_col(backend, "since", false))
                    .primary_key(Index::create().col("owner_type").col("owner_id"))
                    .to_owned(),
            )
            .await
    }
}
