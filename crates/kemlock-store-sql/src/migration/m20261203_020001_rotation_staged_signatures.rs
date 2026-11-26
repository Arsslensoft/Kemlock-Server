//! Signed rotations (docs/crypto.md, "Rotating the root key"): `rotation_staged_items.write_sig`
//! holds the account's signature of the write a rotation makes of a staged item, by the new keys
//! (`writer (16) ‖ u32be(key version) ‖ signature`), until the install checks it and keeps it with
//! the item. Null for an item staged without one, which a vault that takes signed writes only
//! refuses at the install.

use super::cols::big_blob;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        if !manager
            .has_column("rotation_staged_items", "write_sig")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table("rotation_staged_items")
                        .add_column(big_blob(backend, "write_sig", true))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
