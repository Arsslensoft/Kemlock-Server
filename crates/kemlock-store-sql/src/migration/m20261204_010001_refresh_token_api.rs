//! `refresh_tokens.api`: which API issued a refresh token (0 unknown, 1 Kemlock, 2 Bitwarden). The
//! two APIs share the table and the token form, and a Kemlock token is bound to a DPoP key while a
//! Bitwarden one is a bearer token, so each refuses the other's. A token that exists now has no
//! known origin and stays 0: the Bitwarden API takes it only for a device with no DPoP key.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Idempotent: a half-applied migration (MySQL commits DDL) must be able to run again.
        if !manager.has_column("refresh_tokens", "api").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table("refresh_tokens")
                        .add_column(c::small_integer("api").default(0).take())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
