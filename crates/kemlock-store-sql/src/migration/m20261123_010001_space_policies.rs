//! `space_policies`: the policies of a space, beside the space rather than in it.
//!
//! One row per space that has had a policy set; a space with no row has none on. Today the one
//! policy is "Require SSO", which closes the password, passkey and device-approval ways in to the
//! space's members. Nothing points at `spaces` with a foreign key, like the other space tables.

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
                    .table("space_policies")
                    .if_not_exists()
                    .col(c::uuid("space_id").primary_key().take())
                    .col(c::boolean("require_sso"))
                    .to_owned(),
            )
            .await
    }
}
