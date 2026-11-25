//! `custom_fields`: the fields an admin offers for the items.
//!
//! A row is a name, a type and the item types it applies to. None of it is secret, so it is kept in
//! the clear; the values live in the encrypted item bodies and never reach the server. `name_key`
//! is the name in lowercase, unique, so two fields can't differ only by case.

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
                    .table("custom_fields")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::string_len("name", 64))
                    .col(c::string_len_uniq("name_key", 256))
                    .col(c::string_len("field_type", 16))
                    .col(c::string_len("kinds", 256))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "updated_at", false))
                    .to_owned(),
            )
            .await
    }
}
