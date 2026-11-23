//! `bw_docs`: the Bitwarden API's side documents (organization keys, member keys, policies, links
//! between ciphers and collections, equivalent domains), keyed by scope, kind and key.
//!
//! The scope is a space id or an account id and is not a foreign key, so removing an organization
//! or an account is the repository's job (`doc_delete_scope`), like the space tables around it.

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
                    .table("bw_docs")
                    .if_not_exists()
                    .col(c::uuid("scope"))
                    .col(c::string_len("kind", 32))
                    .col(c::string_len("doc_key", 255))
                    .col(c::text("body"))
                    .primary_key(Index::create().col("scope").col("kind").col("doc_key"))
                    .to_owned(),
            )
            .await?;
        // Documents of one kind and key in any scope: an invitation by email, say.
        manager
            .create_index(
                Index::create()
                    .name("idx_bw_docs_kind_key")
                    .table("bw_docs")
                    .col("kind")
                    .col("doc_key")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
