//! `sends`: a note or file shared by a link. The server holds only ciphertext: the content a
//! recipient opens, the Send's key sealed for the owner, and the owner's name and notes. A file
//! Send's bytes are in blob storage under `file_blob_id`.
//!
//! A Send belongs to an account and goes with it. Its password is a salted hash of a value the
//! client derived. Two dates close it: `expires_at` stops access, `deletion_at` removes it.

use super::cols::{big_blob, time_col};
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
                    .table("sends")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("owner_id"))
                    .col(c::small_integer("kind"))
                    .col(c::blob("meta"))
                    .col(c::blob("sealed_key"))
                    .col(big_blob(backend, "payload", false))
                    .col(c::uuid_null("file_blob_id"))
                    .col(c::big_integer_null("file_size"))
                    .col(c::string_len_null("file_format", 16))
                    .col(c::boolean("file_ready"))
                    .col(c::blob_null("password_salt"))
                    .col(c::blob_null("password_hash"))
                    .col(c::big_integer_null("max_access"))
                    .col(c::big_integer("access_count"))
                    .col(c::boolean("hide_email"))
                    .col(c::boolean("disabled"))
                    .col(time_col(backend, "expires_at", true))
                    .col(time_col(backend, "deletion_at", false))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "revised_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sends_owner_id")
                            .from("sends", "owner_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // An account's Sends.
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_owner_id")
                    .table("sends")
                    .col("owner_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        // The job that deletes Sends reads the ones whose date has come.
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_deletion_at")
                    .table("sends")
                    .col("deletion_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
