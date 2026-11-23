//! `passkeys` (an account's WebAuthn credentials and their PRF copy of the root key) and
//! `webauthn_challenges` (ceremonies that started and wait for the browser's answer).

use super::cols::time_col;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // The credential id is at most 1,023 bytes (WebAuthn) and unique across the server: a
        // discoverable sign-in names the credential, not the account. A `varbinary` keeps MySQL
        // able to index it. The credential column is the WebAuthn library's JSON of the public
        // key, counter and flags, far under 64 KiB.
        manager
            .create_table(
                Table::create()
                    .table("passkeys")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::var_binary_uniq("credential_id", 1023))
                    .col(c::string_len("name", 64))
                    .col(c::blob("credential"))
                    .col(c::blob_null("prf_wrapped_key"))
                    .col(c::big_integer_null("prf_key_version"))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "last_used_at", true))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkeys_user_id")
                            .from("passkeys", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_passkeys_user_id")
                    .table("passkeys")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // One state per account and kind: a new challenge replaces the one before it.
        manager
            .create_table(
                Table::create()
                    .table("webauthn_challenges")
                    .if_not_exists()
                    .col(c::uuid("user_id"))
                    .col(c::string_len("kind", 32))
                    .col(c::blob("state"))
                    .col(time_col(backend, "expires_at", false))
                    .primary_key(Index::create().col("user_id").col("kind"))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_webauthn_challenges_user_id")
                            .from("webauthn_challenges", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_webauthn_challenges_expires_at")
                    .table("webauthn_challenges")
                    .col("expires_at")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
