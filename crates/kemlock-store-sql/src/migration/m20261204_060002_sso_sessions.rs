//! `sso_sessions`: the devices an SSO sign-in started, with the identity (issuer and subject) and
//! the provider's session id (`sid`) that signed each in. A back-channel logout ends exactly these
//! devices. Before this table it ended every device of the account the subject was linked to,
//! so anyone who held a provider identity linked to an account could sign its owner out of every
//! device, whatever way each had signed in.
//!
//! One row per device. Devices that were signed in by SSO before the table existed have no row, so
//! a logout does not end them.

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
                    .table("sso_sessions")
                    .if_not_exists()
                    .col(c::uuid("device_id").primary_key().take())
                    .col(c::uuid("user_id"))
                    .col(c::string_len("issuer", 255))
                    .col(c::string_len("subject", 255))
                    .col(c::string_len_null("session_id", 255))
                    .col(time_col(backend, "started_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sso_sessions_user_id")
                            .from("sso_sessions", "user_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        // A logout token names a subject, a session id, or both.
        manager
            .create_index(
                Index::create()
                    .name("idx_sso_sessions_subject")
                    .table("sso_sessions")
                    .col("issuer")
                    .col("subject")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sso_sessions_session_id")
                    .table("sso_sessions")
                    .col("issuer")
                    .col("session_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sso_sessions_user_id")
                    .table("sso_sessions")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
