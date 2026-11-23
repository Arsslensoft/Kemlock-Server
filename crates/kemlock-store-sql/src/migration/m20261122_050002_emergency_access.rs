//! `emergency_access`: one row per grantor and contact.

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
                    .table("emergency_access")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("grantor_id"))
                    .col(c::string_len("grantee_email", 254))
                    .col(c::uuid_null("grantee_id"))
                    .col(c::string_len("kind", 16))
                    .col(c::big_integer("wait_days"))
                    .col(c::string_len("state", 24))
                    .col(c::blob_null("sealed_key"))
                    .col(time_col(backend, "recovery_initiated_at", true))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "updated_at", false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_emergency_access_grantor_id")
                            .from("emergency_access", "grantor_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_emergency_access_grantee_id")
                            .from("emergency_access", "grantee_id")
                            .to("users", "id")
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_emergency_access_grantor_email")
                    .table("emergency_access")
                    .col("grantor_id")
                    .col("grantee_email")
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_emergency_access_grantee_email")
                    .table("emergency_access")
                    .col("grantee_email")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_emergency_access_state")
                    .table("emergency_access")
                    .col("state")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
