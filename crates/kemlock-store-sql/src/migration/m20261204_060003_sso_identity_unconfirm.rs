//! Marks the SSO links of accounts that have a second step unconfirmed.
//!
//! `m20261201_040001_sso_identity_confirmed` added `sso_identities.confirmed` with every existing
//! identity confirmed, because they were all trusted before the column. That includes a link an
//! SSO sign-in made to an account that had a second step, which the provider's `amr` could then
//! stand in for: the link may have been made by whoever held an identity at the provider with the
//! account's email, and abandoned at the second-step challenge. From now on such a link is
//! unconfirmed, so that account's own second step is asked at each SSO sign-in with it.
//!
//! Running it again changes nothing.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sso_identities SET confirmed = false \
                 WHERE user_id IN (SELECT user_id FROM two_factor WHERE enabled = true)",
            )
            .await?;
        Ok(())
    }
}
