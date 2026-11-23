//! `space_policy_settings`: one row per space, a column per typed setting (see
//! `kemlock_domain::policies::SpacePolicies`). A space with no row has everything off.
//!
//! Nothing points at `spaces` with a foreign key, as with the other space tables.

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
                    .table("space_policy_settings")
                    .if_not_exists()
                    .col(c::uuid("space_id").primary_key().take())
                    .col(c::boolean("require_sso"))
                    .col(c::boolean("two_step"))
                    .col(c::boolean("single_space"))
                    .col(c::boolean("disable_export"))
                    .col(c::boolean("disable_send"))
                    .col(c::boolean("always_show_email"))
                    .col(c::boolean("no_pin_unlock"))
                    .col(c::boolean("central_ownership"))
                    .col(c::boolean("no_card_items"))
                    // The master password rules: `mp_on` says whether there are any.
                    .col(c::boolean("mp_on"))
                    .col(c::big_integer_null("mp_min_length"))
                    .col(c::small_integer_null("mp_min_complexity"))
                    .col(c::boolean("mp_require_upper"))
                    .col(c::boolean("mp_require_lower"))
                    .col(c::boolean("mp_require_numbers"))
                    .col(c::boolean("mp_require_special"))
                    .col(c::boolean("mp_enforce_on_login"))
                    // The session timeout, when there is one.
                    .col(c::big_integer_null("timeout_minutes"))
                    .col(c::string_len_null("timeout_action", 8))
                    .col(time_col(backend, "updated_at", false))
                    .col(c::uuid_null("updated_by"))
                    .to_owned(),
            )
            .await
    }
}
