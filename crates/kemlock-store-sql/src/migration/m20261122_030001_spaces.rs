//! `spaces`, `members`, `groups`, `group_members`, `collections`, `collection_grants`,
//! `collection_keys` and `item_collections`.
//!
//! A space owns its members (each with its role, state, the space key sealed to it and the
//! confirmer's signed statement), groups and collections. Collections nest by `parent_id` and
//! carry their own key version; `collection_keys` holds each collection's key sealed to every
//! member who may hold it; `collection_grants` says who may. `item_collections` records which
//! collection a space item is in, beside `items` rather than in it. Nothing here points at the
//! other tables with a foreign key: removing a member, group or collection deletes its rows in
//! the same transaction (see the repository).

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
                    .table("spaces")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::blob("name"))
                    .col(c::big_integer("key_version"))
                    .col(time_col(backend, "keys_pending_since", true))
                    .col(time_col(backend, "created_at", false))
                    .col(time_col(backend, "updated_at", false))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("members")
                    .if_not_exists()
                    .col(c::uuid("space_id"))
                    .col(c::uuid("user_id"))
                    .col(c::string_len("role", 16))
                    .col(c::big_integer("custom_permissions"))
                    .col(c::string_len("state", 16))
                    .col(c::uuid("invited_by"))
                    .col(time_col(backend, "invited_at", false))
                    .col(time_col(backend, "accepted_at", true))
                    .col(c::blob_null("sealed_space_key"))
                    .col(c::big_integer_null("key_version"))
                    .col(time_col(backend, "revoked_at", true))
                    .col(c::uuid_null("confirmed_by"))
                    .col(time_col(backend, "confirmed_at", true))
                    .col(c::blob_null("confirmed_fingerprint"))
                    .col(c::big_integer_null("confirmed_key_version"))
                    .col(c::blob_null("confirmation_statement"))
                    .col(c::blob_null("confirmation_signature"))
                    .primary_key(Index::create().col("space_id").col("user_id"))
                    .to_owned(),
            )
            .await?;
        // An account's spaces.
        manager
            .create_index(
                Index::create()
                    .name("idx_members_user_id")
                    .table("members")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("groups")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("space_id"))
                    .col(c::blob("name"))
                    .col(time_col(backend, "created_at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_groups_space_id")
                    .table("groups")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("group_members")
                    .if_not_exists()
                    .col(c::uuid("group_id"))
                    .col(c::uuid("user_id"))
                    .primary_key(Index::create().col("group_id").col("user_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_members_user_id")
                    .table("group_members")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("collections")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::uuid("space_id"))
                    .col(c::uuid_null("parent_id"))
                    .col(c::blob("name"))
                    .col(c::big_integer("key_version"))
                    .col(time_col(backend, "stale_since", true))
                    .col(time_col(backend, "created_at", false))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_collections_space_id")
                    .table("collections")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("collection_grants")
                    .if_not_exists()
                    .col(c::uuid("collection_id"))
                    .col(c::small_integer("grantee_type"))
                    .col(c::uuid("grantee_id"))
                    .col(c::string_len("permission", 32))
                    .primary_key(
                        Index::create()
                            .col("collection_id")
                            .col("grantee_type")
                            .col("grantee_id"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("collection_keys")
                    .if_not_exists()
                    .col(c::uuid("collection_id"))
                    .col(c::uuid("user_id"))
                    .col(c::big_integer("key_version"))
                    .col(c::blob("sealed"))
                    .primary_key(Index::create().col("collection_id").col("user_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_collection_keys_user_id")
                    .table("collection_keys")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table("item_collections")
                    .if_not_exists()
                    .col(c::uuid("item_id").primary_key().take())
                    .col(c::uuid("space_id"))
                    .col(c::uuid("collection_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_item_collections_space_id")
                    .table("item_collections")
                    .col("space_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_item_collections_collection_id")
                    .table("item_collections")
                    .col("collection_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
