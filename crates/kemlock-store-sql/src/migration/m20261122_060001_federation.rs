//! `peers`, `vault_federation`, `item_siblings`, `peer_log_switches`, `peer_cursors`,
//! `change_meta` and `home_records`: what federation keeps beside the items and the change log.

use super::cols::big_blob;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // The servers this one is paired with. The identity key is pinned at pairing.
        manager
            .create_table(
                Table::create()
                    .table("peers")
                    .if_not_exists()
                    .col(c::uuid("id").primary_key().take())
                    .col(c::string_len("operator", 128))
                    .col(c::blob("identity_key"))
                    .col(c::text("addresses"))
                    .col(c::text("suites"))
                    .col(c::string_len("state", 16))
                    .col(c::big_integer("paired_at"))
                    .col(c::big_integer_null("last_seen"))
                    .to_owned(),
            )
            .await?;

        // How each federated vault is set up: policy, home, epoch and replica order.
        manager
            .create_table(
                Table::create()
                    .table("vault_federation")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::string_len("policy", 16))
                    .col(c::uuid("home"))
                    .col(c::big_integer("epoch"))
                    .col(c::blob("replicas"))
                    .col(c::blob_null("promotion"))
                    .primary_key(Index::create().col("owner_type").col("owner_id"))
                    .to_owned(),
            )
            .await?;

        // Versions of an item held beside its head, after a conflict.
        manager
            .create_table(
                Table::create()
                    .table("item_siblings")
                    .if_not_exists()
                    .col(c::uuid("origin"))
                    .col(c::big_integer("seq"))
                    .col(c::uuid("item_id"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::string_len("kind", 64))
                    .col(c::string_len("format", 16))
                    .col(c::big_integer("revision"))
                    .col(c::big_integer("key_version"))
                    .col(big_blob(backend, "ciphertext", true))
                    .col(c::blob_null("item_key"))
                    .col(c::boolean("deleted"))
                    .col(c::big_integer("updated_at_ms"))
                    .col(c::big_integer("hlc"))
                    .primary_key(Index::create().col("origin").col("seq"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_item_siblings_item")
                    .table("item_siblings")
                    .col("item_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_item_siblings_owner_origin_seq")
                    .table("item_siblings")
                    .col("owner_type")
                    .col("owner_id")
                    .col("origin")
                    .col("seq")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // The two event-log switches of a peer, both off until an admin turns them on.
        manager
            .create_table(
                Table::create()
                    .table("peer_log_switches")
                    .if_not_exists()
                    .col(c::uuid("peer").primary_key().take())
                    .col(c::boolean("send"))
                    .col(c::boolean("pull"))
                    .to_owned(),
            )
            .await?;

        // What has been pulled from each peer, per vault.
        manager
            .create_table(
                Table::create()
                    .table("peer_cursors")
                    .if_not_exists()
                    .col(c::uuid("peer"))
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::blob("cursor_bytes"))
                    .primary_key(
                        Index::create()
                            .col("peer")
                            .col("owner_type")
                            .col("owner_id"),
                    )
                    .to_owned(),
            )
            .await?;

        // The lineage and the origin's signature of a change, kept so it can be relayed.
        manager
            .create_table(
                Table::create()
                    .table("change_meta")
                    .if_not_exists()
                    .col(c::uuid("origin"))
                    .col(c::big_integer("seq"))
                    .col(c::blob("lineage"))
                    .col(c::blob_null("signature"))
                    .primary_key(Index::create().col("origin").col("seq"))
                    .to_owned(),
            )
            .await?;
        // Working out a local change's lineage reads the log of one item in HLC order.
        manager
            .create_index(
                Index::create()
                    .name("idx_changes_item_hlc")
                    .table("changes")
                    .col("item_id")
                    .col("hlc")
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Home-only writes, applied or quarantined by epoch.
        manager
            .create_table(
                Table::create()
                    .table("home_records")
                    .if_not_exists()
                    .col(c::small_integer("owner_type"))
                    .col(c::uuid("owner_id"))
                    .col(c::big_integer("idx"))
                    .col(c::big_integer("epoch"))
                    .col(c::string_len("kind", 64))
                    .col(big_blob(backend, "payload", false))
                    .col(c::uuid("signer"))
                    .col(big_blob(backend, "envelope", false))
                    .col(c::string_len("status", 16))
                    .primary_key(Index::create().col("owner_type").col("owner_id").col("idx"))
                    .to_owned(),
            )
            .await
    }
}
