//! `space_recovery_boxes`: a member's root key sealed to a space's recovery key (docs/crypto.md,
//! the `"account-recovery"` sealed-box context), one row per space and member. The server keeps the
//! box as it came and the `seq` of the chain record that set the recovery key it is sealed to;
//! the chain says whether that is still the current key. Nothing here is the chain's state.

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
                    .table("space_recovery_boxes")
                    .if_not_exists()
                    .col(c::uuid("space_id"))
                    .col(c::uuid("user_id"))
                    // The `seq` of the `recovery-key` record the box is sealed under.
                    .col(c::big_integer("key_seq"))
                    // The 1693-byte sealed box: version byte, kx1 ciphertext, nonce, a 64-byte
                    // root key and the tag.
                    .col(c::blob("sealed"))
                    // Unix seconds.
                    .col(c::big_integer("enrolled_at"))
                    .primary_key(Index::create().col("space_id").col("user_id"))
                    .to_owned(),
            )
            .await?;
        // A member's boxes, for when they leave or their account is erased.
        manager
            .create_index(
                Index::create()
                    .name("idx_space_recovery_boxes_user_id")
                    .table("space_recovery_boxes")
                    .col("user_id")
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}
