//! `account_bundles`: every public-key bundle an account has had, by key version
//! (docs/crypto.md, "Signed item writes", "Key versions"). The current one is also in `users`.

use crate::convert::{from_i64_u32, utc};
use crate::error::{StoreResult, is_unique_violation, map_db};
use kemlock_app::ports::{StoreError, StoredBundle};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use sea_orm::{ConnectionTrait, QueryOrder};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "account_bundles")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_version: i64,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub recorded_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_stored(self) -> Result<StoredBundle, StoreError> {
        Ok(StoredBundle {
            key_version: from_i64_u32(self.key_version, "key version")?,
            public_bundle: self.public_bundle,
            bundle_signature: self.bundle_signature,
        })
    }
}

/// Keeps the bundle of `key_version` for `user`, once: a version already kept is left as it was, so
/// history never changes. An account with no keys (`key_version` 0, an empty bundle) keeps nothing.
pub(crate) async fn record<C: ConnectionTrait>(
    conn: &C,
    user: Uuid,
    key_version: i64,
    public_bundle: &[u8],
    bundle_signature: &[u8],
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    if key_version <= 0 || public_bundle.is_empty() {
        return Ok(());
    }
    if Entity::find_by_id((user, key_version))
        .one(conn)
        .await
        .store()?
        .is_some()
    {
        return Ok(());
    }
    let row = ActiveModel {
        user_id: Set(user),
        key_version: Set(key_version),
        public_bundle: Set(public_bundle.to_vec()),
        bundle_signature: Set(bundle_signature.to_vec()),
        recorded_at: Set(utc(at)),
    };
    match Entity::insert(row).exec(conn).await {
        Ok(_) => Ok(()),
        // Another writer kept the same version between the read and the write.
        Err(err) if is_unique_violation(&err) => Ok(()),
        Err(err) => Err(map_db(err)),
    }
}

/// Every bundle kept for `user`, oldest key version first.
pub(crate) async fn all_of<C: ConnectionTrait>(
    conn: &C,
    user: Uuid,
) -> Result<Vec<StoredBundle>, StoreError> {
    Entity::find()
        .filter(Column::UserId.eq(user))
        .order_by_asc(Column::KeyVersion)
        .all(conn)
        .await
        .store()?
        .into_iter()
        .map(Model::into_stored)
        .collect()
}
