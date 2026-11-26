//! `FirstAdminRepo` on `settings` and `users`.
//!
//! The marker is the `settings` row `first_admin`, whose value is the account's id. Its primary
//! key is the key name, so a second insert fails on every backend; it is written in the
//! transaction that inserts the account, so either both exist or neither does.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::{settings, users};
use kemlock_app::FirstAdminRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::{User, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use uuid::Uuid;

/// The marker's `settings` key.
const KEY: &str = kemlock_app::first_admin::MARKER_KEY;

/// The account the marker names, if the marker exists and the account does too.
async fn marked_account<C: ConnectionTrait>(db: &C) -> Result<Option<Uuid>, StoreError> {
    let Some(row) = settings::Entity::find_by_id(KEY.to_owned())
        .one(db)
        .await
        .store()?
    else {
        return Ok(None);
    };
    let Ok(id) = Uuid::parse_str(&row.value) else {
        return Ok(None);
    };
    let exists = users::Entity::find_by_id(id)
        .one(db)
        .await
        .store()?
        .is_some();
    Ok(exists.then_some(id))
}

impl FirstAdminRepo for SqlStore {
    async fn insert_first_admin(&self, user: &User) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            if marked_account(&txn).await?.is_some() {
                return Err(StoreError::Duplicate);
            }
            // A marker whose account is gone (or whose value is garbage) holds nothing.
            settings::Entity::delete_by_id(KEY.to_owned())
                .exec(&txn)
                .await
                .store()?;
            settings::Entity::insert(settings::ActiveModel {
                key: Set(KEY.to_owned()),
                value: Set(user.id.0.to_string()),
            })
            .exec(&txn)
            .await
            .store()?;
            users::Entity::insert(users::active(user))
                .exec(&txn)
                .await
                .store()?;
            crate::tables::account_bundles::record(
                &txn,
                user.id.0,
                i64::from(user.key_version),
                &user.public_bundle,
                &user.bundle_signature,
                user.updated_at,
            )
            .await?;
            Ok::<(), StoreError>(())
        }
        .await;
        match outcome {
            Ok(()) => txn.commit().await.store(),
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed first-admin insert failed");
                }
                Err(err)
            }
        }
    }

    async fn first_admin(&self) -> Result<Option<UserId>, StoreError> {
        Ok(marked_account(self.reader()).await?.map(UserId))
    }
}
