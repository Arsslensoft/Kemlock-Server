//! `UserRepo` on `users`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::admin::user_state;
use crate::tables::{
    account_bundles, bw_account_extras, email_confirmations, pending_erasures, users,
};
use kemlock_app::ports::{EmailConfirmation, StoreError, StoredBundle, UserRepo};
use kemlock_domain::{Email, User, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait};
use time::OffsetDateTime;

/// Keeps the account's current bundle in its history.
async fn keep_bundle<C: sea_orm::ConnectionTrait>(conn: &C, user: &User) -> Result<(), StoreError> {
    account_bundles::record(
        conn,
        user.id.0,
        i64::from(user.key_version),
        &user.public_bundle,
        &user.bundle_signature,
        user.updated_at,
    )
    .await
}

impl UserRepo for SqlStore {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, StoreError> {
        users::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(users::Model::into_domain)
            .transpose()
    }

    async fn by_email(&self, email: &Email) -> Result<Option<User>, StoreError> {
        users::Entity::find()
            .filter(users::Column::Email.eq(email.as_str()))
            .one(self.reader())
            .await
            .store()?
            .map(users::Model::into_domain)
            .transpose()
    }

    async fn bundle_at(
        &self,
        id: UserId,
        key_version: u32,
    ) -> Result<Option<StoredBundle>, StoreError> {
        // The account's row is what a write is checked against now, so the current version is its
        // row, whatever the history holds; the history answers for the versions before it.
        if let Some(user) = self.by_id(id).await?
            && user.key_version == key_version
        {
            return Ok((!user.public_bundle.is_empty()).then(|| StoredBundle {
                key_version: user.key_version,
                public_bundle: user.public_bundle,
                bundle_signature: user.bundle_signature,
            }));
        }
        account_bundles::Entity::find_by_id((id.0, i64::from(key_version)))
            .one(self.reader())
            .await
            .store()?
            .map(account_bundles::Model::into_stored)
            .transpose()
    }

    async fn bundle_retired_at(
        &self,
        id: UserId,
        key_version: u32,
    ) -> Result<Option<i64>, StoreError> {
        account_bundles::retired_at(self.reader(), id.0, i64::from(key_version)).await
    }

    async fn bundles_of(&self, id: UserId) -> Result<Vec<StoredBundle>, StoreError> {
        let mut all = account_bundles::all_of(self.reader(), id.0).await?;
        // The current one is the account's row, as in `bundle_at`.
        if let Some(current) = self
            .bundle_at(id, self.by_id(id).await?.map_or(0, |u| u.key_version))
            .await?
        {
            all.retain(|b| b.key_version != current.key_version);
            all.push(current);
            all.sort_by_key(|b| b.key_version);
        }
        Ok(all)
    }

    async fn insert(&self, user: &User) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        users::Entity::insert(users::active(user))
            .exec(&txn)
            .await
            .store()?;
        keep_bundle(&txn, user).await?;
        // A failure above drops the transaction, which rolls it back.
        txn.commit().await.store()
    }

    async fn update(&self, user: &User) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        // The bundle this replaces is kept first, so a key replacement never loses the version
        // before it: whatever path makes the replacement, it comes through here.
        if let Some(old) = users::Entity::find_by_id(user.id.0)
            .one(&txn)
            .await
            .store()?
        {
            account_bundles::record(
                &txn,
                old.id,
                old.key_version,
                &old.public_bundle,
                &old.bundle_signature,
                old.updated_at,
            )
            .await?;
        }
        let row = users::ActiveModel {
            id: NotSet,
            ..users::active(user)
        };
        let result = users::Entity::update_many()
            .set(row)
            .filter(users::Column::Id.eq(user.id.0))
            .exec(&txn)
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        keep_bundle(&txn, user).await?;
        txn.commit().await.store()
    }

    async fn set_first_keys(&self, user: &User) -> Result<(), StoreError> {
        // One conditional UPDATE: it matches only while the account has no keys, so of two
        // enrolments at once the database lets one through, and only these columns change.
        let txn = self.writer().begin().await.store()?;
        let row = users::ActiveModel {
            public_bundle: Set(user.public_bundle.clone()),
            bundle_signature: Set(user.bundle_signature.clone()),
            sealed_private_keys: Set(user.sealed_private_keys.clone()),
            key_version: Set(i64::from(user.key_version)),
            updated_at: Set(crate::convert::utc(user.updated_at)),
            ..Default::default()
        };
        let result = users::Entity::update_many()
            .set(row)
            .filter(users::Column::Id.eq(user.id.0))
            .filter(users::Column::KeyVersion.eq(0))
            .exec(&txn)
            .await
            .store()?;
        if result.rows_affected > 0 {
            keep_bundle(&txn, user).await?;
            return txn.commit().await.store();
        }
        // Nothing matched: no such account, or it has keys already.
        let exists = users::Entity::find_by_id(user.id.0)
            .one(&txn)
            .await
            .store()?
            .is_some();
        Err(if exists {
            StoreError::Duplicate
        } else {
            StoreError::NotFound
        })
    }

    async fn count_admins(&self) -> Result<u64, StoreError> {
        users::Entity::find()
            .filter(users::Column::Role.eq(users::ROLE_ADMIN))
            .count(self.reader())
            .await
            .store()
    }

    async fn account_disabled(&self, id: UserId) -> Result<bool, StoreError> {
        let db = self.reader();
        if user_state::Entity::find_by_id(id.0)
            .one(db)
            .await
            .store()?
            .is_some()
        {
            return Ok(true);
        }
        // An account moved from Vaultwarden keeps the flag it had there.
        Ok(bw_account_extras::Entity::find_by_id(id.0)
            .one(db)
            .await
            .store()?
            .is_some_and(|extras| !extras.enabled))
    }

    async fn erasure_pending(&self, id: UserId) -> Result<Option<OffsetDateTime>, StoreError> {
        Ok(pending_erasures::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(|row| row.due_at))
    }

    /// The account and its hold in one transaction.
    async fn insert_held(
        &self,
        user: &User,
        token_hash: [u8; 32],
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        users::Entity::insert(users::active(user))
            .exec(&txn)
            .await
            .store()?;
        keep_bundle(&txn, user).await?;
        email_confirmations::Entity::insert(email_confirmations::ActiveModel {
            user_id: Set(user.id.0),
            token_hash: Set(token_hash.to_vec()),
            requested_at: Set(utc(requested_at)),
            expires_at: Set(utc(expires_at)),
        })
        .exec(&txn)
        .await
        .store()?;
        // A failure above drops the transaction, which rolls it back.
        txn.commit().await.store()?;
        Ok(())
    }

    /// Read from the writer: a hold made a moment ago must be seen, or a stale read would let an
    /// unconfirmed account in.
    async fn email_unconfirmed(&self, id: UserId) -> Result<bool, StoreError> {
        Ok(email_confirmations::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .is_some())
    }

    /// An upsert on the account: a new link replaces the one before, which stops working.
    async fn hold_unconfirmed(
        &self,
        id: UserId,
        token_hash: [u8; 32],
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let row = email_confirmations::ActiveModel {
            user_id: Set(id.0),
            token_hash: Set(token_hash.to_vec()),
            requested_at: Set(utc(requested_at)),
            expires_at: Set(utc(expires_at)),
        };
        let conflict = OnConflict::column(email_confirmations::Column::UserId)
            .update_columns([
                email_confirmations::Column::TokenHash,
                email_confirmations::Column::RequestedAt,
                email_confirmations::Column::ExpiresAt,
            ])
            .to_owned();
        let written = email_confirmations::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match written {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn confirmation_of(&self, id: UserId) -> Result<Option<EmailConfirmation>, StoreError> {
        Ok(email_confirmations::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .map(email_confirmations::Model::into_domain))
    }

    /// The delete is the claim: of two openings of one link, one finds the row to remove.
    async fn spend_confirmation(
        &self,
        token_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<UserId>, StoreError> {
        let Some(row) = email_confirmations::Entity::find()
            .filter(email_confirmations::Column::TokenHash.eq(token_hash.to_vec()))
            .one(self.writer())
            .await
            .store()?
        else {
            return Ok(None);
        };
        if row.expires_at <= now {
            return Ok(None);
        }
        let spent = email_confirmations::Entity::delete_many()
            .filter(email_confirmations::Column::UserId.eq(row.user_id))
            .filter(email_confirmations::Column::TokenHash.eq(token_hash.to_vec()))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok((spent == 1).then_some(UserId(row.user_id)))
    }
}
