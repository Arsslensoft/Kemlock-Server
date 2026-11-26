//! `UserRepo` on `users`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::admin::user_state;
use crate::tables::{bw_account_extras, email_confirmations, pending_erasures, users};
use kemlock_app::ports::{EmailConfirmation, StoreError, UserRepo};
use kemlock_domain::{Email, User, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use time::OffsetDateTime;

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

    async fn insert(&self, user: &User) -> Result<(), StoreError> {
        users::Entity::insert(users::active(user))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), StoreError> {
        let row = users::ActiveModel {
            id: NotSet,
            ..users::active(user)
        };
        let result = users::Entity::update_many()
            .set(row)
            .filter(users::Column::Id.eq(user.id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_first_keys(&self, user: &User) -> Result<(), StoreError> {
        // One conditional UPDATE: it matches only while the account has no keys, so of two
        // enrolments at once the database lets one through, and only these columns change.
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
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected > 0 {
            return Ok(());
        }
        // Nothing matched: no such account, or it has keys already.
        let exists = users::Entity::find_by_id(user.id.0)
            .one(self.writer())
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
