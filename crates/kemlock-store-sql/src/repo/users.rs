//! `UserRepo` on `users`.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::admin::user_state;
use crate::tables::{bw_account_extras, pending_erasures, users};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_domain::{Email, User, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
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
}
