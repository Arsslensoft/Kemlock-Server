//! `BwUserKeyIdRepo` on `bw_user_key_ids`, with the id an import left in `bw_account_extras.key_id`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::{bw_account_extras, bw_user_key_ids};
use kemlock_app::bitwarden::BwUserKeyIdRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use sea_orm::sea_query::OnConflict;
use sea_orm::{EntityTrait, Set};

impl BwUserKeyIdRepo for SqlStore {
    async fn user_key_id(&self, user: UserId) -> Result<Option<String>, StoreError> {
        let imported = bw_account_extras::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .and_then(|row| row.key_id);
        if imported.is_some() {
            return Ok(imported);
        }
        Ok(bw_user_key_ids::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map(|row| row.key_id))
    }

    async fn put_user_key_id_if_absent(
        &self,
        user: UserId,
        key_id: &str,
    ) -> Result<bool, StoreError> {
        let imported = bw_account_extras::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .and_then(|row| row.key_id);
        if imported.is_some() {
            return Ok(false);
        }
        let inserted = bw_user_key_ids::Entity::insert(bw_user_key_ids::ActiveModel {
            user_id: Set(user.0),
            key_id: Set(key_id.to_owned()),
        })
        .on_conflict(
            OnConflict::column(bw_user_key_ids::Column::UserId)
                .do_nothing()
                .to_owned(),
        )
        .exec(self.writer())
        .await;
        match inserted {
            Ok(_) => Ok(true),
            // The account has an id already: the conflict did nothing.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(false),
            Err(err) => Err(map_db(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::ports::UserRepo;
    use kemlock_domain::{AccountMode, Email, KdfParams, Role, User};
    use time::OffsetDateTime;
    use time::macros::datetime;
    use uuid::Uuid;

    const AT: OffsetDateTime = datetime!(2026-11-24 12:00:00 UTC);
    const ID: &str = "0123456789abcdef0123456789abcdef";

    async fn store_with_user() -> (SqlStore, UserId) {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        let user = User {
            id: UserId::random(),
            email: Email::parse("ada@example.org").expect("valid"),
            name: None,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account([1; 16]),
            opaque_record: None,
            wrapped_root_key: vec![2; 92],
            public_bundle: vec![3; 100],
            bundle_signature: vec![4; 100],
            sealed_private_keys: vec![5; 100],
            key_version: 1,
            security_stamp: Uuid::new_v4(),
            created_at: AT,
            updated_at: AT,
        };
        UserRepo::insert(&store, &user).await.expect("a user");
        (store, user.id)
    }

    #[tokio::test]
    async fn an_id_is_recorded_once_and_read_back() {
        let (store, user) = store_with_user().await;
        assert_eq!(store.user_key_id(user).await, Ok(None));
        assert_eq!(store.put_user_key_id_if_absent(user, ID).await, Ok(true));
        assert_eq!(store.user_key_id(user).await, Ok(Some(ID.to_owned())));
        let other = "fedcba9876543210fedcba9876543210";
        assert_eq!(
            store.put_user_key_id_if_absent(user, other).await,
            Ok(false)
        );
        assert_eq!(store.user_key_id(user).await, Ok(Some(ID.to_owned())));
    }
}
