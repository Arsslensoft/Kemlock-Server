//! `RecoveryCodeRepo` on `two_factor_recovery`, with the legacy code an import left in
//! `bw_account_extras.sealed_totp_recover`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::{bw_account_extras, two_factor_recovery};
use kemlock_app::ports::StoreError;
use kemlock_app::two_step::RecoveryCodeRepo;
use kemlock_domain::UserId;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use time::OffsetDateTime;

impl RecoveryCodeRepo for SqlStore {
    async fn recovery_code(&self, user: UserId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(two_factor_recovery::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map(|row| row.sealed_code))
    }

    async fn legacy_recovery_code(&self, user: UserId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(bw_account_extras::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .and_then(|row| row.sealed_totp_recover))
    }

    async fn put_recovery_code_if_absent(
        &self,
        user: UserId,
        sealed: &[u8],
        at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        if self.legacy_recovery_code(user).await?.is_some() {
            return Ok(false);
        }
        let inserted =
            two_factor_recovery::Entity::insert(two_factor_recovery::active(user.0, sealed, at))
                .on_conflict(
                    OnConflict::column(two_factor_recovery::Column::UserId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(self.writer())
                .await;
        match inserted {
            Ok(_) => Ok(true),
            // The account has a code already: the conflict did nothing.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(false),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn remove_recovery_code(&self, user: UserId) -> Result<bool, StoreError> {
        let removed = two_factor_recovery::Entity::delete_many()
            .filter(two_factor_recovery::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        // The legacy column is cleared too, and only a row that holds a code counts, so of two
        // calls racing for one code exactly one sees it.
        let legacy = bw_account_extras::Entity::update_many()
            .col_expr(
                bw_account_extras::Column::SealedTotpRecover,
                Expr::cust("NULL"),
            )
            .filter(bw_account_extras::Column::UserId.eq(user.0))
            .filter(bw_account_extras::Column::SealedTotpRecover.is_not_null())
            .exec(self.writer())
            .await
            .store()?
            .rows_affected;
        Ok(removed + legacy > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::ports::UserRepo;
    use kemlock_domain::{AccountMode, Email, KdfParams, Role, User};
    use sea_orm::ActiveValue::Set;
    use time::macros::datetime;
    use uuid::Uuid;

    const AT: OffsetDateTime = datetime!(2026-11-25 10:00:00 UTC);

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

    /// What the import leaves: a `bw_account_extras` row whose legacy column holds a sealed code.
    async fn import_legacy_code(store: &SqlStore, user: UserId, sealed: Option<Vec<u8>>) {
        bw_account_extras::Entity::insert(bw_account_extras::ActiveModel {
            user_id: Set(user.0),
            enabled: Set(true),
            verified_at: Set(None),
            last_verifying_at: Set(None),
            login_verify_count: Set(0),
            email_new: Set(None),
            email_new_token: Set(None),
            stamp_exception: Set(None),
            equivalent_domains: Set("[]".to_owned()),
            excluded_globals: Set("[]".to_owned()),
            external_id: Set(None),
            key_id: Set(None),
            sealed_totp_secret: Set(None),
            sealed_totp_recover: Set(sealed),
            vw_security_stamp: Set("stamp".to_owned()),
        })
        .exec(store.writer())
        .await
        .expect("the imported row");
    }

    #[tokio::test]
    async fn a_code_is_stored_once_read_back_and_removed_once() {
        let (store, user) = store_with_user().await;
        assert_eq!(store.recovery_code(user).await, Ok(None));
        assert_eq!(store.remove_recovery_code(user).await, Ok(false));

        assert_eq!(
            store
                .put_recovery_code_if_absent(user, &[1, 2, 3], AT)
                .await,
            Ok(true)
        );
        assert_eq!(
            store
                .put_recovery_code_if_absent(user, &[9, 9, 9], AT)
                .await,
            Ok(false),
            "an account that has a code keeps it"
        );
        assert_eq!(store.recovery_code(user).await, Ok(Some(vec![1, 2, 3])));

        assert_eq!(store.remove_recovery_code(user).await, Ok(true));
        assert_eq!(
            store.remove_recovery_code(user).await,
            Ok(false),
            "the second of two racing calls finds nothing"
        );
        assert_eq!(store.recovery_code(user).await, Ok(None));
        assert_eq!(
            store.put_recovery_code_if_absent(user, &[4, 5], AT).await,
            Ok(true),
            "and a new one can be made after"
        );
    }

    #[tokio::test]
    async fn an_imported_code_is_read_blocks_a_new_one_and_is_cleared_by_remove() {
        let (store, user) = store_with_user().await;
        import_legacy_code(&store, user, Some(vec![7, 7, 7])).await;
        assert_eq!(store.recovery_code(user).await, Ok(None));
        assert_eq!(
            store.legacy_recovery_code(user).await,
            Ok(Some(vec![7, 7, 7]))
        );
        assert_eq!(
            store.put_recovery_code_if_absent(user, &[1], AT).await,
            Ok(false),
            "no second code beside the imported one"
        );

        assert_eq!(store.remove_recovery_code(user).await, Ok(true));
        assert_eq!(store.legacy_recovery_code(user).await, Ok(None));
        assert_eq!(store.remove_recovery_code(user).await, Ok(false));
        assert_eq!(
            store.put_recovery_code_if_absent(user, &[1], AT).await,
            Ok(true)
        );
    }

    #[tokio::test]
    async fn an_imported_account_that_never_had_a_code_gets_one() {
        let (store, user) = store_with_user().await;
        import_legacy_code(&store, user, None).await;
        assert_eq!(store.legacy_recovery_code(user).await, Ok(None));
        assert_eq!(
            store.put_recovery_code_if_absent(user, &[1], AT).await,
            Ok(true)
        );
    }
}
