//! `PasskeyRepo` on `passkeys` and `ChallengeRepo` on `webauthn_challenges`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{passkeys, webauthn_challenges};
use kemlock_app::passkeys::{ChallengeKind, ChallengeRepo, PasskeyRepo};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;

impl SqlStore {
    /// Whether the account has this passkey. MySQL counts only changed rows for an update, so an
    /// update that changed nothing needs this to tell "same value" from "no such row".
    async fn has_passkey(&self, user: UserId, id: PasskeyId) -> Result<bool, StoreError> {
        let count = passkeys::Entity::find()
            .filter(passkeys::Column::UserId.eq(user.0))
            .filter(passkeys::Column::Id.eq(id.0))
            .count(self.writer())
            .await
            .store()?;
        Ok(count > 0)
    }
}

impl PasskeyRepo for SqlStore {
    async fn passkeys_of(&self, user: UserId) -> Result<Vec<Passkey>, StoreError> {
        passkeys::Entity::find()
            .filter(passkeys::Column::UserId.eq(user.0))
            .order_by_asc(passkeys::Column::CreatedAt)
            .order_by_asc(passkeys::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(passkeys::Model::into_domain)
            .collect()
    }

    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, StoreError> {
        passkeys::Entity::find()
            .filter(passkeys::Column::CredentialId.eq(credential_id.to_vec()))
            .one(self.reader())
            .await
            .store()?
            .map(passkeys::Model::into_domain)
            .transpose()
    }

    async fn insert_passkey(&self, passkey: &Passkey) -> Result<(), StoreError> {
        passkeys::Entity::insert(passkeys::active(passkey))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn rename_passkey(
        &self,
        user: UserId,
        id: PasskeyId,
        name: &str,
    ) -> Result<(), StoreError> {
        let result = passkeys::Entity::update_many()
            .col_expr(passkeys::Column::Name, Expr::value(name))
            .filter(passkeys::Column::UserId.eq(user.0))
            .filter(passkeys::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 && !self.has_passkey(user, id).await? {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_passkey(&self, user: UserId, id: PasskeyId) -> Result<(), StoreError> {
        let result = passkeys::Entity::delete_many()
            .filter(passkeys::Column::UserId.eq(user.0))
            .filter(passkeys::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn record_passkey_use(
        &self,
        id: PasskeyId,
        credential: &[u8],
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let result = passkeys::Entity::update_many()
            .col_expr(
                passkeys::Column::Credential,
                Expr::value(credential.to_vec()),
            )
            .col_expr(passkeys::Column::LastUsedAt, Expr::value(utc(at)))
            .filter(passkeys::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            // A sign-in at the very instant of the last one, with the same credential, changes
            // nothing: that is not a missing row.
            let count = passkeys::Entity::find()
                .filter(passkeys::Column::Id.eq(id.0))
                .count(self.writer())
                .await
                .store()?;
            if count == 0 {
                return Err(StoreError::NotFound);
            }
        }
        Ok(())
    }

    async fn set_passkey_wrap(
        &self,
        user: UserId,
        id: PasskeyId,
        wrap: Option<&PrfWrap>,
    ) -> Result<(), StoreError> {
        let wrapped_key: Option<Vec<u8>> = wrap.map(|w| w.wrapped_key.clone());
        let key_version: Option<i64> = wrap.map(|w| i64::from(w.key_version));
        let result = passkeys::Entity::update_many()
            .col_expr(passkeys::Column::PrfWrappedKey, Expr::value(wrapped_key))
            .col_expr(passkeys::Column::PrfKeyVersion, Expr::value(key_version))
            .filter(passkeys::Column::UserId.eq(user.0))
            .filter(passkeys::Column::Id.eq(id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 && !self.has_passkey(user, id).await? {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl ChallengeRepo for SqlStore {
    async fn put_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let conflict = OnConflict::columns([
            webauthn_challenges::Column::UserId,
            webauthn_challenges::Column::Kind,
        ])
        .update_columns([
            webauthn_challenges::Column::State,
            webauthn_challenges::Column::ExpiresAt,
        ])
        .to_owned();
        let row = webauthn_challenges::ActiveModel {
            user_id: Set(user.0),
            kind: Set(kind.as_str().to_owned()),
            state: Set(state.to_vec()),
            expires_at: Set(utc(expires_at)),
        };
        let inserted = webauthn_challenges::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    /// Reads the row, then deletes it only if it still holds the state that was read: of two calls
    /// racing for one state, one delete finds the row and the other finds none, and a challenge
    /// that was replaced in between is not the one that was asked for.
    async fn take_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(row) = webauthn_challenges::Entity::find()
            .filter(webauthn_challenges::Column::UserId.eq(user.0))
            .filter(webauthn_challenges::Column::Kind.eq(kind.as_str()))
            .one(self.writer())
            .await
            .store()?
        else {
            return Ok(None);
        };
        let removed = webauthn_challenges::Entity::delete_many()
            .filter(webauthn_challenges::Column::UserId.eq(user.0))
            .filter(webauthn_challenges::Column::Kind.eq(kind.as_str()))
            .filter(webauthn_challenges::Column::State.eq(row.state.clone()))
            .exec(self.writer())
            .await
            .store()?;
        if removed.rows_affected != 1 || row.expires_at <= utc(now) {
            return Ok(None);
        }
        Ok(Some(row.state))
    }

    async fn purge_challenges(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let result = webauthn_challenges::Entity::delete_many()
            .filter(webauthn_challenges::Column::ExpiresAt.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}
