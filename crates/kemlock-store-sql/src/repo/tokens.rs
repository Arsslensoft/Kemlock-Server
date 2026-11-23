//! `TokenRepo` on `refresh_tokens` and `revoked_families`.
//!
//! Revoking a family writes a row to `revoked_families` before it deletes the family's tokens. A
//! token of a listed family counts as used when it is taken and can't be inserted, so a rotation
//! that read its token before the revocation and inserts its successor after it leaves nothing
//! usable behind: reuse detection can't be raced.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{refresh_tokens, revoked_families};
use kemlock_app::ports::{RefreshToken, StoreError, TokenRepo};
use kemlock_domain::DeviceId;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

/// Whether `family` was revoked.
async fn is_revoked<C: ConnectionTrait>(db: &C, family: Uuid) -> Result<bool, StoreError> {
    Ok(revoked_families::Entity::find_by_id(family)
        .one(db)
        .await
        .store()?
        .is_some())
}

impl TokenRepo for SqlStore {
    /// `NotFound` when the token's family was revoked (or its device is gone).
    async fn insert(&self, token: &RefreshToken) -> Result<(), StoreError> {
        if is_revoked(self.writer(), token.family).await? {
            return Err(StoreError::NotFound);
        }
        refresh_tokens::Entity::insert(refresh_tokens::active(token))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    /// Reads the token, then marks it used with a compare-and-set (`WHERE used_at IS NULL`), so
    /// of two racing refreshes of one token exactly one sees it unused. The loser re-reads and
    /// gets the token as the winner left it, used. A token of a revoked family is returned as
    /// used, whatever it was.
    async fn take(
        &self,
        hash: [u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<RefreshToken>, StoreError> {
        let writer = self.writer();
        let Some(before) = refresh_tokens::Entity::find_by_id(hash.to_vec())
            .one(writer)
            .await
            .store()?
        else {
            return Ok(None);
        };
        if is_revoked(writer, before.family).await? {
            let mut token = before.into_domain()?;
            token.used_at.get_or_insert(now);
            return Ok(Some(token));
        }
        if before.used_at.is_some() {
            return before.into_domain().map(Some);
        }

        let mark = refresh_tokens::ActiveModel {
            hash: NotSet,
            family: NotSet,
            user_id: NotSet,
            device_id: NotSet,
            created_at: NotSet,
            expires_at: NotSet,
            security_stamp: NotSet,
            used_at: Set(Some(utc(now))),
        };
        let result = refresh_tokens::Entity::update_many()
            .set(mark)
            .filter(refresh_tokens::Column::Hash.eq(hash.to_vec()))
            .filter(refresh_tokens::Column::UsedAt.is_null())
            .exec(writer)
            .await
            .store()?;
        if result.rows_affected == 1 {
            return before.into_domain().map(Some);
        }

        // Someone else took it between our read and our update.
        refresh_tokens::Entity::find_by_id(hash.to_vec())
            .one(writer)
            .await
            .store()?
            .map(refresh_tokens::Model::into_domain)
            .transpose()
    }

    async fn revoke_family(&self, family: Uuid) -> Result<(), StoreError> {
        // The tombstone first: from here on no token of the family can be taken or inserted,
        // whatever happens to the rows below.
        let tombstone = revoked_families::ActiveModel {
            family: Set(family),
            revoked_at: Set(utc(OffsetDateTime::now_utc())),
        };
        match revoked_families::Entity::insert(tombstone)
            .exec(self.writer())
            .await
        {
            Ok(_) => {}
            // Already revoked, perhaps by the other half of the same race.
            Err(err) if is_unique_violation(&err) => {}
            Err(err) => return Err(map_db(err)),
        }
        refresh_tokens::Entity::delete_many()
            .filter(refresh_tokens::Column::Family.eq(family))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn revoke_device(&self, device: DeviceId) -> Result<(), StoreError> {
        refresh_tokens::Entity::delete_many()
            .filter(refresh_tokens::Column::DeviceId.eq(device.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::ports::{DeviceRepo, UserRepo};
    use kemlock_domain::{AccountMode, Device, DeviceKind, Email, KdfParams, Role, User, UserId};
    use time::macros::datetime;

    fn an_account() -> (User, Device) {
        let now = datetime!(2026-01-02 03:04:05 UTC);
        let user = User {
            id: UserId::random(),
            email: Email::parse("race@example.org").expect("valid"),
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
            created_at: now,
            updated_at: now,
        };
        let device = Device {
            id: DeviceId::random(),
            user: user.id,
            name: "Phone".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: Some("jkt".to_owned()),
            created_at: now,
            last_seen_at: now,
        };
        (user, device)
    }

    #[tokio::test]
    async fn a_token_that_lands_in_a_revoked_family_is_dead() {
        // The race: a rotation took its token, the loser revoked the family, and only then does
        // the winner's successor reach the table.
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects");
        let (user, device) = an_account();
        UserRepo::insert(&store, &user).await.expect("a user");
        DeviceRepo::upsert(&store, &device).await.expect("a device");

        let family = Uuid::new_v4();
        let successor = RefreshToken {
            hash: [7; 32],
            family,
            user: user.id,
            device: device.id,
            security_stamp: user.security_stamp,
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            expires_at: datetime!(2026-02-02 03:04:05 UTC),
            used_at: None,
        };
        TokenRepo::revoke_family(&store, family)
            .await
            .expect("revoke");
        // The checked path refuses it...
        assert_eq!(
            TokenRepo::insert(&store, &successor).await,
            Err(StoreError::NotFound)
        );
        // ...and a row that got in anyway (an insert on another connection that passed its check
        // before the revocation) can't be taken as a live token.
        refresh_tokens::Entity::insert(refresh_tokens::active(&successor))
            .exec(store.writer())
            .await
            .expect("a raw insert");
        let taken_at = datetime!(2026-01-03 00:00:00 UTC);
        let taken = TokenRepo::take(&store, successor.hash, taken_at)
            .await
            .expect("take")
            .expect("the row exists");
        assert_eq!(taken.used_at, Some(taken_at));
        // Revoking again is harmless.
        TokenRepo::revoke_family(&store, family)
            .await
            .expect("revoke again");
    }
}
