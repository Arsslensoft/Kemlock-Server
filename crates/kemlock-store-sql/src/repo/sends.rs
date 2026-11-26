//! `SendRepo` on `sends`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::owner_lock::begin_locked;
use crate::store::SqlStore;
use crate::tables::sends::{self, untouched};
use kemlock_app::ports::StoreError;
use kemlock_app::quota::{QuotaRefusal, check};
use kemlock_app::sends::{SendRepo, file_send_bytes};
use kemlock_domain::UserId;
use kemlock_domain::sends::{SendId, SendRecord};
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use time::OffsetDateTime;

/// How many times a view count retries when another opener changed it between the read and the
/// write. Each retry means someone else got a view in, so a few suffice.
const VIEW_RETRIES: u32 = 8;

impl SendRepo for SqlStore {
    async fn add_send(&self, send: &SendRecord) -> Result<(), StoreError> {
        // A Send's sealed key is a wrap of the owner's root key: written under the owner's lock.
        let txn = begin_locked(self, send.owner).await?;
        sends::Entity::insert(sends::active(send)?)
            .exec(&txn)
            .await
            .store()?;
        txn.commit().await.store()?;
        Ok(())
    }

    /// The sum and the insert in one transaction, under the store's quota gate.
    async fn add_send_within_quota(
        &self,
        send: &SendRecord,
        quota: Option<u64>,
    ) -> Result<Result<(), QuotaRefusal>, StoreError> {
        let _gate = self.quota_gate().await;
        let txn = begin_locked(self, send.owner).await?;
        let outcome = async {
            if let (Some(_), Some(file)) = (quota, send.file) {
                let owned = sends::Entity::find()
                    .filter(sends::Column::OwnerId.eq(send.owner.0))
                    .all(&txn)
                    .await
                    .store()?
                    .into_iter()
                    .map(sends::Model::into_domain)
                    .collect::<Result<Vec<_>, _>>()?;
                if let Err(refusal) = check(quota, file_send_bytes(&owned), file.size) {
                    return Ok(Err(refusal));
                }
            }
            sends::Entity::insert(sends::active(send)?)
                .exec(&txn)
                .await
                .store()?;
            Ok::<_, StoreError>(Ok(()))
        }
        .await;
        match outcome {
            Ok(done) => {
                txn.commit().await.store()?;
                Ok(done)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after adding a Send failed");
                }
                Err(err)
            }
        }
    }

    async fn send_by_id(&self, id: SendId) -> Result<Option<SendRecord>, StoreError> {
        // The writer, not the reader: a Send was just made or its count just moved, and a recipient
        // must see the same count the next opener will be held to.
        sends::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .map(sends::Model::into_domain)
            .transpose()
    }

    async fn sends_of(&self, owner: UserId) -> Result<Vec<SendRecord>, StoreError> {
        sends::Entity::find()
            .filter(sends::Column::OwnerId.eq(owner.0))
            .order_by_desc(sends::Column::CreatedAt)
            .order_by_asc(sends::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(sends::Model::into_domain)
            .collect()
    }

    async fn update_send(&self, send: &SendRecord) -> Result<(), StoreError> {
        let row = sends::ActiveModel {
            meta: Set(send.meta.clone()),
            payload: Set(send.payload.clone()),
            password_salt: Set(send.password.as_ref().map(|p| p.salt.clone())),
            password_hash: Set(send.password.as_ref().map(|p| p.hash.clone())),
            max_access: Set(send.max_access.map(i64::from)),
            hide_email: Set(send.hide_email),
            disabled: Set(send.disabled),
            expires_at: Set(send.expires_at.map(utc)),
            deletion_at: Set(utc(send.deletion_at)),
            revised_at: Set(utc(send.revised_at)),
            ..untouched()
        };
        let result = sends::Entity::update_many()
            .set(row)
            .filter(sends::Column::Id.eq(send.id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// One conditional update: of two uploads of one file finishing together, exactly one sees a
    /// row change.
    async fn mark_send_file_ready(&self, id: SendId) -> Result<bool, StoreError> {
        let row = sends::ActiveModel {
            file_ready: Set(true),
            ..untouched()
        };
        let result = sends::Entity::update_many()
            .set(row)
            .filter(sends::Column::Id.eq(id.0))
            .filter(sends::Column::FileBlobId.is_not_null())
            .filter(sends::Column::FileReady.eq(false))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected > 0)
    }

    /// A compare-and-swap on the count: read it, then write count + 1 only where the count is still
    /// what was read. Two openers racing for the last view can't both win, because the second
    /// one's write matches no row and it reads again, finding the limit reached.
    async fn count_send_view(&self, id: SendId, at: OffsetDateTime) -> Result<bool, StoreError> {
        for _ in 0..VIEW_RETRIES {
            let Some(row) = sends::Entity::find_by_id(id.0)
                .one(self.writer())
                .await
                .store()?
            else {
                return Ok(false);
            };
            if row.max_access.is_some_and(|max| row.access_count >= max) {
                return Ok(false);
            }
            let next = sends::ActiveModel {
                access_count: Set(row.access_count + 1),
                revised_at: Set(utc(at)),
                ..untouched()
            };
            let result = sends::Entity::update_many()
                .set(next)
                .filter(sends::Column::Id.eq(id.0))
                .filter(sends::Column::AccessCount.eq(row.access_count))
                .exec(self.writer())
                .await
                .store()?;
            if result.rows_affected == 1 {
                return Ok(true);
            }
        }
        Err(StoreError::Backend(
            "a Send's view count kept changing under a read".to_owned(),
        ))
    }

    async fn remove_send(&self, id: SendId) -> Result<(), StoreError> {
        sends::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn sends_to_delete(
        &self,
        now: OffsetDateTime,
        abandoned_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SendRecord>, StoreError> {
        let abandoned = Condition::all()
            .add(sends::Column::FileBlobId.is_not_null())
            .add(sends::Column::FileReady.eq(false))
            .add(sends::Column::CreatedAt.lt(utc(abandoned_before)));
        let due = Condition::any()
            .add(sends::Column::DeletionAt.lte(utc(now)))
            .add(abandoned);
        sends::Entity::find()
            .filter(due)
            .order_by_asc(sends::Column::CreatedAt)
            .order_by_asc(sends::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(sends::Model::into_domain)
            .collect()
    }
}

impl SqlStore {
    /// Writes everything the Bitwarden API's `PUT /api/sends/{id}` may change, the sealed key
    /// included, which [`SendRepo::update_send`] never touches (a Kemlock owner can't re-key a
    /// Send; a Bitwarden app can). Never the owner, the kind, the file, the creation time or the
    /// view count, which a recipient moves on its own and an edit must not roll back. `NotFound`
    /// when the Send is gone.
    pub async fn overwrite_send(&self, send: &SendRecord) -> Result<(), StoreError> {
        let row = sends::ActiveModel {
            meta: Set(send.meta.clone()),
            sealed_key: Set(send.sealed_key.clone()),
            payload: Set(send.payload.clone()),
            password_salt: Set(send.password.as_ref().map(|p| p.salt.clone())),
            password_hash: Set(send.password.as_ref().map(|p| p.hash.clone())),
            max_access: Set(send.max_access.map(i64::from)),
            hide_email: Set(send.hide_email),
            disabled: Set(send.disabled),
            expires_at: Set(send.expires_at.map(utc)),
            deletion_at: Set(utc(send.deletion_at)),
            revised_at: Set(utc(send.revised_at)),
            ..untouched()
        };
        let result = sends::Entity::update_many()
            .set(row)
            .filter(sends::Column::Id.eq(send.id.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
