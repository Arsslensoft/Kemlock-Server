//! `ApprovalRepo` on `auth_requests`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::owner_lock::begin_locked;
use crate::store::SqlStore;
use crate::tables::auth_requests::{self, state_str};
use kemlock_app::devices::{ApprovalRepo, RecentRequest};
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use kemlock_domain::unlock::{ApprovalId, ApprovalState, AuthRequest};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;

impl ApprovalRepo for SqlStore {
    async fn insert_request(&self, request: &AuthRequest) -> Result<(), StoreError> {
        auth_requests::Entity::insert(auth_requests::active(request))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn request(&self, id: ApprovalId) -> Result<Option<AuthRequest>, StoreError> {
        auth_requests::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(auth_requests::Model::into_domain)
            .transpose()
    }

    async fn pending_requests(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<AuthRequest>, StoreError> {
        auth_requests::Entity::find()
            .filter(auth_requests::Column::UserId.eq(user.0))
            .filter(auth_requests::Column::State.eq(state_str(ApprovalState::Pending)))
            .filter(auth_requests::Column::ExpiresAt.gt(utc(now)))
            .order_by_desc(auth_requests::Column::CreatedAt)
            .order_by_asc(auth_requests::Column::Id)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(auth_requests::Model::into_domain)
            .collect()
    }

    /// `UPDATE … WHERE id = ? AND state = ?`: of two racing answers, the update that finds the
    /// old state wins and the other changes no row.
    async fn save_request(
        &self,
        request: &AuthRequest,
        from: ApprovalState,
    ) -> Result<bool, StoreError> {
        let answer = auth_requests::ActiveModel {
            id: NotSet,
            user_id: NotSet,
            device_id: NotSet,
            device_name: NotSet,
            device_kind: NotSet,
            public_key: NotSet,
            jkt: NotSet,
            ip: NotSet,
            state: Set(state_str(request.state).to_owned()),
            sealed_key: Set(request.sealed_key.clone()),
            answered_at: Set(request.answered_at.map(utc)),
            created_at: NotSet,
            expires_at: NotSet,
        };
        // An approval holds the root key sealed to the new device: written under the lock.
        let txn = begin_locked(self, request.user).await?;
        let result = auth_requests::Entity::update_many()
            .set(answer)
            .filter(auth_requests::Column::Id.eq(request.id.0))
            .filter(auth_requests::Column::State.eq(state_str(from)))
            .exec(&txn)
            .await
            .store()?;
        txn.commit().await.store()?;
        Ok(result.rows_affected == 1)
    }

    async fn requests_since(
        &self,
        user: UserId,
        since: OffsetDateTime,
    ) -> Result<Vec<RecentRequest>, StoreError> {
        auth_requests::Entity::find()
            .filter(auth_requests::Column::UserId.eq(user.0))
            .filter(auth_requests::Column::CreatedAt.gt(utc(since)))
            .order_by_asc(auth_requests::Column::CreatedAt)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                row.into_domain().map(|r| RecentRequest {
                    created_at: r.created_at,
                    ip: r.ip,
                    state: r.state,
                })
            })
            .collect()
    }

    async fn purge_requests(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let result = auth_requests::Entity::delete_many()
            .filter(auth_requests::Column::ExpiresAt.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}
