//! `EmergencyRepo` on `emergency_access`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::owner_lock::begin_locked_at;
use crate::store::SqlStore;
use crate::tables::emergency_access;
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::unlock::{EmergencyGrant, EmergencyState, GrantId};
use kemlock_domain::{Email, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

fn into_grants(rows: Vec<emergency_access::Model>) -> Result<Vec<EmergencyGrant>, StoreError> {
    rows.into_iter()
        .map(emergency_access::Model::into_domain)
        .collect()
}

impl EmergencyRepo for SqlStore {
    /// `Duplicate` when the grantor already named that email (the unique index refuses it).
    async fn insert_grant(&self, grant: &EmergencyGrant) -> Result<(), StoreError> {
        emergency_access::Entity::insert(emergency_access::active(grant)?)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn grant(&self, id: GrantId) -> Result<Option<EmergencyGrant>, StoreError> {
        emergency_access::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(emergency_access::Model::into_domain)
            .transpose()
    }

    async fn grants_of_grantor(&self, grantor: UserId) -> Result<Vec<EmergencyGrant>, StoreError> {
        into_grants(
            emergency_access::Entity::find()
                .filter(emergency_access::Column::GrantorId.eq(grantor.0))
                .order_by_asc(emergency_access::Column::CreatedAt)
                .order_by_asc(emergency_access::Column::Id)
                .all(self.reader())
                .await
                .store()?,
        )
    }

    async fn grants_for_email(&self, email: &Email) -> Result<Vec<EmergencyGrant>, StoreError> {
        into_grants(
            emergency_access::Entity::find()
                .filter(emergency_access::Column::GranteeEmail.eq(email.as_str()))
                .order_by_asc(emergency_access::Column::CreatedAt)
                .order_by_asc(emergency_access::Column::Id)
                .all(self.reader())
                .await
                .store()?,
        )
    }

    /// `UPDATE … WHERE id = ? AND state = ?`: of the grantor's refusal and the timer's approval
    /// racing, the update that finds the old state wins and the other changes no row.
    async fn save_grant(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
    ) -> Result<bool, StoreError> {
        self.save_grant_at(grant, from, None).await
    }

    async fn save_grant_at(
        &self,
        grant: &EmergencyGrant,
        from: EmergencyState,
        key_version: Option<u32>,
    ) -> Result<bool, StoreError> {
        let mutable = emergency_access::ActiveModel {
            id: NotSet,
            grantor_id: NotSet,
            grantee_email: NotSet,
            grantee_id: Set(grant.grantee.map(|u| u.0)),
            kind: NotSet,
            wait_days: NotSet,
            state: Set(grant.state.as_str().to_owned()),
            sealed_key: Set(grant.sealed_key.clone()),
            recovery_initiated_at: Set(grant.recovery_initiated_at.map(utc)),
            created_at: NotSet,
            updated_at: Set(utc(grant.updated_at)),
        };
        // The grant may hold a box of the grantor's root key: written under the grantor's lock.
        let txn = begin_locked_at(self, grant.grantor, key_version).await?;
        let result = emergency_access::Entity::update_many()
            .set(mutable)
            .filter(emergency_access::Column::Id.eq(grant.id.0))
            .filter(emergency_access::Column::State.eq(from.as_str()))
            .exec(&txn)
            .await
            .store()?;
        txn.commit().await.store()?;
        Ok(result.rows_affected == 1)
    }

    async fn recovering_grants(&self) -> Result<Vec<EmergencyGrant>, StoreError> {
        into_grants(
            emergency_access::Entity::find()
                .filter(
                    emergency_access::Column::State.eq(EmergencyState::RecoveryInitiated.as_str()),
                )
                .order_by_asc(emergency_access::Column::RecoveryInitiatedAt)
                .all(self.reader())
                .await
                .store()?,
        )
    }

    async fn remove_grant(&self, id: GrantId) -> Result<(), StoreError> {
        emergency_access::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
