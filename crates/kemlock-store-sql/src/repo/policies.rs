//! `PolicyRepo` on `space_policy_settings`, and the membership facts the Require SSO check reads.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::policies;
use crate::tables::space_tables::members;
use kemlock_app::policies::{PolicyRepo, StoredPolicies};
use kemlock_app::ports::StoreError;
use kemlock_app::sso::{MembershipFacts, SpaceMembership};
use kemlock_domain::policies::{PoliciesBySpace, SpacePolicies};
use kemlock_domain::spaces::{MemberState, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

impl PolicyRepo for SqlStore {
    async fn space_policies(&self, space: SpaceId) -> Result<StoredPolicies, StoreError> {
        match policies::Entity::find_by_id(space.0)
            .one(self.reader())
            .await
            .store()?
        {
            Some(row) => row.into_domain(),
            None => Ok(StoredPolicies::default()),
        }
    }

    async fn put_space_policies(
        &self,
        space: SpaceId,
        value: &SpacePolicies,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let conflict = OnConflict::column(policies::Column::SpaceId)
            .update_columns([
                policies::Column::RequireSso,
                policies::Column::TwoStep,
                policies::Column::SingleSpace,
                policies::Column::DisableExport,
                policies::Column::DisableSend,
                policies::Column::AlwaysShowEmail,
                policies::Column::NoPinUnlock,
                policies::Column::CentralOwnership,
                policies::Column::NoCardItems,
                policies::Column::MpOn,
                policies::Column::MpMinLength,
                policies::Column::MpMinComplexity,
                policies::Column::MpRequireUpper,
                policies::Column::MpRequireLower,
                policies::Column::MpRequireNumbers,
                policies::Column::MpRequireSpecial,
                policies::Column::MpEnforceOnLogin,
                policies::Column::TimeoutMinutes,
                policies::Column::TimeoutAction,
                policies::Column::UpdatedAt,
                policies::Column::UpdatedBy,
            ])
            .to_owned();
        let written = policies::Entity::insert(policies::active(space.0, value, by, at))
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

    async fn policies_of_spaces(&self, spaces: &[SpaceId]) -> Result<PoliciesBySpace, StoreError> {
        if spaces.is_empty() {
            return Ok(PoliciesBySpace::new());
        }
        let ids: Vec<Uuid> = spaces.iter().map(|id| id.0).collect();
        let mut out = PoliciesBySpace::new();
        for row in policies::Entity::find()
            .filter(policies::Column::SpaceId.is_in(ids))
            .all(self.reader())
            .await
            .store()?
        {
            out.insert(SpaceId(row.space_id), row.policies()?);
        }
        Ok(out)
    }
}

impl SqlStore {
    /// Which of these spaces have Require SSO on, read from `space_policy_settings`: the one place
    /// the policy is kept, for `SpaceRepo::require_sso_of` and the sign-in checks alike.
    pub(crate) async fn spaces_requiring_sso(
        &self,
        spaces: &[SpaceId],
    ) -> Result<Vec<SpaceId>, StoreError> {
        if spaces.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = spaces.iter().map(|id| id.0).collect();
        Ok(policies::Entity::find()
            .filter(policies::Column::SpaceId.is_in(ids))
            .filter(policies::Column::RequireSso.eq(true))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| SpaceId(row.space_id))
            .collect())
    }

    /// Turns Require SSO on or off in `space_policy_settings`, in one statement: a space with no
    /// row gets one with everything else off, and a space with one keeps its other settings. No
    /// one is named as having set it (see `PolicyRepo::put_space_policies` for a write that does).
    pub(crate) async fn upsert_require_sso(
        &self,
        space: SpaceId,
        on: bool,
    ) -> Result<(), StoreError> {
        let fresh = SpacePolicies {
            require_sso: on,
            ..SpacePolicies::default()
        };
        let row = policies::active_by(space.0, &fresh, None, OffsetDateTime::now_utc());
        let conflict = OnConflict::column(policies::Column::SpaceId)
            .update_columns([policies::Column::RequireSso, policies::Column::UpdatedAt])
            .to_owned();
        match policies::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            // MySQL counts a replaced row with identical values as zero rows affected.
            Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }
}

/// The Require SSO check reads, for an account, each space it has been confirmed in, the role it
/// holds there and whether the space requires SSO. An invitation, an acceptance no admin has
/// confirmed and a revoked membership are not being in a space: whoever sent the invitation could
/// otherwise close the invitee's password sign-in.
impl MembershipFacts for SqlStore {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        let rows = members::Entity::find()
            .filter(members::Column::UserId.eq(user.0))
            .filter(members::Column::State.eq(MemberState::Confirmed.as_str()))
            .all(self.reader())
            .await
            .store()?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<SpaceId> = rows.iter().map(|m| SpaceId(m.space_id)).collect();
        let required = self.spaces_requiring_sso(&ids).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let role = match SpaceRole::parse(&row.role) {
                Some(SpaceRole::Owner) => kemlock_app::sso::SpaceRole::Owner,
                Some(SpaceRole::Admin) => kemlock_app::sso::SpaceRole::Admin,
                Some(SpaceRole::Custom | SpaceRole::Member) => kemlock_app::sso::SpaceRole::Member,
                None => {
                    return Err(StoreError::Backend(
                        "stored member role is not valid".to_owned(),
                    ));
                }
            };
            out.push(SpaceMembership {
                space: SpaceId(row.space_id),
                role,
                require_sso: required.contains(&SpaceId(row.space_id)),
            });
        }
        Ok(out)
    }
}
