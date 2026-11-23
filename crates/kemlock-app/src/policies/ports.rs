//! The ports the policy use cases call. `kemlock-store-sql` implements [`PolicyRepo`]; tests use an
//! in-memory fake. Names are distinct from every other port's so one store implements them all.

use crate::ports::StoreError;
use kemlock_domain::policies::{PoliciesBySpace, SpacePolicies};
use kemlock_domain::{SpaceId, UserId};
use std::future::Future;
use time::OffsetDateTime;

/// A space's policies as stored, with when and by whom they were last set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredPolicies {
    pub policies: SpacePolicies,
    /// `None` for a space nobody has set policies for.
    pub updated_at: Option<OffsetDateTime>,
    pub updated_by: Option<UserId>,
}

/// The `space_policy_settings` table: one row per space.
pub trait PolicyRepo: Send + Sync {
    /// The space's policies; everything off, with no date, when it has none.
    fn space_policies(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<StoredPolicies, StoreError>> + Send;

    /// Replaces the space's policies.
    fn put_space_policies(
        &self,
        space: SpaceId,
        policies: &SpacePolicies,
        by: UserId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The policies of each of these spaces that has any set. A space with no row is not in the
    /// map, which reads as everything off.
    fn policies_of_spaces(
        &self,
        spaces: &[SpaceId],
    ) -> impl Future<Output = Result<PoliciesBySpace, StoreError>> + Send;

    /// Whether the space requires SSO. The narrow read the sign-in checks used before the general
    /// policies existed; `SpaceRepo::require_sso_of` is the same read.
    fn policy_require_sso(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async move { Ok(self.space_policies(space).await?.policies.require_sso) }
    }

    /// Turns Require SSO on or off and leaves every other setting as it is.
    /// `SpaceRepo::set_require_sso` is the same write, without an actor.
    fn set_policy_require_sso(
        &self,
        space: SpaceId,
        on: bool,
        by: UserId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async move {
            let mut policies = self.space_policies(space).await?.policies;
            policies.require_sso = on;
            self.put_space_policies(space, &policies, by, at).await
        }
    }
}
