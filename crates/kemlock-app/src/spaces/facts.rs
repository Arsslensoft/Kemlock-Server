//! The membership facts the Require SSO policy reads, over the spaces repository: an account's
//! confirmed memberships with their roles, and whether each space requires SSO.
//!
//! Only a confirmed member is bound by a space's policy: someone who was invited, accepted but
//! wasn't confirmed, or was revoked holds no key of the space and isn't one of its members yet
//! (or any more), so the space can't lock them out of their own vault.

use super::ports::SpaceRepo;
use crate::ports::StoreError;
use crate::sso::model::SpaceRole as SsoRole;
use crate::sso::ports::{MembershipFacts, SpaceMembership};
use kemlock_domain::UserId;
use kemlock_domain::spaces::{MemberState, SpaceRole};
use std::collections::BTreeSet;

/// `MembershipFacts` over a [`SpaceRepo`].
#[derive(Clone, Debug)]
pub struct SpaceFacts<R> {
    pub spaces: R,
}

/// The policy's coarser role: owners and admins are exempt, everyone else is an ordinary member.
/// A custom role is an ordinary member here: its permissions manage users or collections, and
/// don't reach the provider.
fn policy_role(role: SpaceRole) -> SsoRole {
    match role {
        SpaceRole::Owner => SsoRole::Owner,
        SpaceRole::Admin => SsoRole::Admin,
        SpaceRole::Custom | SpaceRole::Member => SsoRole::Member,
    }
}

impl<R: SpaceRepo> MembershipFacts for SpaceFacts<R> {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        let confirmed: Vec<_> = self
            .spaces
            .memberships(user)
            .await?
            .into_iter()
            .filter(|m| m.state == MemberState::Confirmed)
            .collect();
        if confirmed.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = confirmed.iter().map(|m| m.space).collect();
        let requiring: BTreeSet<_> = self
            .spaces
            .require_sso_of(&ids)
            .await?
            .into_iter()
            .collect();
        Ok(confirmed
            .iter()
            .map(|m| SpaceMembership {
                space: m.space,
                role: policy_role(m.role),
                require_sso: requiring.contains(&m.space),
            })
            .collect())
    }
}
