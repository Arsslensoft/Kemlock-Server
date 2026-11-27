//! The join check: what a space's policies say about someone about to join it.
//!
//! Call [`JoinGuard::check`] when a person accepts an invitation and when an admin confirms them,
//! with the role they have in the space. It is what Vaultwarden runs as `check_user_allowed`, and it
//! refuses in these cases:
//!
//! - the space requires two-step login and the person has no confirmed two-step method;
//! - the space allows one space per member and the person is in another (accepted or confirmed);
//! - the person is in another space that allows one space per member, unless they are an owner or
//!   admin there.
//!
//! In a space with a chain, "confirmed" is what the chain says: a row the members table calls
//! confirmed counts only when the chain holds that member (`spaces::chain_confirmed`), so a change
//! from outside Kemlock clients that left a row confirmed without a record does not count.
//!
//! A person joining as an owner or admin is never refused, so someone can always get in to change
//! the policy. Invitations and revoked memberships don't count as being in a space.

use super::error::PoliciesError;
use super::ports::PolicyRepo;
use crate::ports::TwoFactorRepo;
use crate::spaces::{SpaceChainRepo, SpaceRepo, chain_confirmed};
use kemlock_domain::policies::is_exempt;
use kemlock_domain::spaces::{Member, MemberState, SpaceRole};
use kemlock_domain::{SpaceId, UserId};

#[derive(Debug)]
pub struct JoinGuard<R, P, F> {
    pub spaces: R,
    pub policies: P,
    pub two_factor: F,
}

impl<R: SpaceRepo + SpaceChainRepo, P: PolicyRepo, F: TwoFactorRepo> JoinGuard<R, P, F> {
    /// `Ok` when `user` may join `space` as `role` under the policies of `space` and of every
    /// space they are already in.
    pub async fn check(
        &self,
        user: UserId,
        space: SpaceId,
        role: SpaceRole,
    ) -> Result<(), PoliciesError> {
        if is_exempt(role) {
            return Ok(());
        }
        // A space another server is the home of binds nobody here, and doesn't count toward what
        // the spaces of this server say (single space and the rest).
        let memberships = self.spaces.memberships(user).await?;
        let binding = self
            .spaces
            .spaces_binding_here(&memberships.iter().map(|m| m.space).collect::<Vec<_>>())
            .await?;
        if !self.spaces.spaces_binding_here(&[space]).await?.contains(&space) {
            return Ok(());
        }
        let here = self.policies.space_policies(space).await?.policies;
        let mut others = Vec::new();
        for m in memberships {
            if m.space != space && binding.contains(&m.space) && self.is_in(&m).await? {
                others.push(m);
            }
        }

        if here.two_step
            && !self
                .two_factor
                .list(user)
                .await?
                .iter()
                .any(|method| method.enabled)
        {
            return Err(PoliciesError::TwoStepRequired);
        }
        if here.single_space && !others.is_empty() {
            return Err(PoliciesError::SingleSpace);
        }
        if !others.is_empty() {
            let ids: Vec<SpaceId> = others.iter().map(|m| m.space).collect();
            let theirs = self.policies.policies_of_spaces(&ids).await?;
            let barred = others.iter().any(|m| {
                !is_exempt(m.role) && theirs.get(&m.space).is_some_and(|p| p.single_space)
            });
            if barred {
                return Err(PoliciesError::OtherSpaceSingle);
            }
        }
        Ok(())
    }

    /// Whether the row puts its member in that space: accepted, or confirmed. On a space with a
    /// chain a confirmed row counts only when the chain holds the member as confirmed.
    async fn is_in(&self, row: &Member) -> Result<bool, PoliciesError> {
        match row.state {
            MemberState::Accepted => Ok(true),
            MemberState::Confirmed => Ok(chain_confirmed(&self.spaces, row.space)
                .await?
                .is_none_or(|confirmed| confirmed.contains(&row.user))),
            _ => Ok(false),
        }
    }
}
