//! The "Require SSO" policy. Other sign-in paths (OPAQUE password, passkey, phone approval) call
//! [`RequireSso::check`] after they have identified the account and before they issue tokens.
//!
//! A space with the policy on blocks password, passkey and phone-approval sign-in for its members
//! (design, "Policies"). Its owners and admins are exempt, so someone can always get in to fix the
//! provider, and so are server admins. Second-step methods (authenticator codes, security keys)
//! only follow a first step and are not sign-in methods here.

use crate::sso::error::SsoError;
use crate::sso::model::SpaceRole;
use crate::sso::ports::{MembershipFacts, SpaceMembership};
use kemlock_domain::{SpaceId, User};

/// How an account is trying to sign in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInMethod {
    /// The identity provider. Never blocked by this policy.
    Sso,
    /// The master password, through OPAQUE or the Bitwarden hash.
    Password,
    /// A passkey, with or without PRF.
    Passkey,
    /// Approval from another device ("Log in with device").
    PhoneApproval,
    /// The key a device registered, on a replica holding a copy of the account.
    DeviceKey,
    /// A personal API key (the Bitwarden `client_credentials` grant).
    ApiKey,
}

/// The first space that requires SSO from this account for `method`, or `None` when nothing
/// blocks it. Pure: the facts come from [`MembershipFacts`].
pub fn blocking_space(spaces: &[SpaceMembership], method: SignInMethod) -> Option<SpaceId> {
    if method == SignInMethod::Sso {
        return None;
    }
    spaces
        .iter()
        .find(|m| m.require_sso && m.role < SpaceRole::Admin)
        .map(|m| m.space)
}

/// The Require SSO check, over the membership facts the spaces area provides.
#[derive(Debug)]
pub struct RequireSso<M> {
    pub membership: M,
}

impl<M: MembershipFacts> RequireSso<M> {
    /// `Ok` when `user` may sign in with `method`; `SsoError::SsoRequired` naming the space when
    /// a space they are an ordinary member of requires SSO. Server admins are exempt.
    pub async fn check(&self, user: &User, method: SignInMethod) -> Result<(), SsoError> {
        if method == SignInMethod::Sso || user.is_admin() {
            return Ok(());
        }
        let spaces = self.membership.spaces_of(user.id).await?;
        match blocking_space(&spaces, method) {
            Some(space) => Err(SsoError::SsoRequired { space }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(role: SpaceRole, require_sso: bool) -> SpaceMembership {
        SpaceMembership {
            space: SpaceId::random(),
            role,
            require_sso,
        }
    }

    const BLOCKED: [SignInMethod; 5] = [
        SignInMethod::Password,
        SignInMethod::Passkey,
        SignInMethod::PhoneApproval,
        SignInMethod::DeviceKey,
        SignInMethod::ApiKey,
    ];

    #[test]
    fn members_of_a_requiring_space_cannot_use_the_other_ways() {
        let m = member(SpaceRole::Member, true);
        for method in BLOCKED {
            assert_eq!(blocking_space(&[m], method), Some(m.space), "{method:?}");
        }
    }

    #[test]
    fn sso_itself_is_never_blocked() {
        let m = member(SpaceRole::Member, true);
        assert_eq!(blocking_space(&[m], SignInMethod::Sso), None);
    }

    #[test]
    fn owners_and_admins_are_exempt() {
        for role in [SpaceRole::Owner, SpaceRole::Admin] {
            let m = member(role, true);
            for method in BLOCKED {
                assert_eq!(blocking_space(&[m], method), None, "{role:?} {method:?}");
            }
        }
    }

    #[test]
    fn a_space_without_the_policy_blocks_nothing() {
        let m = member(SpaceRole::Member, false);
        for method in BLOCKED {
            assert_eq!(blocking_space(&[m], method), None);
        }
    }

    #[test]
    fn an_admin_in_one_space_is_still_bound_by_another_they_only_belong_to() {
        let free = member(SpaceRole::Owner, true);
        let bound = member(SpaceRole::Member, true);
        assert_eq!(
            blocking_space(&[free, bound], SignInMethod::Password),
            Some(bound.space)
        );
    }

    #[test]
    fn no_spaces_blocks_nothing() {
        for method in BLOCKED {
            assert_eq!(blocking_space(&[], method), None);
        }
    }
}
