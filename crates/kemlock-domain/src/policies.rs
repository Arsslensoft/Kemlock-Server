//! Space policies: the rules an owner or admin sets for everyone in a space.
//!
//! Policies are typed settings, one set per space ([`SpacePolicies`]), not a list of loose
//! records. Each maps onto a Bitwarden policy type (see [`PolicyType`]), so Bitwarden apps enforce
//! them from their own sync (the mapping to Bitwarden's JSON is in `kemlock-app`).
//!
//! The server enforces what it can see: who may join a space (two-step login, one space per
//! member), what Sends a member may make, and which sign-in ways Require SSO closes (that part
//! lives in `kemlock-app`'s `sso::policy`). Everything else, such as the length of the master
//! password, the vault timeout and "no export of space items", is only *reported*: a client holds
//! the key and the password, so only a client can enforce them. The "no export" switch in
//! particular is advice: anyone who can view an item can copy it.
//!
//! Which roles a policy binds follows Bitwarden and Vaultwarden: the policies that decide who may
//! join or sign in ([`require_sso`](SpacePolicies::require_sso), [`two_step`](SpacePolicies::two_step),
//! [`single_space`](SpacePolicies::single_space)) and the Send policies do not bind a space's
//! owners and admins, so someone can always get in to fix the setting. The rest bind everyone.

use crate::spaces::{MemberState, SpaceRole};
use std::collections::BTreeMap;

/// Bitwarden's policy type numbers (`PolicyType.cs`), for the ones Kemlock serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyType {
    /// Require two-step login.
    TwoFactorAuthentication,
    /// Master password requirements.
    MasterPassword,
    /// One space per member ("Single organization").
    SingleOrg,
    /// Require single sign-on.
    RequireSso,
    /// Central ownership ("Personal ownership" off).
    PersonalOwnership,
    /// Remove Send: members can't make Sends.
    DisableSend,
    /// Send options: "Always show the sender's email".
    SendOptions,
    /// Session timeout ("Maximum vault timeout").
    MaximumVaultTimeout,
    /// No export of the member's vault.
    DisablePersonalVaultExport,
    /// No PIN unlock.
    RemoveUnlockWithPin,
    /// No card items ("Restricted item types").
    RestrictedItemTypes,
}

impl PolicyType {
    /// Every type, in number order.
    pub const ALL: [PolicyType; 11] = [
        PolicyType::TwoFactorAuthentication,
        PolicyType::MasterPassword,
        PolicyType::SingleOrg,
        PolicyType::RequireSso,
        PolicyType::PersonalOwnership,
        PolicyType::DisableSend,
        PolicyType::SendOptions,
        PolicyType::MaximumVaultTimeout,
        PolicyType::DisablePersonalVaultExport,
        PolicyType::RemoveUnlockWithPin,
        PolicyType::RestrictedItemTypes,
    ];

    /// Bitwarden's number for the type.
    pub fn number(self) -> i32 {
        match self {
            PolicyType::TwoFactorAuthentication => 0,
            PolicyType::MasterPassword => 1,
            PolicyType::SingleOrg => 3,
            PolicyType::RequireSso => 4,
            PolicyType::PersonalOwnership => 5,
            PolicyType::DisableSend => 6,
            PolicyType::SendOptions => 7,
            PolicyType::MaximumVaultTimeout => 9,
            PolicyType::DisablePersonalVaultExport => 10,
            PolicyType::RemoveUnlockWithPin => 14,
            PolicyType::RestrictedItemTypes => 15,
        }
    }

    /// The type with Bitwarden's number, or `None` for a type Kemlock doesn't serve.
    pub fn from_number(number: i32) -> Option<PolicyType> {
        PolicyType::ALL.into_iter().find(|t| t.number() == number)
    }
}

/// Why a set of policies is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyInvalid(pub &'static str);

/// The most characters a master password minimum may ask for (Bitwarden's own limit).
pub const MAX_MIN_PASSWORD_LENGTH: u32 = 128;
/// The most minutes a session timeout may be: a year.
pub const MAX_TIMEOUT_MINUTES: u32 = 525_600;

/// What a client does when the session timeout runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Lock,
    LogOut,
}

impl TimeoutAction {
    pub fn as_str(self) -> &'static str {
        match self {
            TimeoutAction::Lock => "lock",
            TimeoutAction::LogOut => "logOut",
        }
    }

    pub fn parse(text: &str) -> Option<TimeoutAction> {
        match text {
            "lock" => Some(TimeoutAction::Lock),
            "logOut" => Some(TimeoutAction::LogOut),
            _ => None,
        }
    }
}

/// The master password rules. Reported to clients; the server never sees a password, so only a
/// client can check one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MasterPasswordPolicy {
    /// The fewest characters (the design's default switch is 14).
    pub min_length: Option<u32>,
    /// Bitwarden's complexity score, 0 to 4.
    pub min_complexity: Option<u8>,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    /// Whether a client also checks the password at each sign-in, not only when it is set.
    pub enforce_on_login: bool,
}

impl MasterPasswordPolicy {
    /// The design's "14-character password" switch.
    pub fn fourteen_characters() -> MasterPasswordPolicy {
        MasterPasswordPolicy {
            min_length: Some(14),
            ..MasterPasswordPolicy::default()
        }
    }

    fn check(&self) -> Result<(), PolicyInvalid> {
        if self
            .min_length
            .is_some_and(|n| n == 0 || n > MAX_MIN_PASSWORD_LENGTH)
        {
            return Err(PolicyInvalid(
                "the minimum password length must be 1 to 128 characters",
            ));
        }
        if self.min_complexity.is_some_and(|n| n > 4) {
            return Err(PolicyInvalid("the minimum complexity must be 0 to 4"));
        }
        Ok(())
    }

    /// The stricter of two rule sets: the longer minimum, the higher score, every requirement
    /// either one makes.
    fn merge(self, other: MasterPasswordPolicy) -> MasterPasswordPolicy {
        MasterPasswordPolicy {
            min_length: self.min_length.max(other.min_length),
            min_complexity: self.min_complexity.max(other.min_complexity),
            require_upper: self.require_upper || other.require_upper,
            require_lower: self.require_lower || other.require_lower,
            require_numbers: self.require_numbers || other.require_numbers,
            require_special: self.require_special || other.require_special,
            enforce_on_login: self.enforce_on_login || other.enforce_on_login,
        }
    }
}

/// Every setting of one space. The default turns everything off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpacePolicies {
    /// Members sign in through SSO only: password, passkey and phone-approval sign-in are closed
    /// to them. Owners and admins are exempt.
    pub require_sso: bool,
    /// A member needs a confirmed two-step method to join. Owners and admins are exempt.
    pub two_step: bool,
    /// The master password rules, when there are any. Reported only.
    pub master_password: Option<MasterPasswordPolicy>,
    /// A member may belong to no other space, and nobody in another space with this on may join
    /// this one. Owners and admins are exempt.
    pub single_space: bool,
    /// Clients refuse to export the space's items. Advice only: whoever can view an item can copy
    /// it, so the server cannot make this true.
    pub disable_export: bool,
    /// Members can't make Sends. Owners and admins are exempt.
    pub disable_send: bool,
    /// "Always show the sender's email": a member's Send can't hide their email. Owners and
    /// admins are exempt.
    pub always_show_email: bool,
    /// The longest session timeout clients allow, in minutes, and what happens at the end.
    /// Reported only.
    pub session_timeout_minutes: Option<u32>,
    pub session_timeout_action: Option<TimeoutAction>,
    /// Clients don't offer PIN unlock. Reported only.
    pub no_pin_unlock: bool,
    /// Clients make new items in the space, not in the member's own vault. Reported only.
    pub central_ownership: bool,
    /// Clients refuse card items. Reported only.
    pub no_card_items: bool,
}

impl SpacePolicies {
    /// Refuses a setting that makes no sense, so a stored row is always one the server can serve.
    pub fn validate(&self) -> Result<(), PolicyInvalid> {
        if let Some(mp) = &self.master_password {
            mp.check()?;
        }
        if self
            .session_timeout_minutes
            .is_some_and(|m| m == 0 || m > MAX_TIMEOUT_MINUTES)
        {
            return Err(PolicyInvalid(
                "the session timeout must be 1 minute to a year",
            ));
        }
        if self.session_timeout_action.is_some() && self.session_timeout_minutes.is_none() {
            return Err(PolicyInvalid(
                "a session timeout action needs a timeout in minutes",
            ));
        }
        Ok(())
    }

    /// Whether any setting is on.
    pub fn any(&self) -> bool {
        *self != SpacePolicies::default()
    }

    /// The Bitwarden types this set turns on, in number order.
    pub fn enabled_types(&self) -> Vec<PolicyType> {
        PolicyType::ALL
            .into_iter()
            .filter(|t| self.is_enabled(*t))
            .collect()
    }

    /// Whether the policy of this Bitwarden type is on.
    pub fn is_enabled(&self, kind: PolicyType) -> bool {
        match kind {
            PolicyType::TwoFactorAuthentication => self.two_step,
            PolicyType::MasterPassword => self.master_password.is_some(),
            PolicyType::SingleOrg => self.single_space,
            PolicyType::RequireSso => self.require_sso,
            PolicyType::PersonalOwnership => self.central_ownership,
            PolicyType::DisableSend => self.disable_send,
            PolicyType::SendOptions => self.always_show_email,
            PolicyType::MaximumVaultTimeout => self.session_timeout_minutes.is_some(),
            PolicyType::DisablePersonalVaultExport => self.disable_export,
            PolicyType::RemoveUnlockWithPin => self.no_pin_unlock,
            PolicyType::RestrictedItemTypes => self.no_card_items,
        }
    }
}

/// Whether a role is exempt from the policies that decide who may join or sign in, and from the
/// Send policies. Owners and admins are, in Bitwarden and in Vaultwarden.
pub fn is_exempt(role: SpaceRole) -> bool {
    matches!(role, SpaceRole::Owner | SpaceRole::Admin)
}

/// A person's place in one space, with that space's policies: what [`EffectivePolicies::of`] folds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundBy {
    pub role: SpaceRole,
    pub state: MemberState,
    pub policies: SpacePolicies,
}

/// What binds one person after every space they belong to has had its say. Served to clients as
/// `GET /kem/v1/policies`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectivePolicies {
    /// A space they are an ordinary member of requires SSO.
    pub require_sso: bool,
    /// A space requires two-step login of them.
    pub two_step: bool,
    /// The strictest master password rules among their spaces.
    pub master_password: Option<MasterPasswordPolicy>,
    pub single_space: bool,
    pub disable_export: bool,
    pub disable_send: bool,
    pub always_show_email: bool,
    /// The shortest session timeout among their spaces, with the action of the space that set it.
    pub session_timeout_minutes: Option<u32>,
    pub session_timeout_action: Option<TimeoutAction>,
    pub no_pin_unlock: bool,
    pub central_ownership: bool,
    pub no_card_items: bool,
}

impl EffectivePolicies {
    /// Folds a person's spaces. Spaces where they have only been invited, or were revoked from,
    /// bind them in nothing. Policies that report only apply from the moment they accept
    /// (Bitwarden's "accepted and confirmed"); the Send policies, as in Vaultwarden, only once
    /// confirmed.
    pub fn of(spaces: &[BoundBy]) -> EffectivePolicies {
        let mut out = EffectivePolicies::default();
        for space in spaces {
            let accepted = matches!(space.state, MemberState::Accepted | MemberState::Confirmed);
            if !accepted {
                continue;
            }
            let p = &space.policies;
            let exempt = is_exempt(space.role);
            let confirmed = space.state == MemberState::Confirmed;
            out.require_sso |= p.require_sso && !exempt;
            out.two_step |= p.two_step && !exempt;
            out.single_space |= p.single_space && !exempt;
            out.disable_send |= p.disable_send && !exempt && confirmed;
            out.always_show_email |= p.always_show_email && !exempt && confirmed;
            out.disable_export |= p.disable_export;
            out.no_pin_unlock |= p.no_pin_unlock;
            out.central_ownership |= p.central_ownership;
            out.no_card_items |= p.no_card_items;
            if let Some(mp) = p.master_password {
                out.master_password = Some(match out.master_password {
                    Some(seen) => seen.merge(mp),
                    None => mp,
                });
            }
            if let Some(minutes) = p.session_timeout_minutes
                && out
                    .session_timeout_minutes
                    .is_none_or(|seen| minutes < seen)
            {
                out.session_timeout_minutes = Some(minutes);
                out.session_timeout_action = p.session_timeout_action;
            }
        }
        out
    }
}

/// The policies of each of several spaces, by space, for the lookups that join a person's
/// memberships to them.
pub type PoliciesBySpace = BTreeMap<crate::ids::SpaceId, SpacePolicies>;

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(role: SpaceRole, state: MemberState, policies: SpacePolicies) -> BoundBy {
        BoundBy {
            role,
            state,
            policies,
        }
    }

    #[test]
    fn bitwarden_numbers_round_trip_and_unknown_ones_are_refused() {
        for t in PolicyType::ALL {
            assert_eq!(PolicyType::from_number(t.number()), Some(t));
        }
        let numbers: Vec<i32> = PolicyType::ALL.iter().map(|t| t.number()).collect();
        assert_eq!(numbers, vec![0, 1, 3, 4, 5, 6, 7, 9, 10, 14, 15]);
        assert_eq!(PolicyType::from_number(2), None);
        assert_eq!(PolicyType::from_number(99), None);
        assert_eq!(PolicyType::from_number(-1), None);
    }

    #[test]
    fn the_default_turns_everything_off() {
        let p = SpacePolicies::default();
        assert!(!p.any());
        assert!(p.enabled_types().is_empty());
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn enabled_types_follow_the_switches() {
        let p = SpacePolicies {
            two_step: true,
            master_password: Some(MasterPasswordPolicy::fourteen_characters()),
            single_space: true,
            always_show_email: true,
            ..SpacePolicies::default()
        };
        assert_eq!(
            p.enabled_types(),
            vec![
                PolicyType::TwoFactorAuthentication,
                PolicyType::MasterPassword,
                PolicyType::SingleOrg,
                PolicyType::SendOptions,
            ]
        );
    }

    #[test]
    fn nonsense_settings_are_refused() {
        let with = |mp: MasterPasswordPolicy| SpacePolicies {
            master_password: Some(mp),
            ..SpacePolicies::default()
        };
        let long = MasterPasswordPolicy {
            min_length: Some(129),
            ..MasterPasswordPolicy::default()
        };
        assert!(with(long).validate().is_err());
        let zero = MasterPasswordPolicy {
            min_length: Some(0),
            ..MasterPasswordPolicy::default()
        };
        assert!(with(zero).validate().is_err());
        let score = MasterPasswordPolicy {
            min_complexity: Some(5),
            ..MasterPasswordPolicy::default()
        };
        assert!(with(score).validate().is_err());
        assert!(
            with(MasterPasswordPolicy::fourteen_characters())
                .validate()
                .is_ok()
        );

        let timeout = |minutes, action| SpacePolicies {
            session_timeout_minutes: minutes,
            session_timeout_action: action,
            ..SpacePolicies::default()
        };
        assert!(timeout(Some(0), None).validate().is_err());
        assert!(
            timeout(Some(MAX_TIMEOUT_MINUTES + 1), None)
                .validate()
                .is_err()
        );
        assert!(timeout(None, Some(TimeoutAction::Lock)).validate().is_err());
        assert!(
            timeout(Some(15), Some(TimeoutAction::LogOut))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn owners_and_admins_are_exempt_from_the_joining_and_send_policies() {
        let strict = SpacePolicies {
            require_sso: true,
            two_step: true,
            single_space: true,
            disable_send: true,
            always_show_email: true,
            disable_export: true,
            ..SpacePolicies::default()
        };
        for role in [SpaceRole::Owner, SpaceRole::Admin] {
            let e = EffectivePolicies::of(&[bound(role, MemberState::Confirmed, strict.clone())]);
            assert!(!e.require_sso && !e.two_step && !e.single_space, "{role:?}");
            assert!(!e.disable_send && !e.always_show_email, "{role:?}");
            // The rest bind everyone.
            assert!(e.disable_export, "{role:?}");
        }
        for role in [SpaceRole::Custom, SpaceRole::Member] {
            let e = EffectivePolicies::of(&[bound(role, MemberState::Confirmed, strict.clone())]);
            assert!(e.require_sso && e.two_step && e.single_space, "{role:?}");
            assert!(e.disable_send && e.always_show_email && e.disable_export);
        }
    }

    #[test]
    fn an_invitation_or_a_revocation_binds_nobody() {
        let strict = SpacePolicies {
            two_step: true,
            disable_export: true,
            ..SpacePolicies::default()
        };
        for state in [MemberState::Invited, MemberState::Revoked] {
            let e = EffectivePolicies::of(&[bound(SpaceRole::Member, state, strict.clone())]);
            assert_eq!(e, EffectivePolicies::default(), "{state:?}");
        }
    }

    #[test]
    fn send_policies_wait_for_confirmation_but_the_others_bind_at_acceptance() {
        let strict = SpacePolicies {
            disable_send: true,
            always_show_email: true,
            two_step: true,
            ..SpacePolicies::default()
        };
        let e = EffectivePolicies::of(&[bound(SpaceRole::Member, MemberState::Accepted, strict)]);
        assert!(e.two_step);
        assert!(!e.disable_send && !e.always_show_email);
    }

    #[test]
    fn the_strictest_master_password_and_the_shortest_timeout_win() {
        let a = SpacePolicies {
            master_password: Some(MasterPasswordPolicy {
                min_length: Some(14),
                require_upper: true,
                ..MasterPasswordPolicy::default()
            }),
            session_timeout_minutes: Some(60),
            session_timeout_action: Some(TimeoutAction::Lock),
            ..SpacePolicies::default()
        };
        let b = SpacePolicies {
            master_password: Some(MasterPasswordPolicy {
                min_length: Some(10),
                min_complexity: Some(3),
                require_numbers: true,
                enforce_on_login: true,
                ..MasterPasswordPolicy::default()
            }),
            session_timeout_minutes: Some(15),
            session_timeout_action: Some(TimeoutAction::LogOut),
            ..SpacePolicies::default()
        };
        let e = EffectivePolicies::of(&[
            bound(SpaceRole::Member, MemberState::Confirmed, a),
            bound(SpaceRole::Admin, MemberState::Confirmed, b),
        ]);
        assert_eq!(
            e.master_password,
            Some(MasterPasswordPolicy {
                min_length: Some(14),
                min_complexity: Some(3),
                require_upper: true,
                require_lower: false,
                require_numbers: true,
                require_special: false,
                enforce_on_login: true,
            })
        );
        assert_eq!(e.session_timeout_minutes, Some(15));
        assert_eq!(e.session_timeout_action, Some(TimeoutAction::LogOut));
    }

    #[test]
    fn timeout_actions_round_trip() {
        for a in [TimeoutAction::Lock, TimeoutAction::LogOut] {
            assert_eq!(TimeoutAction::parse(a.as_str()), Some(a));
        }
        assert_eq!(TimeoutAction::parse("sleep"), None);
    }
}
