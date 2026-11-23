//! Policies: Bitwarden's policy types, which apps enforce, and the checks the server makes.
//!
//! The types are Vaultwarden 1.37.5's, plus Require SSO (4) and Remove export (10), which the
//! design serves "as Bitwarden policy types, so its apps enforce them too". Require SSO is also
//! read by the sign-in paths through [`OrgMembership`].

use super::json::policy_json;
use super::model::{ACCEPTED, ADMIN, CONFIRMED, INVITED, MemberDoc, Org, level};
use crate::app::{App, BwStore};
use crate::error::{BwError, BwResult};
use kemlock_app::ports::{StoreError, TwoFactorRepo};
use kemlock_app::sso::{MembershipFacts, SpaceMembership};
use kemlock_domain::{SpaceId, UserId};
use serde_json::Value;

pub(crate) const TWO_FACTOR: i32 = 0;
pub(crate) const MASTER_PASSWORD: i32 = 1;
pub(crate) const SINGLE_ORG: i32 = 3;
pub(crate) const REQUIRE_SSO: i32 = 4;
pub(crate) const DISABLE_SEND: i32 = 6;
pub(crate) const SEND_OPTIONS: i32 = 7;
/// Account recovery administration: members may enrol, and admins reset an enrolled member.
pub(crate) const RESET_PASSWORD: i32 = 8;
pub(crate) const FILL_ASSIST: i32 = 22;

/// The policy types a client may read or set.
const TYPES: [i32; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 14, 15, 16, 17, 20, 22];

pub(crate) fn is_known(ptype: i32) -> bool {
    TYPES.contains(&ptype)
}

/// The organizations an account is a confirmed member of, with the member's document.
async fn confirmed_orgs<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Vec<(Org, MemberDoc)>> {
    let mut out = Vec::new();
    for org in app.orgs_of(user).await? {
        if let Some(doc) = org.member(user).filter(|m| m.confirmed()).cloned() {
            out.push((org, doc));
        }
    }
    Ok(out)
}

/// Whether the account is in an organization that has the policy on and isn't an owner or admin
/// of it, leaving out `exclude`. Only meaningful for policies that bind members but not admins.
pub(crate) async fn is_applicable_to_user<S: BwStore>(
    app: &App<S>,
    user: UserId,
    ptype: i32,
    exclude: Option<SpaceId>,
) -> BwResult<bool> {
    for org in app.orgs_of(user).await? {
        if Some(org.id) == exclude || !org.policy_enabled(ptype) {
            continue;
        }
        if org
            .member(user)
            .is_some_and(|m| m.confirmed() && level(m.atype) < level(ADMIN))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `OrgPolicy::check_user_allowed`: the two-step and single-organization policies, checked when a
/// member is accepted, confirmed, restored or has their role changed. `doc` is the member as it
/// would be after the change.
pub(crate) async fn check_user_allowed<S: BwStore>(
    app: &App<S>,
    org: &Org,
    user: UserId,
    doc: &MemberDoc,
    action: &str,
) -> BwResult<()> {
    if level(doc.atype) >= level(ADMIN) || doc.status <= INVITED {
        return Ok(());
    }
    if org.policy_enabled(TWO_FACTOR) && TwoFactorRepo::list(&app.store, user).await?.is_empty() {
        return Err(BwError::msg(format!(
            "Cannot {action} because 2FA is required (membership {user})"
        )));
    }
    if is_applicable_to_user(app, user, SINGLE_ORG, Some(org.id)).await? {
        return Err(BwError::msg(format!(
            "Cannot {action} because another organization policy forbids it (membership {user})"
        )));
    }
    if org.policy_enabled(SINGLE_ORG) {
        let others = app
            .orgs_of(user)
            .await?
            .iter()
            .filter(|o| o.id != org.id)
            .filter(|o| {
                o.member(user)
                    .is_some_and(|m| m.status == ACCEPTED || m.status == CONFIRMED)
            })
            .count();
        if others > 0 {
            return Err(BwError::msg(format!(
                "Cannot {action} because the organization policy forbids being part of other organization (membership {user})"
            )));
        }
    }
    Ok(())
}

/// The policies of the organizations the account belongs to: confirmed memberships only, or
/// accepted ones too (`policiesNew`).
pub(crate) async fn policies_json<S: BwStore>(
    app: &App<S>,
    user: UserId,
    include_accepted: bool,
) -> BwResult<Vec<Value>> {
    let mut out = Vec::new();
    for org in app.orgs_of(user).await? {
        let counts = org
            .member(user)
            .is_some_and(|m| m.status == CONFIRMED || (include_accepted && m.status == ACCEPTED));
        if !counts {
            continue;
        }
        for (ptype, policy) in &org.policies {
            out.push(policy_json(&org.id.to_string(), *ptype, policy));
        }
    }
    Ok(out)
}

/// Whether the account is in an organization that has the Disable Send policy on and is not an
/// owner or admin of it.
pub(crate) async fn disable_send_applies<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<bool> {
    is_applicable_to_user(app, user, DISABLE_SEND, None).await
}

/// Whether the account is in an organization whose Send Options policy forbids hiding the email
/// address, and is not an owner or admin of it.
pub(crate) async fn hide_email_disabled<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<bool> {
    for (org, _) in confirmed_orgs(app, user).await? {
        let Some(policy) = org.policy(SEND_OPTIONS).filter(|p| p.enabled) else {
            continue;
        };
        let member_binds = org
            .member(user)
            .is_some_and(|m| level(m.atype) < level(ADMIN));
        if !member_binds {
            continue;
        }
        match serde_json::from_str::<Value>(&policy.data) {
            Ok(data) => {
                let flag = data
                    .get("disableHideEmail")
                    .or_else(|| data.get("DisableHideEmail"))
                    .and_then(Value::as_bool);
                if flag == Some(true) {
                    return Ok(true);
                }
            }
            Err(_) => tracing::error!("failed to read a Send Options policy's data"),
        }
    }
    Ok(false)
}

/// The Require SSO facts of an account, for [`kemlock_app::sso::policy::RequireSso`]: wire it
/// to the sign-in paths with the server's store, `OrgMembership(store)`.
#[derive(Clone, Debug)]
pub struct OrgMembership<S>(pub S);

impl<S: BwStore> MembershipFacts for OrgMembership<S> {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        use kemlock_app::spaces::SpaceRepo;
        let mut out = Vec::new();
        for member in SpaceRepo::memberships(&self.0, user).await? {
            if member.state == kemlock_domain::spaces::MemberState::Revoked {
                continue;
            }
            let Some(text) = self
                .0
                .doc_get(
                    member.space.0,
                    super::model::KIND_POLICY,
                    &REQUIRE_SSO.to_string(),
                )
                .await?
            else {
                continue;
            };
            let enabled = serde_json::from_str::<super::model::PolicyDoc>(&text)
                .map(|p| p.enabled)
                .unwrap_or(false);
            let role = match member.role {
                kemlock_domain::spaces::SpaceRole::Owner => kemlock_app::sso::SpaceRole::Owner,
                kemlock_domain::spaces::SpaceRole::Admin => kemlock_app::sso::SpaceRole::Admin,
                _ => kemlock_app::sso::SpaceRole::Member,
            };
            out.push(SpaceMembership {
                space: member.space,
                role,
                require_sso: enabled,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_are_vaultwardens_plus_require_sso_and_remove_export() {
        for known in [0, 1, 3, 4, 6, 7, 8, 10, 22] {
            assert!(is_known(known), "{known}");
        }
        for unknown in [9, 11, 12, 13, 18, 19, 21, 23, -1] {
            assert!(!is_known(unknown), "{unknown}");
        }
    }
}
