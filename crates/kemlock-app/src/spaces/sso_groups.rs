//! The admin's SSO group rules, applied to an account at sign-in: the provider's `groups` claim
//! maps to spaces and roles (`sso::map_groups`), and this invites the account to each space it
//! isn't in yet.
//!
//! An invitation grants nothing. The account still accepts it, and someone already in the space
//! compares its key fingerprint and confirms it ([`ConfirmMember`](super::ConfirmMember)) before
//! any key is sealed to it, so a provider, or a rule, can add a name to a space's list but never
//! a reader to its data. Nothing here confirms anyone.

use super::chain::{ExternalChangeMode, ExternalSource, PendingChange, PendingExternal};
use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use crate::ports::{Clock, Event, EventLog};
use crate::sso::model::{GroupAssignment, SpaceRole as RuleRole};
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee, Member,
    SpaceRole,
};
use kemlock_domain::{SpaceId, UserId};

#[derive(Debug)]
pub struct ApplyGroupRules<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

/// The role a rule's role becomes in an invitation. A space never invites an owner (an owner is a
/// confirmed member someone promotes), so a rule that names Owner invites an Admin and leaves the
/// promotion to the space's owners.
fn invited_role(role: RuleRole) -> SpaceRole {
    match role {
        RuleRole::Member => SpaceRole::Member,
        RuleRole::Admin | RuleRole::Owner => SpaceRole::Admin,
    }
}

impl<R: SpaceRepo, V: EventLog, C: Clock> ApplyGroupRules<R, V, C> {
    /// Invites `user` to every space of `assignments` that has no row for them, in the mapped role
    /// and with a View grant on each mapped collection that exists and isn't awaiting a key
    /// replacement. Returns the spaces they were invited to.
    ///
    /// A row that exists, in any state, is left as it is: a space's own people decide roles,
    /// grants, confirmations and removals (a member who was revoked or who left is not asked
    /// back at every sign-in, and a confirmed member's grants need keys only a client can seal).
    /// A space the rules name that no longer exists is skipped. The invitation's `invited_by` is
    /// the account itself, which is how a member list tells a rule's invitation from a person's.
    pub async fn execute(
        &self,
        user: UserId,
        assignments: &[GroupAssignment],
    ) -> Result<Vec<SpaceId>, SpacesError> {
        let mut invited = Vec::new();
        for assignment in assignments {
            let space = assignment.space;
            let Some(state) = self.spaces.load(space).await? else {
                tracing::debug!(%space, "a group rule names a space that isn't there");
                continue;
            };
            if state.member(user).is_some() {
                continue;
            }
            // A space with a chain changes only by signed records: the provider's rule can't
            // sign one. What happens instead is the setting's (docs/crypto.md, "Changes from
            // outside Kemlock clients"); sign-in never fails over it.
            if self.spaces.is_chained(space).await? {
                if self.spaces.external_change_mode().await? == ExternalChangeMode::Queue {
                    self.spaces
                        .queue_external(PendingExternal {
                            id: uuid::Uuid::new_v4(),
                            space,
                            source: ExternalSource::Sso,
                            queued_at: self.clock.now(),
                            requested_by: None,
                            via: "SSO group rule".to_owned(),
                            account: user,
                            email: None,
                            change: PendingChange::AddMember {
                                role: invited_role(assignment.role),
                                custom: CustomPermissions::NONE,
                                grants: assignment
                                    .collections
                                    .iter()
                                    .map(|id| (CollectionId(*id), CollectionPermission::View))
                                    .collect(),
                            },
                        })
                        .await?;
                } else {
                    tracing::debug!(%space, "a group rule names a space with a chain: skipped");
                }
                continue;
            }
            let now = self.clock.now();
            let grants: Vec<CollectionGrant> = assignment
                .collections
                .iter()
                .map(|id| CollectionId(*id))
                .filter(|id| {
                    state
                        .collection(*id)
                        .is_some_and(|c| state.ensure_collection_open(c).is_ok())
                })
                .map(|collection| CollectionGrant {
                    collection,
                    grantee: Grantee::Member(user),
                    permission: CollectionPermission::View,
                })
                .collect();
            let member = Member::invited(
                space,
                user,
                invited_role(assignment.role),
                CustomPermissions::NONE,
                user,
                now,
            );
            self.spaces
                .apply(SpaceChanges {
                    members: vec![member],
                    grants,
                    ..SpaceChanges::new(space)
                })
                .await?;
            let event = Event {
                actor: Some(user),
                device: None,
                action: "space.member.sso-invite",
                target: Some(format!("{space}/{user}")),
                at: now,
            };
            if let Err(e) = self.events.record(event).await {
                tracing::warn!(error = %e, "couldn't record an SSO group invitation");
            }
            invited.push(space);
        }
        Ok(invited)
    }
}
