//! Change a member's role, and take members out: revoke, restore, remove and leave.
//!
//! Taking out a confirmed member means they held the space key and some collection keys, and the
//! server can't make them forget. So the space is marked as awaiting a key replacement, which
//! pauses its writes, and every collection they held is marked stale. The client then makes new
//! keys and lands them with [`ReplaceKeys`](super::ReplaceKeys).

use super::authority;
use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{load_open, record};
use crate::authenticate::Actor;
use crate::policies::{check_join, refusal_in_spaces};
use crate::ports::{Clock, EventLog, TwoFactorRepo};
use kemlock_domain::policies::is_exempt;
use kemlock_domain::spaces::{
    Collection, CollectionId, CustomPermissions, Grantee, Member, MemberState, SpaceRole,
    SpaceState,
};
use kemlock_domain::{SpaceId, UserId};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct ChangeRole<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog + TwoFactorRepo, C: Clock> ChangeRole<R, V, C> {
    /// Gives `target` a role. Only an owner makes an owner, and the new owner must be confirmed:
    /// the server can't hand out the space key. The last confirmed owner can't be demoted.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        target: UserId,
        role: SpaceRole,
        custom: CustomPermissions,
    ) -> Result<Member, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let mut member = state
            .authorize_role_change(actor.user, target, role, custom)?
            .clone();
        authority::ensure_manage(&state, actor.user, target)?;
        // Someone who stops being an owner or admin is a member now, and the space's join policies
        // (two-step login, one space per member) bind members.
        if is_exempt(member.role) && !is_exempt(role) {
            check_join(&self.spaces, &self.events, target, space, role)
                .await
                .map_err(refusal_in_spaces)?;
        }
        member.role = role;
        member.custom = custom;
        let mut after = state.clone();
        replace_member(&mut after, &member);
        authority::check(&state, &after, actor.user, None)?;
        self.spaces
            .apply(SpaceChanges {
                members: vec![member.clone()],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.member.role",
            format!("{space}/{target}"),
            self.clock.now(),
        )
        .await;
        Ok(member)
    }
}

/// A collection a removed member could open, and how many live items it holds: what the admin
/// must treat as seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exposure {
    pub collection: CollectionId,
    pub live_items: usize,
}

/// What offboarding left to do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offboarded {
    /// The collections the member held a key of, with their live items, in collection order.
    pub exposed: Vec<Exposure>,
    /// Whether the space now waits for a key replacement.
    pub keys_pending: bool,
}

#[derive(Debug)]
pub struct Offboard<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog + TwoFactorRepo, C: Clock> Offboard<R, V, C> {
    /// Revokes a confirmed member: they keep their row (so they can be restored and confirmed
    /// again) but lose their keys, and the keys they held must be replaced.
    pub async fn revoke(
        &self,
        actor: &Actor,
        space: SpaceId,
        target: UserId,
    ) -> Result<Offboarded, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let mut revoked = state.authorize_revoke(actor.user, target)?.clone();
        let now = self.clock.now();
        revoked.state = MemberState::Revoked;
        revoked.revoked_at = Some(now);
        revoked.sealed_space_key = None;
        revoked.sealed_by = None;
        revoked.key_version = None;
        revoked.confirmation = None;

        authority::ensure_manage(&state, actor.user, target)?;
        let mut after = state.clone();
        replace_member(&mut after, &revoked);
        authority::check(&state, &after, actor.user, Some(target))?;
        let (changes, outcome) = self
            .exposing_changes(&state, &after, target, Some(revoked), now)
            .await?;
        self.spaces.apply(changes).await?;
        record(
            &self.events,
            actor,
            "space.member.revoke",
            format!("{space}/{target}"),
            now,
        )
        .await;
        Ok(outcome)
    }

    /// Restores a revoked member as an accepted one: an admin confirms them again, with a new
    /// fingerprint check, before any key is sealed to them.
    pub async fn restore(
        &self,
        actor: &Actor,
        space: SpaceId,
        target: UserId,
    ) -> Result<Member, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let mut member = state.authorize_restore(actor.user, target)?.clone();
        member.state = MemberState::Accepted;
        member.revoked_at = None;
        authority::ensure_manage(&state, actor.user, target)?;
        // A restored member is in the space again: the join policies are checked as for a join.
        check_join(&self.spaces, &self.events, target, space, member.role)
            .await
            .map_err(refusal_in_spaces)?;
        let mut after = state.clone();
        replace_member(&mut after, &member);
        authority::check(&state, &after, actor.user, None)?;
        self.spaces
            .apply(SpaceChanges {
                members: vec![member.clone()],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.member.restore",
            format!("{space}/{target}"),
            self.clock.now(),
        )
        .await;
        Ok(member)
    }

    /// Removes a member, or lets the actor leave when `target` is themselves. Their row, grants,
    /// group memberships and key copies go. When they were confirmed, the keys they held must be
    /// replaced.
    pub async fn remove(
        &self,
        actor: &Actor,
        space: SpaceId,
        target: UserId,
    ) -> Result<Offboarded, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        let was_confirmed = state.authorize_remove(actor.user, target)?.is_confirmed();
        // Leaving, or declining an invitation, is the member's own right in any state, so the
        // authority rules (which ask for a confirmed actor) are for removing someone else.
        if actor.user != target {
            authority::ensure_manage(&state, actor.user, target)?;
            let mut checked = state.clone();
            checked.members.retain(|m| m.user != target);
            checked
                .grants
                .retain(|g| g.grantee != Grantee::Member(target));
            for group in &mut checked.groups {
                group.members.remove(&target);
            }
            authority::check(&state, &checked, actor.user, Some(target))?;
        }
        let now = self.clock.now();
        let outcome = if was_confirmed {
            let mut after = state.clone();
            after.members.retain(|m| m.user != target);
            after.grants.retain(|g| match g.grantee {
                Grantee::Member(user) => user != target,
                Grantee::Group(_) => true,
            });
            for group in &mut after.groups {
                group.members.remove(&target);
            }
            let (mut changes, outcome) = self
                .exposing_changes(&state, &after, target, None, now)
                .await?;
            changes.members_removed.push(target);
            self.spaces.apply(changes).await?;
            outcome
        } else {
            self.spaces
                .apply(SpaceChanges {
                    members_removed: vec![target],
                    ..SpaceChanges::new(space)
                })
                .await?;
            Offboarded {
                exposed: Vec::new(),
                keys_pending: state.writes_paused(),
            }
        };
        record(
            &self.events,
            actor,
            "space.member.remove",
            format!("{space}/{target}"),
            now,
        )
        .await;
        Ok(outcome)
    }

    /// The changes that follow from `target` losing their keys: their copies go, the collections
    /// they held are marked stale, and the space waits for a key replacement.
    async fn exposing_changes(
        &self,
        before: &SpaceState,
        after: &SpaceState,
        target: UserId,
        member: Option<Member>,
        now: time::OffsetDateTime,
    ) -> Result<(SpaceChanges, Offboarded), SpacesError> {
        let holders = self.spaces.holders(before.space.id).await?;
        let held: Vec<CollectionId> = holders
            .iter()
            .filter(|(_, user)| *user == target)
            .map(|(collection, _)| *collection)
            .collect();
        let delta = after.key_delta(&holders);
        let items = self.spaces.space_items(before.space.id).await?;
        let mut live: BTreeMap<CollectionId, usize> = BTreeMap::new();
        for item in items.iter().filter(|i| !i.deleted) {
            if let Some(collection) = item.collection {
                *live.entry(collection).or_default() += 1;
            }
        }
        let mut exposed: Vec<Exposure> = held
            .iter()
            .map(|collection| Exposure {
                collection: *collection,
                live_items: live.get(collection).copied().unwrap_or(0),
            })
            .collect();
        exposed.sort_by_key(|e| e.collection);

        // Everyone whose copy is lost (the target's, in practice) leaves the keys they held.
        let mut space = before.space.clone();
        if space.keys_pending_since.is_none() {
            space.keys_pending_since = Some(now);
        }
        space.updated_at = now;
        let mut stale: Vec<Collection> = Vec::new();
        for id in delta.stale_collections() {
            if let Some(collection) = before.collection(id)
                && collection.stale_since.is_none()
            {
                let mut marked = collection.clone();
                marked.stale_since = Some(now);
                stale.push(marked);
            }
        }
        let changes = SpaceChanges {
            space: Some(space),
            members: member.into_iter().collect(),
            collections: stale,
            key_copies_removed: delta.lost.iter().copied().collect(),
            ..SpaceChanges::new(before.space.id)
        };
        Ok((
            changes,
            Offboarded {
                exposed,
                keys_pending: true,
            },
        ))
    }
}

fn replace_member(state: &mut SpaceState, member: &Member) {
    if let Some(slot) = state.members.iter_mut().find(|m| m.user == member.user) {
        *slot = member.clone();
    }
}
