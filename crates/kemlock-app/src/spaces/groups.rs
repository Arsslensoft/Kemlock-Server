//! Groups: named sets of members that a collection can be granted to as one.
//!
//! Changing who is in a group changes who may hold the keys of the collections it is granted. A
//! member added to a group needs the sealed key of each such collection, and a member taken out
//! loses access, which marks those collections' keys for replacement.

use super::authority;
use super::collections::check_grantee_member;
use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{SealedCollectionKey, key_changes, load_open, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog};
use kemlock_domain::spaces::{Group, GroupId, SpaceError, check_sealed_name};
use kemlock_domain::{SpaceId, UserId};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct CreateGroup<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateGroupInput {
    /// Chosen by the client, so a failed request can be resent unchanged.
    pub id: GroupId,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    pub members: Vec<UserId>,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> CreateGroup<R, V, C> {
    /// Makes a group. A new group is granted nothing, so no key is sealed. Owners, admins and
    /// Custom members who manage groups can; the space must not be waiting for a key replacement,
    /// because the name is sealed under the space key.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        input: CreateGroupInput,
    ) -> Result<Group, SpacesError> {
        check_sealed_name(&input.name)?;
        let state = load_open(&self.spaces, space).await?;
        state.authorize_manage_groups(actor.user)?;
        state.ensure_keys_open()?;
        if state.group(input.id).is_some() {
            return Err(SpacesError::Duplicate);
        }
        let members = check_members(&state, &input.members)?;
        let group = Group {
            id: input.id,
            space,
            name: input.name,
            members,
            created_at: self.clock.now(),
        };
        self.spaces
            .apply(SpaceChanges {
                groups: vec![group.clone()],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.group.create",
            format!("{space}/{}", group.id),
            group.created_at,
        )
        .await;
        Ok(group)
    }
}

/// The members of a group: each in the space and not revoked, none twice.
fn check_members(
    state: &kemlock_domain::spaces::SpaceState,
    members: &[UserId],
) -> Result<BTreeSet<UserId>, SpaceError> {
    let mut set = BTreeSet::new();
    for user in members {
        check_grantee_member(state, *user)?;
        if !set.insert(*user) {
            return Err(SpaceError::Invalid("a member is listed twice"));
        }
    }
    Ok(set)
}

#[derive(Debug)]
pub struct EditGroup<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditGroupInput {
    /// A new name, encrypted under the current space key.
    pub name: Option<Vec<u8>>,
    /// The group's whole new member list.
    pub members: Option<Vec<UserId>>,
    /// The key of each collection the group is granted, sealed to each confirmed member the
    /// change adds to it.
    pub keys: Vec<SealedCollectionKey>,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> EditGroup<R, V, C> {
    /// Renames a group or replaces its members. Members who gain access need sealed keys; members
    /// who lose it mark the collections they held for key replacement.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        group: GroupId,
        input: EditGroupInput,
    ) -> Result<Group, SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        state.authorize_manage_groups(actor.user)?;
        let mut edited = state.group(group).cloned().ok_or(SpacesError::NotFound)?;
        if let Some(name) = input.name {
            check_sealed_name(&name)?;
            state.ensure_keys_open()?;
            edited.name = name;
        }
        let mut changes = SpaceChanges::new(space);
        let now = self.clock.now();
        if let Some(members) = &input.members {
            edited.members = check_members(&state, members)?;
            let mut after = state.clone();
            if let Some(slot) = after.groups.iter_mut().find(|g| g.id == group) {
                slot.members = edited.members.clone();
            }
            authority::check(&state, &after, actor.user, None)?;
            let holders = self.spaces.holders(space).await?;
            let delta = after.key_delta(&holders);
            if !delta.needed.is_empty() {
                state.ensure_keys_open()?;
            }
            let keys = key_changes(&after, &delta, input.keys, now)?;
            changes.key_copies = keys.key_copies;
            changes.key_copies_removed = keys.key_copies_removed;
            changes.collections = keys.collections;
        } else if !input.keys.is_empty() {
            return Err(SpaceError::Invalid("no member change takes sealed keys").into());
        }
        changes.groups = vec![edited.clone()];
        self.spaces.apply(changes).await?;
        record(
            &self.events,
            actor,
            "space.group.edit",
            format!("{space}/{group}"),
            now,
        )
        .await;
        Ok(edited)
    }
}

#[derive(Debug)]
pub struct DeleteGroup<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> DeleteGroup<R, V, C> {
    /// Deletes a group and the grants made to it. Members who had a collection only through it
    /// lose access, so those collections' keys must be replaced.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        group: GroupId,
    ) -> Result<(), SpacesError> {
        let state = load_open(&self.spaces, space).await?;
        state.authorize_manage_groups(actor.user)?;
        if state.group(group).is_none() {
            return Err(SpacesError::NotFound);
        }
        let now = self.clock.now();
        let mut after = state.clone();
        after.groups.retain(|g| g.id != group);
        after
            .grants
            .retain(|g| g.grantee != kemlock_domain::spaces::Grantee::Group(group));
        authority::check(&state, &after, actor.user, None)?;
        let holders = self.spaces.holders(space).await?;
        let delta = after.key_delta(&holders);
        let keys = key_changes(&after, &delta, Vec::new(), now)?;
        self.spaces
            .apply(SpaceChanges {
                groups_removed: vec![group],
                collections: keys.collections,
                key_copies_removed: keys.key_copies_removed,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.group.delete",
            format!("{space}/{group}"),
            now,
        )
        .await;
        Ok(())
    }
}
