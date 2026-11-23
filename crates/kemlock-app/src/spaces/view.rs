//! Reading spaces: the list of an account's spaces, one space as its member sees it, and its
//! members. Each reader sees what their role and grants allow, and nothing of a space they aren't
//! in.

use super::error::SpacesError;
use super::ports::SpaceRepo;
use super::support::load_state;
use crate::authenticate::Actor;
use crate::ports::UserRepo;
use kemlock_domain::SpaceId;
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CustomPermissions, Group, KeyCopy, Member, MemberState, Space,
    SpaceError, SpaceRole,
};

#[derive(Debug)]
pub struct ListSpaces<R> {
    pub spaces: R,
}

/// A space and the caller's own place in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceSummary {
    pub space: Space,
    pub member: Member,
}

impl<R: SpaceRepo> ListSpaces<R> {
    /// The spaces the account has been invited to or is in (not the ones it was revoked from),
    /// oldest first.
    pub async fn execute(&self, actor: &Actor) -> Result<Vec<SpaceSummary>, SpacesError> {
        let memberships: Vec<Member> = self
            .spaces
            .memberships(actor.user)
            .await?
            .into_iter()
            .filter(|m| m.state != MemberState::Revoked)
            .collect();
        let ids: Vec<SpaceId> = memberships.iter().map(|m| m.space).collect();
        let spaces = self.spaces.spaces(&ids).await?;
        let mut out: Vec<SpaceSummary> = memberships
            .into_iter()
            .filter_map(|member| {
                spaces
                    .iter()
                    .find(|s| s.id == member.space)
                    .map(|space| SpaceSummary {
                        space: space.clone(),
                        member,
                    })
            })
            .collect();
        out.sort_by_key(|s| (s.space.created_at, s.space.id));
        Ok(out)
    }
}

#[derive(Debug)]
pub struct GetSpace<R> {
    pub spaces: R,
}

/// One space as one member sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceView {
    pub space: Space,
    /// The caller's own row, with the space key sealed to them once confirmed.
    pub me: Member,
    /// Owners and admins see every collection; everyone else the ones they are granted.
    pub collections: Vec<Collection>,
    /// Owners and admins see every group; everyone else the ones they are in.
    pub groups: Vec<Group>,
    /// The grants on the collections shown.
    pub grants: Vec<CollectionGrant>,
    /// The collection keys sealed to the caller.
    pub collection_keys: Vec<KeyCopy>,
}

impl<R: SpaceRepo> GetSpace<R> {
    /// The space. Someone who is invited or accepted sees their own row and nothing else; someone
    /// revoked, or not in the space, gets `NotFound` as if it didn't exist.
    pub async fn execute(&self, actor: &Actor, space: SpaceId) -> Result<SpaceView, SpacesError> {
        let state = load_state(&self.spaces, space).await?;
        let me = state
            .member(actor.user)
            .filter(|m| m.state != MemberState::Revoked)
            .cloned()
            .ok_or(SpacesError::NotFound)?;
        if !me.is_confirmed() {
            return Ok(SpaceView {
                space: state.space,
                me,
                collections: Vec::new(),
                groups: Vec::new(),
                grants: Vec::new(),
                collection_keys: Vec::new(),
            });
        }
        let sees_all = matches!(me.role, SpaceRole::Owner | SpaceRole::Admin);
        let collections: Vec<Collection> = state
            .collections
            .iter()
            .filter(|c| sees_all || state.access(actor.user, c.id).is_some())
            .cloned()
            .collect();
        let groups: Vec<Group> = state
            .groups
            .iter()
            .filter(|g| sees_all || g.members.contains(&actor.user))
            .cloned()
            .collect();
        let grants: Vec<CollectionGrant> = state
            .grants
            .iter()
            .filter(|g| collections.iter().any(|c| c.id == g.collection))
            .copied()
            .collect();
        let collection_keys = self.spaces.key_copies(space, actor.user).await?;
        Ok(SpaceView {
            space: state.space,
            me,
            collections,
            groups,
            grants,
            collection_keys,
        })
    }
}

#[derive(Debug)]
pub struct ListMembers<R, U> {
    pub spaces: R,
    pub users: U,
}

/// A member with the account facts a client needs to show them, compare their fingerprint and seal
/// keys to them. The bundle is public: it is what the fingerprint is made of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub member: Member,
    pub email: String,
    pub name: Option<String>,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    /// The account's current key version.
    pub user_key_version: u32,
    /// A confirmed member whose account has moved to another key version since they were
    /// confirmed: their fingerprint changed, so someone must confirm them again.
    pub needs_reconfirmation: bool,
}

impl<R: SpaceRepo, U: UserRepo> ListMembers<R, U> {
    /// The space's members. Owners, admins and Custom members who manage users see everyone,
    /// whatever their state; other confirmed members see only the confirmed ones. Someone not
    /// confirmed sees nothing.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
    ) -> Result<Vec<MemberView>, SpacesError> {
        let state = load_state(&self.spaces, space).await?;
        let me = state.confirmed_actor(actor.user)?;
        let sees_all = matches!(me.role, SpaceRole::Owner | SpaceRole::Admin)
            || (me.role == SpaceRole::Custom
                && me.custom.contains(CustomPermissions::MANAGE_USERS));

        let mut out = Vec::new();
        for member in state
            .members
            .iter()
            .filter(|m| sees_all || m.is_confirmed())
        {
            let user = self
                .users
                .by_id(member.user)
                .await?
                .ok_or(SpaceError::Invalid("a member's account is gone"))?;
            let needs_reconfirmation = member
                .confirmation
                .as_ref()
                .is_some_and(|c| member.is_confirmed() && c.member_key_version != user.key_version);
            out.push(MemberView {
                member: member.clone(),
                email: user.email.as_str().to_owned(),
                name: user.name,
                public_bundle: user.public_bundle,
                bundle_signature: user.bundle_signature,
                user_key_version: user.key_version,
                needs_reconfirmation,
            });
        }
        out.sort_by_key(|m| (m.member.invited_at, m.member.user));
        Ok(out)
    }
}
