//! Invite and accept. An invitation grants nothing: no key is sealed to anyone until an admin has
//! compared their fingerprint and confirmed them ([`ConfirmMember`](super::ConfirmMember)).

use super::authority;
use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use super::support::{load_open, load_state, record};
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog, UserRepo};
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee, Member,
    MemberState, SpaceError, SpaceRole,
};
use kemlock_domain::{Email, SpaceId, UserId};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct InviteMember<R, U, V, C> {
    pub spaces: R,
    pub users: U,
    pub events: V,
    pub clock: C,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteInput {
    /// The invitee's account email: the invitee must already have an account. The API mails
    /// them a notice once the invitation is stored (the notice names the inviter by email and not
    /// the space, whose name is ciphertext).
    pub email: String,
    pub role: SpaceRole,
    /// For a Custom role; empty otherwise.
    pub custom: CustomPermissions,
    /// Collections the invitee is granted once confirmed. The grants exist at once, the keys come
    /// with the confirmation.
    pub grants: Vec<(CollectionId, CollectionPermission)>,
}

impl<R: SpaceRepo, U: UserRepo, V: EventLog, C: Clock> InviteMember<R, U, V, C> {
    /// Invites an account. An owner or admin invites members, Custom members and admins (not
    /// owners); a Custom member with Manage users invites members and lesser Custom members. Every
    /// grant needs the inviter to manage that collection.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        input: InviteInput,
    ) -> Result<Member, SpacesError> {
        let email = Email::parse(&input.email)
            .map_err(|_| SpacesError::Rule(SpaceError::Invalid("not an email address")))?;
        let invitee = self
            .users
            .by_email(&email)
            .await?
            .ok_or(SpacesError::NotFound)?;
        let state = load_open(&self.spaces, space).await?;
        state.authorize_invite(actor.user, invitee.id, input.role, input.custom)?;

        let mut seen = BTreeSet::new();
        let mut grants = Vec::with_capacity(input.grants.len());
        for (collection, permission) in input.grants {
            let target = state.authorize_manage_collection(actor.user, collection)?;
            state.ensure_collection_open(target)?;
            if !seen.insert(collection) {
                return Err(SpaceError::Invalid("a collection is granted twice").into());
            }
            grants.push(CollectionGrant {
                collection,
                grantee: Grantee::Member(invitee.id),
                permission,
            });
        }

        let now = self.clock.now();
        let member = Member::invited(space, invitee.id, input.role, input.custom, actor.user, now);
        let mut after = state.clone();
        after.members.push(member.clone());
        after.grants.extend(grants.iter().copied());
        authority::check(&state, &after, actor.user, None)?;
        self.spaces
            .apply(SpaceChanges {
                members: vec![member.clone()],
                grants,
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.member.invite",
            format!("{space}/{}", invitee.id),
            now,
        )
        .await;
        Ok(member)
    }
}

#[derive(Debug)]
pub struct AcceptInvitation<R, V, C> {
    pub spaces: R,
    pub events: V,
    pub clock: C,
}

impl<R: SpaceRepo, V: EventLog, C: Clock> AcceptInvitation<R, V, C> {
    /// The invitee accepts: they wait to be confirmed and hold no key. Accepting twice is fine.
    /// Declining is [`Offboard::remove`](super::Offboard::remove) on oneself.
    pub async fn execute(&self, actor: &Actor, space: SpaceId) -> Result<Member, SpacesError> {
        let state = load_state(&self.spaces, space).await?;
        let mut member = state
            .member(actor.user)
            .cloned()
            .ok_or(SpacesError::NotFound)?;
        match member.state {
            MemberState::Accepted => return Ok(member),
            MemberState::Invited => {}
            MemberState::Confirmed | MemberState::Revoked => {
                return Err(SpaceError::State("there is no invitation to accept").into());
            }
        }
        let now = self.clock.now();
        member.state = MemberState::Accepted;
        member.accepted_at = Some(now);
        self.spaces
            .apply(SpaceChanges {
                members: vec![member.clone()],
                ..SpaceChanges::new(space)
            })
            .await?;
        record(
            &self.events,
            actor,
            "space.member.accept",
            format!("{space}/{}", actor.user),
            now,
        )
        .await;
        Ok(member)
    }
}

#[derive(Debug)]
pub struct ResendInvitation<R> {
    pub spaces: R,
}

impl<R: SpaceRepo> ResendInvitation<R> {
    /// Checks that `actor` may have `target`'s invitation sent again, and returns the member. It
    /// sends nothing: the API mails the notice, and limits how often. Reads only, so a space with
    /// a chain is fine.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        target: UserId,
    ) -> Result<Member, SpacesError> {
        let state = load_state(&self.spaces, space).await?;
        Ok(state.authorize_resend(actor.user, target)?.clone())
    }
}
