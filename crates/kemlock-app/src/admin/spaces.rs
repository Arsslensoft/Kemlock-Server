//! The Spaces screen: every space with its owners and size, and a change of owner.
//!
//! A server admin is not a member of the spaces on the server and holds none of their keys, so
//! what they can do is limited to what the server can do without a key: the new owner must be a
//! confirmed member already, because the server can't hand out the space key (design, "Feature
//! feasibility", Users & spaces).

use super::audit::Audit;
use super::error::AdminError;
use super::ports::{
    AdminEventRepo, AdminSpaceRepo, AdminSpaceRow, AdminUserRepo, Mailer, SpacePage,
};
use crate::authenticate::Actor;
use crate::bitwarden::{Asker, BwInviteLinks, InviteLinkError, MemberInviteLink};
use crate::error::AppError;
use crate::ports::Clock;
use crate::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{Member, SpaceRole};
use kemlock_domain::{SpaceId, UserId};
use std::net::IpAddr;

/// The most spaces a page lists.
pub const MAX_SPACE_PAGE: u32 = 200;

/// What a change of owner did: the space as it is now, and whether the change is only queued. A space
/// with a chain takes a change of roles only as a signed record, so the change waits for the
/// space's owners or admins to sign it and the owners in `row` are still the old ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerChange {
    pub row: AdminSpaceRow,
    pub queued: bool,
}

#[derive(Debug)]
pub struct AdminSpaces<Sp, R, M, C> {
    pub spaces: Sp,
    pub repos: R,
    pub mail: M,
    pub clock: C,
}

impl<Sp, R, M, C> AdminSpaces<Sp, R, M, C>
where
    Sp: SpaceRepo,
    R: AdminSpaceRepo + AdminUserRepo + AdminEventRepo + Clone,
    M: Mailer + Clone,
    C: Clock + Clone,
{
    pub async fn list(&self, limit: u32, offset: u64) -> Result<SpacePage, AdminError> {
        Ok(self
            .repos
            .list_spaces(limit.clamp(1, MAX_SPACE_PAGE), offset)
            .await?)
    }

    pub async fn get(&self, id: SpaceId) -> Result<AdminSpaceRow, AdminError> {
        self.repos.space_row(id).await?.ok_or(AdminError::NotFound)
    }

    /// Makes `new_owner` an owner of the space. With `demote_previous` the other owners become
    /// admins, so the space has the one owner the admin named; without it the space gains an
    /// owner. The space keeps at least one confirmed owner either way.
    pub async fn change_owner(
        &self,
        actor: &Actor,
        ip: Option<IpAddr>,
        space: SpaceId,
        new_owner: UserId,
        demote_previous: bool,
    ) -> Result<OwnerChange, AdminError> {
        let state = self.spaces.load(space).await?.ok_or(AdminError::NotFound)?;
        let target = state.member(new_owner).ok_or(AdminError::State(
            "that account isn't a member of the space",
        ))?;
        if !target.is_confirmed() {
            return Err(AdminError::State(
                "the new owner must be a confirmed member: the server can't hand out the space key",
            ));
        }
        let already_owner = target.role == SpaceRole::Owner;
        let others: Vec<Member> = state
            .members
            .iter()
            .filter(|m| m.is_confirmed() && m.role == SpaceRole::Owner && m.user != new_owner)
            .cloned()
            .collect();
        if already_owner && (!demote_previous || others.is_empty()) {
            return Err(AdminError::State(
                "that member is already an owner of the space",
            ));
        }

        let mut changes = SpaceChanges::new(space);
        if !already_owner {
            let mut promoted = target.clone();
            promoted.role = SpaceRole::Owner;
            promoted.custom = Default::default();
            changes.members.push(promoted);
        }
        if demote_previous {
            for mut owner in others {
                owner.role = SpaceRole::Admin;
                owner.custom = Default::default();
                changes.members.push(owner);
            }
        }
        // On a space with a chain a role changes only by a signed record: the store keeps the change
        // for an owner's or admin's app to sign (or refuses it), and nothing has changed yet.
        let queued = self.spaces.is_chained(space).await?;
        self.spaces.apply(changes).await?;

        let audit = Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.clock.clone(),
        };
        audit
            .record(
                actor,
                ip,
                "admin.space.change_owner",
                Some(format!("{space}/{new_owner}")),
                if queued {
                    "asked to change who owns a space (queued for its admins to sign)"
                } else {
                    "changed who owns a space"
                },
            )
            .await;
        Ok(OwnerChange {
            row: self.get(space).await?,
            queued,
        })
    }

    /// The link that accepts a member's invitation to a Bitwarden organization, for a server that
    /// can't mail it: the admin copies it and hands it over. Whoever opens it accepts for that
    /// account, so it is a secret and the read is recorded like a write.
    pub async fn invite_link(
        &self,
        links: &dyn BwInviteLinks,
        actor: &Actor,
        ip: Option<IpAddr>,
        space: SpaceId,
        member: UserId,
    ) -> Result<MemberInviteLink, AdminError> {
        let link = links
            .member_link(space, member, Asker::Server)
            .await
            .map_err(|e| match e {
                InviteLinkError::NotOrganization => {
                    AdminError::State("that space isn't a Bitwarden organization")
                }
                InviteLinkError::NotFound => AdminError::NotFound,
                InviteLinkError::Forbidden(why) => AdminError::Forbidden(why),
                InviteLinkError::NotInvited => {
                    AdminError::State("that member has accepted the invitation already")
                }
                InviteLinkError::Server(message) => AdminError::App(AppError::Store(message)),
            })?;
        let audit = Audit {
            events: self.repos.clone(),
            users: self.repos.clone(),
            mail: self.mail.clone(),
            clock: self.clock.clone(),
        };
        // The link is a secret that accepts for the account: it leaves only when the event is
        // written, so a copy is never unseen.
        audit
            .record_checked(
                actor,
                ip,
                "admin.space.invite_link",
                Some(format!("{space}/{member}")),
                "copied the link that accepts a member's invitation to a Bitwarden organization",
            )
            .await?;
        Ok(link)
    }
}
