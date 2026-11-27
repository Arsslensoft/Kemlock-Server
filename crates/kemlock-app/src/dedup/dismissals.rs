//! "Not duplicates": save an answer for a group, or take it back.

use super::access::{Need, authorize, visible};
use super::error::DedupError;
use super::ports::{DismissalStore, TagStore};
use crate::authenticate::Actor;
use crate::ports::{Clock, ItemStore};
use crate::spaces::SpaceRepo;
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::{Dismissal, DismissalId, ItemId, Owner};

/// Saves "these items are not duplicates" for an owner.
#[derive(Debug)]
pub struct Dismiss<T, D, I, R, C> {
    pub tags: T,
    pub dismissals: D,
    pub items: I,
    pub spaces: R,
    pub clock: C,
}

impl<T: TagStore, D: DismissalStore, I: ItemStore, R: SpaceRepo, C: Clock> Dismiss<T, D, I, R, C> {
    /// Saves the answer for `items`, two to 500 items of `owner` that the actor may see. Server
    /// matching must be on: with it off there are no server groups to answer about.
    pub async fn execute(
        &self,
        actor: &Actor,
        owner: Owner,
        items: Vec<ItemId>,
    ) -> Result<Dismissal, DedupError> {
        let state = authorize(&self.spaces, actor.user, owner, Need::Read).await?;
        if !self.tags.settings(owner).await?.enabled {
            return Err(DedupError::MatchingOff);
        }
        let dismissal = Dismissal::new(owner, items, actor.user, self.clock.now())?;
        for id in &dismissal.items {
            let item = self.items.get(*id).await?;
            if item.is_none_or(|i| i.owner != owner) {
                return Err(DedupError::NotFound);
            }
        }
        if let Some(state) = &state {
            let seen = visible(&self.spaces, state, actor.user, &dismissal.items).await?;
            if seen.len() != dismissal.items.len() {
                return Err(DedupError::NotFound);
            }
        }
        self.dismissals.add(&dismissal).await?;
        Ok(dismissal)
    }
}

/// Takes a "Not duplicates" answer back.
#[derive(Debug)]
pub struct Undismiss<D, R> {
    pub dismissals: D,
    pub spaces: R,
}

impl<D: DismissalStore, R: SpaceRepo> Undismiss<D, R> {
    /// Removes the answer. In a space only its owners and admins may, and whoever gave it: a member
    /// who may only view could otherwise take back what the others answered. The vault's own
    /// answers are the account's.
    pub async fn execute(&self, actor: &Actor, id: DismissalId) -> Result<(), DedupError> {
        let dismissal = self.dismissals.get(id).await?.ok_or(DedupError::NotFound)?;
        let state = authorize(&self.spaces, actor.user, dismissal.owner, Need::Read).await?;
        if let Some(state) = &state
            && dismissal.by != actor.user
            && !state
                .member(actor.user)
                .is_some_and(|m| matches!(m.role, SpaceRole::Owner | SpaceRole::Admin))
        {
            return Err(DedupError::Forbidden(
                "only a space's owners and admins, or whoever gave the answer, take it back",
            ));
        }
        if self.dismissals.remove(id).await? {
            Ok(())
        } else {
            Err(DedupError::NotFound)
        }
    }
}
