//! Sync owners: whose items a device syncs.
//!
//! A device sees its user's own vault and every space its user is a confirmed member of.
//! `SyncDelta` reads each of those owners from the vector the device's cursor holds for it, so
//! this list is all it needs from the spaces. A space an account was invited to, or accepted but
//! wasn't confirmed in, or was revoked from, is not in it (on a chained space, "confirmed" is what
//! the chain says, not the members table: see `SpaceRepo::chain_confirmed_members`): its items arrive only once the account
//! holds keys that can open them, and a space that leaves the list leaves the cursor too, so a
//! member restored later is sent the space's history again, from empty. Members receive every
//! item's envelope of a space they are confirmed in, including the collections they aren't
//! granted: they can't open those, and they need the envelopes to check the space's signed
//! manifest. For the same reason a collection grant made later changes nothing about which items
//! the device syncs: it adds a key to envelopes the device already holds.
//!
//! `SyncDelta::execute` asks [`owners_of`] for that list and passes it to `latest_each`,
//! `changes_since_each` and `purged_each`.

use super::error::SpacesError;
use super::ports::SpaceRepo;
use kemlock_domain::spaces::MemberState;
use kemlock_domain::{Owner, SpaceId, UserId};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct SyncOwners<R> {
    pub spaces: R,
}

impl<R: SpaceRepo> SyncOwners<R> {
    /// The account's own vault first, then each confirmed space in id order.
    pub async fn execute(&self, user: UserId) -> Result<Vec<Owner>, SpacesError> {
        owners_of(&self.spaces, user).await
    }
}

/// [`SyncOwners::execute`] for a caller that only borrows the repository.
pub async fn owners_of<R: SpaceRepo>(spaces: &R, user: UserId) -> Result<Vec<Owner>, SpacesError> {
    let mut confirmed: BTreeSet<SpaceId> = BTreeSet::new();
    for membership in spaces.memberships(user).await? {
        if membership.state != MemberState::Confirmed {
            continue;
        }
        // On a chained space only the chain says who is confirmed: a row that an outside change
        // left confirmed, with no `confirm` record behind it, would hand a key-less account every
        // envelope of the space.
        if let Some(by_chain) = spaces.chain_confirmed_members(membership.space).await?
            && !by_chain.contains(&user)
        {
            continue;
        }
        confirmed.insert(membership.space);
    }
    let mut owners = Vec::with_capacity(confirmed.len() + 1);
    owners.push(Owner::User(user));
    owners.extend(confirmed.into_iter().map(Owner::Space));
    Ok(owners)
}
