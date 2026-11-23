//! Who may read and change an owner's duplicate data.
//!
//! - A person's own vault: only that person.
//! - A space: a confirmed member reads (and sees only items of collections they hold a grant on);
//!   writing the tags of an item takes edit on its collection, as writing the item does; turning
//!   server matching on or off takes an owner or an admin of the space.
//!
//! Someone outside an owner learns nothing about it: the answer is `NotFound`.

use super::error::DedupError;
use crate::spaces::support::load_state;
use crate::spaces::{SpaceAccess, SpaceRepo};
use kemlock_domain::spaces::{SpaceRole, SpaceState};
use kemlock_domain::{ItemId, Owner, UserId};
use std::collections::BTreeSet;

/// What the actor wants to do with the owner's duplicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// Read the groups, the answers and the settings.
    Read,
    /// Turn server matching on or off.
    Settings,
}

/// Checks the actor against the owner. For a space it returns the loaded state, which the
/// item-level checks below use.
pub(crate) async fn authorize<R: SpaceRepo>(
    spaces: &R,
    actor: UserId,
    owner: Owner,
    need: Need,
) -> Result<Option<SpaceState>, DedupError> {
    match owner {
        Owner::User(user) if user == actor => Ok(None),
        Owner::User(_) => Err(DedupError::NotFound),
        Owner::Space(space) => {
            let state = load_state(spaces, space).await?;
            let member = state.confirmed_actor(actor)?;
            if need == Need::Settings && !matches!(member.role, SpaceRole::Owner | SpaceRole::Admin)
            {
                return Err(DedupError::Forbidden(
                    "only a space's owners and admins can turn server matching on or off",
                ));
            }
            Ok(Some(state))
        }
    }
}

/// The items among `items` that `actor` may see in `state`'s space: those in a collection they
/// hold a grant on.
pub(crate) async fn visible<R: SpaceRepo>(
    spaces: &R,
    state: &SpaceState,
    actor: UserId,
    items: &[ItemId],
) -> Result<BTreeSet<ItemId>, DedupError> {
    let placed = spaces.item_collections(items).await?;
    Ok(placed
        .into_iter()
        .filter(|(_, collection)| state.access(actor, *collection).is_some())
        .map(|(item, _)| item)
        .collect())
}

/// Whether `actor` may write the tags of `item` in `state`'s space: edit on its collection, in a
/// space and collection that aren't waiting for a key replacement.
pub(crate) async fn authorize_item_write<R: SpaceRepo>(
    spaces: &R,
    state: &SpaceState,
    actor: UserId,
    item: ItemId,
) -> Result<(), DedupError> {
    let collection = spaces
        .item_collections(&[item])
        .await?
        .into_iter()
        .next()
        .map(|(_, collection)| collection)
        .ok_or(DedupError::NotFound)?;
    SpaceAccess::authorize_write(state, actor, collection, None)?;
    Ok(())
}
