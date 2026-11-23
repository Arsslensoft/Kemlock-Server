//! The authorization step for writing an item into a space.
//!
//! `ItemWrite::apply` allows only the actor's own vault, so `put_item` and `put_batch` refuse every
//! space item. This step is what lets a space write through: the actor must be a confirmed member
//! with edit on the item's collection, in a space and collection that aren't waiting for a key
//! replacement, writing under the collection's current key.
//!
//! **How `put_item` should call it, once spaces are merged.** After `put_item` has read the stored
//! item and before it calls `write.apply`:
//!
//! ```text
//! if let Owner::Space(space) = write.owner {
//!     SpaceAccess::load_and_authorize(&self.spaces, actor.user, space, collection, key_version).await?;
//!     draft = apply_space_write(write, stored.as_ref(), actor.user, limits, now)?;
//!     item  = self.spaces.put_item(draft, collection).await?;   // stores the item and its collection together
//! } else { /* the vault path, unchanged */ }
//! ```
//!
//! [`PutSpaceItem`](super::put_item::PutSpaceItem) is that sequence as a use case, so the item
//! routes can call it for a space item without `put_item` changing first. `collection` comes from
//! the wire next to `owner`.

use super::error::SpacesError;
use super::ports::SpaceRepo;
use super::support::load_state;
use kemlock_domain::spaces::{CollectionId, SpaceError, SpaceState};
use kemlock_domain::{SpaceId, UserId};

/// The check, as functions: no state of its own.
#[derive(Clone, Copy, Debug)]
pub struct SpaceAccess;

impl SpaceAccess {
    /// Whether `actor` may write into `collection` of an already loaded space: a confirmed member
    /// with edit on the collection, neither space nor collection awaiting a key replacement, and
    /// `key_version` (`None` for a delete) the collection's current one.
    pub fn authorize_write(
        state: &SpaceState,
        actor: UserId,
        collection: CollectionId,
        key_version: Option<u32>,
    ) -> Result<(), SpaceError> {
        state
            .authorize_item_write(actor, collection, key_version)
            .map(|_| ())
    }

    /// Loads the space and runs [`authorize_write`](Self::authorize_write), returning the state
    /// for callers that need more of it (a move between collections checks the old one too). A
    /// space that isn't there and a space the actor isn't in both read as `NotFound`/`NotAMember`,
    /// which the API shows alike.
    pub async fn load_and_authorize<R: SpaceRepo>(
        spaces: &R,
        actor: UserId,
        space: SpaceId,
        collection: CollectionId,
        key_version: Option<u32>,
    ) -> Result<SpaceState, SpacesError> {
        let state = load_state(spaces, space).await?;
        Self::authorize_write(&state, actor, collection, key_version)?;
        Ok(state)
    }
}
