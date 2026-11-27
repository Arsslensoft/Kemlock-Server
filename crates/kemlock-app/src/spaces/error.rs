//! What a spaces use case can fail with. The API layer maps each variant to a status and a problem
//! type. [`AppError`] has no variant for a rule that pauses writes, so spaces keep their own; the
//! conversion into `AppError` is for code, like `put_item`, that returns that type.

use crate::error::AppError;
use crate::ports::StoreError;
use kemlock_domain::spaces::SpaceError;
use kemlock_domain::{ItemError, ItemId, Revision};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpacesError {
    /// A rule of the space refused the action.
    #[error(transparent)]
    Rule(#[from] SpaceError),
    /// The space, member, collection or grant isn't there.
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Duplicate,
    /// A write over a revision the writer hadn't seen.
    #[error("item {item} changed: stored revision is {current:?}")]
    StaleItem {
        item: ItemId,
        current: Option<Revision>,
    },
    /// A rule of item writes (revision, size, owner) refused a write.
    #[error(transparent)]
    Item(ItemError),
    /// The store failed; the message is for logs only.
    #[error("store failure: {0}")]
    Store(String),
}

impl From<StoreError> for SpacesError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict { item, current } => SpacesError::StaleItem { item, current },
            StoreError::Duplicate => SpacesError::Duplicate,
            StoreError::NotFound => SpacesError::NotFound,
            stale @ StoreError::StaleKeyVersion { .. } => SpacesError::Store(stale.to_string()),
            StoreError::Backend(message) if message == super::ports::OWNER_REQUIRED => {
                SpacesError::Rule(SpaceError::LastOwner)
            }
            StoreError::Backend(message) => SpacesError::Store(message),
        }
    }
}

impl SpacesError {
    /// An item rule failure; a stale write becomes `StaleItem` naming the item.
    pub fn from_item(item: ItemId, e: ItemError) -> Self {
        match e {
            ItemError::Stale { current, .. } => SpacesError::StaleItem { item, current },
            other => SpacesError::Item(other),
        }
    }
}

impl From<SpacesError> for AppError {
    fn from(e: SpacesError) -> Self {
        match e {
            // Someone outside a space learns nothing about it.
            SpacesError::Rule(SpaceError::NotAMember) | SpacesError::NotFound => AppError::NotFound,
            SpacesError::Rule(SpaceError::Forbidden(_)) => AppError::Forbidden,
            SpacesError::Rule(SpaceError::Invalid(why) | SpaceError::State(why)) => {
                AppError::Invalid(why)
            }
            SpacesError::Rule(SpaceError::KeysPending) => {
                AppError::Invalid("the space's keys must be replaced before this can be done")
            }
            SpacesError::Rule(SpaceError::StaleKeyVersion { .. }) => {
                AppError::Invalid("the collection's key was replaced; write under its new key")
            }
            SpacesError::Rule(SpaceError::FingerprintMismatch) => {
                AppError::Invalid("the fingerprint is not the one of the member's key bundle")
            }
            SpacesError::Rule(SpaceError::LastOwner) => {
                AppError::Invalid("a space needs at least one confirmed owner")
            }
            SpacesError::Duplicate => AppError::Duplicate,
            SpacesError::StaleItem { item, current } => AppError::Conflict { item, current },
            SpacesError::Item(e) => AppError::Item(e),
            SpacesError::Store(message) => AppError::Store(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stores_refusal_to_leave_no_owner_is_the_last_owner_rule() {
        let refused = StoreError::Backend(crate::spaces::OWNER_REQUIRED.to_owned());
        assert_eq!(
            SpacesError::from(refused),
            SpacesError::Rule(SpaceError::LastOwner)
        );
        assert!(matches!(
            SpacesError::from(StoreError::Backend("down".to_owned())),
            SpacesError::Store(_)
        ));
    }
}
