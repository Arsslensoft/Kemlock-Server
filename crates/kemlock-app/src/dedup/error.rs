//! What a duplicate-cleaner use case can fail with. The API layer maps each variant to a status and
//! a problem type.

use crate::ports::StoreError;
use crate::spaces::SpacesError;
use kemlock_domain::dedup::TagError;
use kemlock_domain::spaces::SpaceError;
use kemlock_domain::{ItemId, Revision};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DedupError {
    /// The item, owner, space or answer isn't there, or isn't the actor's to know about.
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Forbidden(&'static str),
    /// The request breaks a rule; the text says which.
    #[error("{0}")]
    Invalid(&'static str),
    /// Server matching is off for the owner, so there is nothing to upload or group.
    #[error("server matching is off for this owner")]
    MatchingOff,
    /// The tags were made under another dedup key version than the owner's current one.
    #[error("the owner's dedup key is at version {current}")]
    StaleVersion { current: u32 },
    /// A wrap of the account's root key was for a key version the account no longer has.
    #[error("the account's key version is {current}")]
    StaleAccountKeys { current: u32 },
    /// The item isn't at the revision the caller named (`If-Match`).
    #[error("item {item} changed: stored revision is {current:?}")]
    StaleItem {
        item: ItemId,
        current: Option<Revision>,
    },
    /// The store failed; the message is for logs only.
    #[error("store failure: {0}")]
    Store(String),
}

impl From<StoreError> for DedupError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict { item, current } => DedupError::StaleItem { item, current },
            StoreError::NotFound => DedupError::NotFound,
            StoreError::Duplicate => DedupError::Invalid("that already exists"),
            StoreError::StaleKeyVersion { current } => DedupError::StaleAccountKeys { current },
            StoreError::Backend(message) => DedupError::Store(message),
        }
    }
}

impl From<SpaceError> for DedupError {
    fn from(e: SpaceError) -> Self {
        match e {
            // Someone outside a space learns nothing about it.
            SpaceError::NotAMember => DedupError::NotFound,
            SpaceError::Forbidden(why) => DedupError::Forbidden(why),
            SpaceError::Invalid(why) | SpaceError::State(why) => DedupError::Invalid(why),
            SpaceError::KeysPending => {
                DedupError::Invalid("the space's keys must be replaced before this can be done")
            }
            SpaceError::StaleKeyVersion { .. } => {
                DedupError::Invalid("the collection's key was replaced")
            }
            SpaceError::FingerprintMismatch | SpaceError::LastOwner => {
                DedupError::Invalid("the space refused this")
            }
        }
    }
}

impl From<SpacesError> for DedupError {
    fn from(e: SpacesError) -> Self {
        match e {
            SpacesError::Rule(rule) => rule.into(),
            SpacesError::NotFound => DedupError::NotFound,
            SpacesError::Duplicate => DedupError::Invalid("that already exists"),
            SpacesError::StaleAccountKeys { current } => DedupError::StaleAccountKeys { current },
            SpacesError::StaleItem { item, current } => DedupError::StaleItem { item, current },
            SpacesError::Item(_) => DedupError::Invalid("the item write was refused"),
            SpacesError::Join(_) => DedupError::Invalid("the space's policies refuse this"),
            SpacesError::Store(message) => DedupError::Store(message),
        }
    }
}

impl From<TagError> for DedupError {
    fn from(e: TagError) -> Self {
        match e {
            TagError::TooMany => DedupError::Invalid("an item carries at most 64 tags"),
            TagError::BadDismissal => {
                DedupError::Invalid("a dismissal names between two and 500 items")
            }
        }
    }
}
