//! What a use case can fail with. The API layer maps each variant to a status and a problem type.

use crate::ports::{CryptoError, StoreError};
use kemlock_domain::{ItemError, ItemId, Revision, SetupError, SpaceId};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    /// The request is well-formed JSON but breaks a rule; the text says which, never why a
    /// secret failed.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// Wrong credentials, code or token. Deliberately says nothing more.
    #[error("unauthorized")]
    Unauthorized,
    /// A session ended for a reason the device should show: `"refresh-token-reuse"`,
    /// `"device-key-changed"`, `"expired"`, `"account-disabled"`, `"account-being-deleted"` or
    /// `"security-stamp-changed"`.
    #[error("session ended: {0}")]
    SessionEnded(&'static str),
    #[error("forbidden")]
    Forbidden,
    /// An admin disabled the account (or it came from Vaultwarden disabled): no session, whatever
    /// the credentials.
    #[error("the account is disabled")]
    AccountDisabled,
    /// The account's owner deleted it and its grace period is running: no session until an admin
    /// cancels the deletion or the account is erased. Said only to whoever proved the credentials.
    #[error("the account is being deleted")]
    AccountBeingDeleted,
    /// A space the account is an ordinary member of requires single sign-on, so this way in is
    /// closed to it.
    #[error("space {space} requires single sign-on")]
    SsoRequired { space: SpaceId },
    #[error("not found")]
    NotFound,
    /// A write over a revision the writer hadn't seen.
    #[error("item {item} changed: stored revision is {current:?}")]
    Conflict {
        item: ItemId,
        current: Option<Revision>,
    },
    #[error("already exists")]
    Duplicate,
    /// The cursor is older than the tombstone horizon: start again without one.
    #[error("a full sync is required")]
    FullSyncRequired,
    /// Too many tries; try again after this many seconds.
    #[error("slow down: try again in {retry_after_secs} s")]
    SlowDown { retry_after_secs: u64 },
    #[error(transparent)]
    Setup(SetupError),
    /// A domain rule other than a stale revision refused an item write.
    #[error(transparent)]
    Item(ItemError),
    /// The store failed; the message is for logs only.
    #[error("store failure: {0}")]
    Store(String),
}

impl From<StoreError> for AppError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict { item, current } => AppError::Conflict { item, current },
            StoreError::Duplicate => AppError::Duplicate,
            StoreError::NotFound => AppError::NotFound,
            StoreError::Backend(message) => AppError::Store(message),
        }
    }
}

impl From<CryptoError> for AppError {
    fn from(_: CryptoError) -> Self {
        AppError::Invalid("a cryptographic message is invalid")
    }
}

impl From<SetupError> for AppError {
    fn from(e: SetupError) -> Self {
        AppError::Setup(e)
    }
}

impl AppError {
    /// An item rule failure; a stale write becomes a `Conflict` naming the item, and an id under
    /// another owner becomes `Duplicate`, as the store would answer it.
    pub fn from_item(item: ItemId, e: ItemError) -> Self {
        match e {
            ItemError::Stale { current, .. } => AppError::Conflict { item, current },
            ItemError::Taken => AppError::Duplicate,
            other => AppError::Item(other),
        }
    }
}
