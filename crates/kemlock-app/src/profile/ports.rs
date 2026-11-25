//! The port the profile use cases call beyond the account row: whether an identity provider owns
//! the account's name and address, and the one pending change of address an account may have.
//! `SqlStore` implements it; tests use an in-memory fake.

use crate::ports::StoreError;
use kemlock_domain::{EmailChange, UserId};
use std::future::Future;

pub trait ProfileRepo: Send + Sync {
    /// Whether the account is linked to a single sign-on identity. Its name and address then come
    /// from the identity provider and are not the account's to change.
    fn has_sso_identity(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Keeps the account's pending change of address, in place of the one it had.
    fn put_email_change(
        &self,
        change: &EmailChange,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The account's pending change, whether its link has run out or not.
    fn email_change_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<EmailChange>, StoreError>> + Send;

    /// Removes the pending change whose link holds the token with this SHA-256 and returns it:
    /// one conditional delete, so of two openings of the link at once one gets the change and the
    /// other `None`. A link is good once.
    fn take_email_change(
        &self,
        token_hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<EmailChange>, StoreError>> + Send;

    /// Removes the account's pending change, if it has one.
    fn remove_email_change(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
