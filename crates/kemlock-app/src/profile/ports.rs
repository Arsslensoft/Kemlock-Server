//! The port the profile use cases call beyond the account row: whether an identity provider owns
//! the account's name and address, the one pending change of address an account may have, and the
//! two writes that replace the account's sign-in records. `SqlStore` implements it; tests use an
//! in-memory fake.

use crate::ports::StoreError;
use kemlock_domain::{EmailChange, User, UserId};
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

    /// The pending change whose link holds the token with this SHA-256, left where it is: the
    /// link is spent by [`apply_email_change`](Self::apply_email_change), in the same write as the
    /// change it makes, so a write that does not happen leaves the link good.
    fn email_change_by_token(
        &self,
        token_hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<EmailChange>, StoreError>> + Send;

    /// Removes the account's pending change, if it has one.
    fn remove_email_change(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Replaces the account's password records with those of `after`: the OPAQUE record, the KDF
    /// settings, the root-key wrap and the security stamp (`after.updated_at` too), and drops the
    /// account's pending change of address, which was made from the old password. One write, and
    /// conditional: it happens only while the account still is as `before` read it (the same
    /// `updated_at` and security stamp), so a write of another request is never overwritten with
    /// a stale copy of the row. `false` says it did not happen for that reason, and nothing was
    /// written.
    fn replace_credentials(
        &self,
        before: &User,
        after: &User,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Applies the pending `change` of address, the way [`replace_credentials`] replaces the
    /// password's records and with the same condition: the account's address, record, settings,
    /// wrap and stamp become those of `after`; the change is spent; and the emergency-access
    /// grants follow the address, in one write. A grant in which the account is the contact, and
    /// an invitation still waiting at the old address, now name the new one (a grantor who has a
    /// grant to the new address already keeps both as they were). `false` says the account, or the
    /// change, was not as read: nothing was written and the link is still good.
    /// `Duplicate` says another account has the address now; nothing was written either.
    ///
    /// [`replace_credentials`]: Self::replace_credentials
    fn apply_email_change(
        &self,
        change: &EmailChange,
        before: &User,
        after: &User,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}
