//! A requested change of the sign-in address, kept until the link mailed to the new address is
//! opened (docs/crypto.md, "Changing the master password and the sign-in address").
//!
//! OPAQUE binds an account's password record to the email it was registered under, so a new
//! address needs a new record. The client makes it while it still has the password, and the server
//! holds it here, with the new KDF settings and the root-key wrap that go with it, until the person
//! proves they own the new address by opening the link. Only then does it replace the account's
//! own. An account has at most one pending change; asking again replaces it.

use crate::ids::UserId;
use crate::user::{Email, KdfParams};
use std::fmt;
use time::{Duration, OffsetDateTime};

/// A change of address that waits for its link to be opened.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailChange {
    pub user: UserId,
    /// The address the account will have.
    pub email: Email,
    /// SHA-256 of the token in the mailed link: the token itself is never stored.
    pub token_hash: [u8; 32],
    /// The OPAQUE record registered under the new address.
    pub opaque_record: Vec<u8>,
    /// The Argon2id settings and salt of the master key the record and the wrap were made with.
    pub kdf: KdfParams,
    /// The root key wrapped under that master key and the new record's export key.
    pub wrapped_root_key: Vec<u8>,
    /// The account's key version when the change was asked for, which the wrap was made for. A
    /// root-key rotation replaces the root key, so a change of another version is never applied.
    pub key_version: u32,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl EmailChange {
    /// How long the link works.
    pub const LIFETIME: Duration = Duration::hours(24);

    /// Whether the link has run out at `now`.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}

impl fmt::Debug for EmailChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token's hash, the record and the wrap stay out of logs.
        f.debug_struct("EmailChange")
            .field("user", &self.user)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn change(expires_at: OffsetDateTime) -> EmailChange {
        EmailChange {
            user: UserId::random(),
            email: Email::parse("new@example.org").expect("an address"),
            token_hash: [7; 32],
            opaque_record: vec![1, 2, 3],
            kdf: KdfParams::new_account([4; 16]),
            wrapped_root_key: vec![5; 92],
            key_version: 1,
            requested_at: datetime!(2026-11-25 10:00 UTC),
            expires_at,
        }
    }

    #[test]
    fn a_link_works_until_its_last_moment() {
        let c = change(datetime!(2026-11-26 10:00 UTC));
        assert!(!c.is_expired(datetime!(2026-11-26 9:59:59 UTC)));
        assert!(c.is_expired(datetime!(2026-11-26 10:00 UTC)));
        assert!(c.is_expired(datetime!(2026-11-27 10:00 UTC)));
    }

    #[test]
    fn a_link_lives_a_day() {
        assert_eq!(EmailChange::LIFETIME, Duration::hours(24));
    }

    #[test]
    fn debug_shows_no_secret() {
        let text = format!("{:?}", change(datetime!(2026-11-26 10:00 UTC)));
        assert!(!text.contains("token_hash"), "{text}");
        assert!(!text.contains("opaque_record"), "{text}");
    }
}
