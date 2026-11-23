//! Passkeys: WebAuthn credentials an account signs in with, and the copy of the root key a
//! passkey with the PRF extension can open (docs/crypto.md, "The passkey PRF wrap of the root
//! key").
//!
//! A passkey signs the person in. Only a passkey whose authenticator supports PRF also opens the
//! vault: the client wraps one more copy of the root key under a key made from the PRF output and
//! the server keeps that copy as opaque bytes, never able to open it.

use crate::ids::UserId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A passkey's id on this server. The WebAuthn credential id is separate: the authenticator
/// makes that one, and it can be long.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasskeyId(pub Uuid);

impl PasskeyId {
    /// A new random id (UUID v4).
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Debug for PasskeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PasskeyId({})", self.0)
    }
}

impl std::fmt::Display for PasskeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for PasskeyId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// The root key wrapped under a passkey's PRF output (docs/crypto.md). The server stores the
/// bytes and the key version the client wrapped them for, and never opens them.
#[derive(Clone, PartialEq, Eq)]
pub struct PrfWrap {
    /// `nonce(12) ‖ ciphertext(64) ‖ tag(16)`.
    pub wrapped_key: Vec<u8>,
    /// The account's key version the wrap's AAD names. A copy for another version than the
    /// account's current one is stale: no client can open it.
    pub key_version: u32,
}

impl std::fmt::Debug for PrfWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrfWrap")
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl PrfWrap {
    /// The length of a wrapped root key: a 12-byte nonce, the 64-byte root key and a 16-byte tag.
    pub const WRAPPED_KEY_LEN: usize = 12 + 64 + 16;

    /// Whether `wrapped_key` is the length a wrap of the root key must be.
    pub fn is_well_formed(&self) -> bool {
        self.wrapped_key.len() == Self::WRAPPED_KEY_LEN
    }
}

/// One passkey of an account.
#[derive(Clone, PartialEq, Eq)]
pub struct Passkey {
    pub id: PasskeyId,
    pub user: UserId,
    /// The WebAuthn credential id, the raw bytes. Unique across the server.
    pub credential_id: Vec<u8>,
    /// The name the person gave it ("Work laptop").
    pub name: String,
    /// The credential as the WebAuthn library keeps it: the public key, the signature counter and
    /// the flags. Public data; the server needs it to check a sign-in.
    pub credential: Vec<u8>,
    /// The PRF copy of the root key, when the authenticator supports PRF and the client sent one.
    pub prf_wrap: Option<PrfWrap>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("id", &self.id)
            .field("user", &self.user)
            .field("name", &self.name)
            .field("prf", &self.prf_wrap.is_some())
            .finish_non_exhaustive()
    }
}

impl Passkey {
    /// An account may register this many (Bitwarden's limit too).
    pub const MAX_PER_ACCOUNT: usize = 5;
    pub const MAX_NAME_CHARS: usize = 64;

    /// A name as kept: trimmed, control characters dropped, at most 64 characters. `None` when
    /// nothing is left, because a passkey with no name can't be told from the others in a list.
    pub fn clean_name(raw: &str) -> Option<String> {
        let cleaned: String = raw
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(Self::MAX_NAME_CHARS)
            .collect();
        let cleaned = cleaned.trim().to_owned();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    }

    /// Whether the account's current key version is the one this passkey's PRF copy was wrapped
    /// for, so the copy is worth handing to a client.
    pub fn wrap_is_current(&self, key_version: u32) -> bool {
        self.prf_wrap
            .as_ref()
            .is_some_and(|w| w.key_version == key_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(wrap: Option<PrfWrap>) -> Passkey {
        Passkey {
            id: PasskeyId::random(),
            user: UserId::random(),
            credential_id: vec![1, 2, 3],
            name: "Laptop".to_owned(),
            credential: Vec::new(),
            prf_wrap: wrap,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
        }
    }

    #[test]
    fn names_are_trimmed_cleaned_and_cut() {
        assert_eq!(
            Passkey::clean_name("  Work\u{7} laptop "),
            Some("Work laptop".to_owned())
        );
        assert_eq!(Passkey::clean_name("   "), None);
        assert_eq!(Passkey::clean_name("\u{7}\u{8}"), None);
        assert_eq!(
            Passkey::clean_name(&"x".repeat(100)).map(|n| n.chars().count()),
            Some(Passkey::MAX_NAME_CHARS)
        );
    }

    #[test]
    fn a_wrap_is_the_length_of_a_wrapped_root_key() {
        let wrap = |len| PrfWrap {
            wrapped_key: vec![0; len],
            key_version: 1,
        };
        assert!(wrap(92).is_well_formed());
        assert!(!wrap(91).is_well_formed());
        assert!(!wrap(93).is_well_formed());
        assert!(!wrap(0).is_well_formed());
    }

    #[test]
    fn a_wrap_is_current_only_for_the_version_it_names() {
        let with = passkey(Some(PrfWrap {
            wrapped_key: vec![0; 92],
            key_version: 3,
        }));
        assert!(with.wrap_is_current(3));
        assert!(!with.wrap_is_current(4));
        assert!(!passkey(None).wrap_is_current(3));
    }

    #[test]
    fn ids_parse_and_print() {
        let id = PasskeyId::random();
        assert_eq!(id.to_string().parse::<PasskeyId>().ok(), Some(id));
        assert!("nope".parse::<PasskeyId>().is_err());
    }

    #[test]
    fn debug_shows_no_key_bytes() {
        let shown = format!(
            "{:?}",
            passkey(Some(PrfWrap {
                wrapped_key: vec![0xAB; 92],
                key_version: 1,
            }))
        );
        assert!(!shown.contains("wrapped_key"), "{shown}");
        assert!(!shown.contains("[171"), "{shown}");
        assert!(shown.contains("prf: true"), "{shown}");
    }
}
