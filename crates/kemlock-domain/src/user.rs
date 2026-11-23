//! Accounts.

use crate::ids::UserId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// An email address, trimmed and lower-cased, as accounts are keyed by it. Checked only loosely:
/// the real check is the verification mail.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Email(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an email address")]
pub struct EmailError;

impl Email {
    pub const MAX_LEN: usize = 254;

    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let s = raw.trim().to_lowercase();
        let valid = s.len() <= Self::MAX_LEN
            && !s.chars().any(char::is_whitespace)
            && s.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
            })
            && s.matches('@').count() == 1;
        if valid { Ok(Email(s)) } else { Err(EmailError) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Email {
    type Error = EmailError;
    fn try_from(s: String) -> Result<Self, EmailError> {
        Email::parse(&s)
    }
}

impl From<Email> for String {
    fn from(e: Email) -> String {
        e.0
    }
}

/// How an account signs in. New accounts are Kemlock only; accounts copied from Vaultwarden start
/// Compatible so Bitwarden apps keep working (design, "One account, two front doors").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountMode {
    KemlockOnly,
    Compatible,
}

/// Server roles. Space roles are separate and come with spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Admin,
}

/// The Argon2id settings and salt a client needs to make the master key (docs/crypto.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

impl KdfParams {
    pub const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
    pub const DEFAULT_ITERATIONS: u32 = 3;
    pub const DEFAULT_PARALLELISM: u32 = 4;
    pub const SALT_LEN: usize = 16;

    /// The defaults for a new account, with the given random salt.
    pub fn new_account(salt: [u8; Self::SALT_LEN]) -> Self {
        KdfParams {
            memory_kib: Self::DEFAULT_MEMORY_KIB,
            iterations: Self::DEFAULT_ITERATIONS,
            parallelism: Self::DEFAULT_PARALLELISM,
            salt: salt.to_vec(),
        }
    }

    /// Whether a client-chosen setting is inside the bounds Amethystora Vault accepts:
    /// 2 to 10 passes, 16 to 1,024 MiB, 1 to 16 lanes (design, "Capabilities, client by client"),
    /// with a salt of exactly 16 bytes, no longer: the server stores the salt and hands it to
    /// anyone who asks for it, so its length is not the client's to choose.
    pub fn within_bounds(&self) -> bool {
        (2..=10).contains(&self.iterations)
            && (16 * 1024..=1024 * 1024).contains(&self.memory_kib)
            && (1..=16).contains(&self.parallelism)
            && self.salt.len() == Self::SALT_LEN
    }

    /// Whether these are exactly the settings of a new Kemlock-only account: the defaults and a
    /// 16-byte salt. Registration requires them. Prelogin answers an unknown email with these
    /// same defaults, so any other value would prove the account exists.
    pub fn is_account_default(&self) -> bool {
        self.memory_kib == Self::DEFAULT_MEMORY_KIB
            && self.iterations == Self::DEFAULT_ITERATIONS
            && self.parallelism == Self::DEFAULT_PARALLELISM
            && self.salt.len() == Self::SALT_LEN
    }
}

/// An account. The server holds only verifiers, wrapped keys and public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub name: Option<String>,
    pub mode: AccountMode,
    pub role: Role,
    pub kdf: KdfParams,
    /// The OPAQUE registration record (opaque-ke's `ServerRegistration`), for Kemlock-only
    /// accounts and Compatible accounts that have enrolled OPAQUE.
    pub opaque_record: Option<Vec<u8>>,
    /// The root key wrapped as docs/crypto.md's password wrap.
    pub wrapped_root_key: Vec<u8>,
    /// The signed public-key bundle (docs/crypto.md).
    pub public_bundle: Vec<u8>,
    /// The `sig1` signature over the bundle.
    pub bundle_signature: Vec<u8>,
    /// The private keys sealed under the user key's `kemlock/v1/private-keys` child.
    pub sealed_private_keys: Vec<u8>,
    pub key_version: u32,
    /// Changes whenever sessions must end (password change, key replacement).
    pub security_stamp: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_trimmed_and_lower_cased() {
        assert_eq!(
            Email::parse("  Ada@Example.COM ").map(|e| e.0),
            Ok("ada@example.com".to_owned())
        );
    }

    #[test]
    fn non_emails_are_refused() {
        for bad in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "a b@example.com",
            "a@b@example.com",
            "ada@.com",
        ] {
            assert_eq!(Email::parse(bad), Err(EmailError), "{bad}");
        }
    }

    #[test]
    fn kdf_bounds_follow_amethystora() {
        let mut k = KdfParams::new_account([0; 16]);
        assert!(k.within_bounds());
        k.iterations = 1;
        assert!(!k.within_bounds());
    }

    #[test]
    fn the_salt_is_exactly_sixteen_bytes() {
        let mut k = KdfParams::new_account([0; 16]);
        for len in [0, 15, 17, 64, 100_000] {
            k.salt = vec![1; len];
            assert!(!k.within_bounds(), "{len}");
            assert!(!k.is_account_default(), "{len}");
        }
    }

    #[test]
    fn only_the_defaults_are_an_account_default() {
        assert!(KdfParams::new_account([9; 16]).is_account_default());
        let tweaks: [fn(&mut KdfParams); 3] = [
            |k| k.memory_kib = 32 * 1024,
            |k| k.iterations = 4,
            |k| k.parallelism = 2,
        ];
        for tweak in tweaks {
            let mut k = KdfParams::new_account([9; 16]);
            tweak(&mut k);
            assert!(k.within_bounds(), "still inside the bounds");
            assert!(!k.is_account_default());
        }
    }
}
