//! Account keys: the root key, the Kemlock user key and the labelled children.
//!
//! ```text
//! root key (64 random bytes)
//!   └─ user key  = HKDF(ikm = root, salt = absent, info = "kemlock/v1/user", L = 32)
//!        └─ child = HKDF(ikm = user key, salt = absent, info = label, L = 32)
//! ```

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error,
    backend::{Active, Backend},
    rand,
};

/// The label of the Kemlock user key under the root key.
pub const USER_LABEL: &str = "kemlock/v1/user";
/// The child key that wraps item keys of the owner.
pub const ITEM_WRAP_LABEL: &str = "kemlock/v1/item-wrap";
/// The child key that seals the account's exchange and signing private keys.
pub const PRIVATE_KEYS_LABEL: &str = "kemlock/v1/private-keys";
/// Reserved for the signed manifest's MAC-less parts.
pub const MANIFEST_LABEL: &str = "kemlock/v1/manifest";

/// The length of a root key.
pub const ROOT_KEY_LEN: usize = 64;
/// The length of a user, space, child or item key.
pub const KEY_LEN: usize = 32;

/// A 32-byte secret: a user key, a space key, a child key or an item key. Wiped on drop; `Debug`
/// shows no contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// A fresh random key.
    pub fn generate() -> SecretKey {
        SecretKey(rand::bytes())
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> SecretKey {
        SecretKey(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// `HKDF(ikm = self, salt = absent, info = label, L = 32)`, the child key of that label.
    pub fn child(&self, label: &str) -> Result<SecretKey, Error> {
        self.child_in::<Active>(label)
    }

    pub(crate) fn child_in<B: Backend>(&self, label: &str) -> Result<SecretKey, Error> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        B::hkdf_sha256(&self.0, None, label.as_bytes(), &mut *out)?;
        Ok(SecretKey(*out))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

/// The 64-byte root key of an account. On a Compatible account it is the Bitwarden user key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; ROOT_KEY_LEN]);

impl RootKey {
    /// A fresh random root key.
    pub fn generate() -> RootKey {
        RootKey(rand::bytes())
    }

    pub fn from_bytes(bytes: &[u8; ROOT_KEY_LEN]) -> RootKey {
        RootKey(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.0
    }

    /// The Kemlock user key, `HKDF(ikm = root, salt = absent, info = "kemlock/v1/user", L = 32)`.
    pub fn user_key(&self) -> Result<SecretKey, Error> {
        self.user_key_in::<Active>()
    }

    pub(crate) fn user_key_in<B: Backend>(&self) -> Result<SecretKey, Error> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        B::hkdf_sha256(&self.0, None, USER_LABEL.as_bytes(), &mut *out)?;
        Ok(SecretKey(*out))
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_key_is_hkdf_of_the_root_with_its_label() {
        for_backends!(B => {
            let root = RootKey::from_bytes(&[3u8; 64]);
            let mut expected = [0u8; 32];
            B::hkdf_sha256(&[3u8; 64], None, b"kemlock/v1/user", &mut expected).expect("hkdf");
            assert_eq!(root.user_key_in::<B>().expect("user key").as_bytes(), &expected);
        });
    }

    #[test]
    fn children_differ_by_label_and_parent() {
        for_backends!(B => {
            let user = RootKey::from_bytes(&[1u8; 64]).user_key_in::<B>().expect("user key");
            let wrap = user.child_in::<B>(ITEM_WRAP_LABEL).expect("child");
            let private = user.child_in::<B>(PRIVATE_KEYS_LABEL).expect("child");
            let manifest = user.child_in::<B>(MANIFEST_LABEL).expect("child");
            assert_ne!(wrap.as_bytes(), private.as_bytes());
            assert_ne!(wrap.as_bytes(), manifest.as_bytes());
            assert_ne!(private.as_bytes(), manifest.as_bytes());
            assert_ne!(wrap.as_bytes(), user.as_bytes());
            let other = RootKey::from_bytes(&[2u8; 64]).user_key_in::<B>().expect("user key");
            assert_ne!(
                other.child_in::<B>(ITEM_WRAP_LABEL).expect("child").as_bytes(),
                wrap.as_bytes()
            );
        });
    }

    #[test]
    fn derivation_is_deterministic() {
        let root = RootKey::from_bytes(&[5u8; 64]);
        let a = root
            .user_key()
            .expect("user key")
            .child(ITEM_WRAP_LABEL)
            .expect("child");
        let b = root
            .user_key()
            .expect("user key")
            .child(ITEM_WRAP_LABEL)
            .expect("child");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn generated_keys_are_random() {
        assert_ne!(
            SecretKey::generate().as_bytes(),
            SecretKey::generate().as_bytes()
        );
        assert_ne!(
            RootKey::generate().as_bytes(),
            RootKey::generate().as_bytes()
        );
    }

    #[test]
    fn debug_shows_no_contents() {
        let key = SecretKey::from_bytes(&[0xAB; 32]);
        let text = format!("{key:?}");
        assert!(!text.contains("171") && !text.to_lowercase().contains("ab"));
        let root = format!("{:?}", RootKey::from_bytes(&[0xCD; 64]));
        assert!(!root.contains("205"));
    }
}
