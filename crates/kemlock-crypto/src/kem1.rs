//! `kem1`, the item envelope.
//!
//! Each item has its own random 32-byte item key. The revision is part of what is sealed, so the
//! client assigns it.
//!
//! ```text
//! aad        = "kemlock/v1/item" ‖ item id (16) ‖ u64be(revision) ‖ lp(kind) ‖ owner (17)
//! ciphertext = AES-256-GCM(item key, nonce, item JSON (UTF-8), aad)
//!
//! wrap aad   = "kemlock/v1/item-key" ‖ item id (16) ‖ owner (17) ‖ u32be(key version)
//! item_key   = AES-256-GCM(owner's "kemlock/v1/item-wrap" child key, nonce, item key, wrap aad)
//! ```
//!
//! The item key wrap isn't bound to the revision, so an edit may keep the item key. What the server
//! can check is lengths, that a sealed value is at least 28 bytes, the kind's alphabet, the
//! revision rule and the owner; it can't check the AAD.

use zeroize::Zeroizing;

use crate::{
    Error, aead,
    backend::{Active, Backend},
    keys::{KEY_LEN, SecretKey},
    owner::Owner,
    wire::lp,
};

const ITEM_LABEL: &[u8] = b"kemlock/v1/item";
const ITEM_KEY_LABEL: &[u8] = b"kemlock/v1/item-key";

/// The longest a kind may be, in bytes.
pub const KIND_MAX_LEN: usize = 64;
/// The shortest a sealed value can be: a nonce and a tag around nothing.
pub const MIN_SEALED_LEN: usize = aead::OVERHEAD;
/// The length of a wrapped item key.
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + aead::OVERHEAD;

/// Whether `kind` is 1 to 64 bytes of `[a-z0-9_-]`.
pub fn is_valid_kind(kind: &str) -> bool {
    (1..=KIND_MAX_LEN).contains(&kind.len())
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The additional data of an item's ciphertext.
pub fn item_aad(
    item_id: &[u8; 16],
    revision: u64,
    kind: &str,
    owner: &Owner,
) -> Result<Vec<u8>, Error> {
    if !is_valid_kind(kind) {
        return Err(Error::invalid());
    }
    let mut out = Vec::with_capacity(ITEM_LABEL.len() + 16 + 8 + 4 + kind.len() + 17);
    out.extend_from_slice(ITEM_LABEL);
    out.extend_from_slice(item_id);
    out.extend_from_slice(&revision.to_be_bytes());
    lp(&mut out, kind.as_bytes())?;
    out.extend_from_slice(&owner.to_bytes());
    Ok(out)
}

/// The additional data of a wrapped item key.
pub fn item_key_aad(item_id: &[u8; 16], owner: &Owner, key_version: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(ITEM_KEY_LABEL.len() + 16 + 17 + 4);
    out.extend_from_slice(ITEM_KEY_LABEL);
    out.extend_from_slice(item_id);
    out.extend_from_slice(&owner.to_bytes());
    out.extend_from_slice(&key_version.to_be_bytes());
    out
}

/// Seals an item's JSON under its item key: `nonce(12) ‖ ciphertext ‖ tag(16)`.
pub fn seal_item(
    item_key: &SecretKey,
    item_id: &[u8; 16],
    revision: u64,
    kind: &str,
    owner: &Owner,
    item_json: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_item_in::<Active>(item_key, item_id, revision, kind, owner, item_json)
}

pub(crate) fn seal_item_in<B: Backend>(
    item_key: &SecretKey,
    item_id: &[u8; 16],
    revision: u64,
    kind: &str,
    owner: &Owner,
    item_json: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = item_aad(item_id, revision, kind, owner)?;
    aead::seal::<B>(item_key.as_bytes(), &aad, item_json)
}

/// Opens an item's ciphertext. Fails under another item id, revision, kind or owner, and for any
/// altered byte: that is how a swapped or rolled-back item shows.
pub fn open_item(
    item_key: &SecretKey,
    item_id: &[u8; 16],
    revision: u64,
    kind: &str,
    owner: &Owner,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_item_in::<Active>(item_key, item_id, revision, kind, owner, ciphertext)
}

pub(crate) fn open_item_in<B: Backend>(
    item_key: &SecretKey,
    item_id: &[u8; 16],
    revision: u64,
    kind: &str,
    owner: &Owner,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let aad = item_aad(item_id, revision, kind, owner)?;
    aead::open::<B>(item_key.as_bytes(), &aad, ciphertext)
}

/// Wraps an item key under the owner's `"kemlock/v1/item-wrap"` child key.
pub fn wrap_item_key(
    wrap_key: &SecretKey,
    item_key: &SecretKey,
    item_id: &[u8; 16],
    owner: &Owner,
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    wrap_item_key_in::<Active>(wrap_key, item_key, item_id, owner, key_version)
}

pub(crate) fn wrap_item_key_in<B: Backend>(
    wrap_key: &SecretKey,
    item_key: &SecretKey,
    item_id: &[u8; 16],
    owner: &Owner,
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let aad = item_key_aad(item_id, owner, key_version);
    aead::seal::<B>(wrap_key.as_bytes(), &aad, item_key.as_bytes())
}

/// Unwraps an item key. Fails under another item, owner or key version.
pub fn unwrap_item_key(
    wrap_key: &SecretKey,
    wrapped: &[u8],
    item_id: &[u8; 16],
    owner: &Owner,
    key_version: u32,
) -> Result<SecretKey, Error> {
    unwrap_item_key_in::<Active>(wrap_key, wrapped, item_id, owner, key_version)
}

pub(crate) fn unwrap_item_key_in<B: Backend>(
    wrap_key: &SecretKey,
    wrapped: &[u8],
    item_id: &[u8; 16],
    owner: &Owner,
    key_version: u32,
) -> Result<SecretKey, Error> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(Error::invalid());
    }
    let aad = item_key_aad(item_id, owner, key_version);
    let plain = aead::open::<B>(wrap_key.as_bytes(), &aad, wrapped)?;
    let bytes: &[u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::invalid())?;
    Ok(SecretKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ITEM_WRAP_LABEL, RootKey};

    const ITEM: [u8; 16] = [0x11; 16];

    fn owner() -> Owner {
        Owner::user([0x22; 16])
    }

    #[test]
    fn kind_alphabet() {
        let longest = "a".repeat(64);
        let too_long = "a".repeat(65);
        for ok in [
            "login",
            "otp",
            "backup-codes",
            "ssh-key",
            "a",
            "x_y-9",
            longest.as_str(),
        ] {
            assert!(is_valid_kind(ok), "{ok}");
        }
        for bad in [
            "",
            "Login",
            "log in",
            "login!",
            "é",
            too_long.as_str(),
            "a\0",
        ] {
            assert!(!is_valid_kind(bad), "{bad:?}");
        }
    }

    #[test]
    fn item_aad_layout_matches_the_doc() {
        let aad = item_aad(&ITEM, 0x0102, "login", &owner()).expect("aad");
        let mut expected = b"kemlock/v1/item".to_vec();
        expected.extend_from_slice(&ITEM);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"login");
        expected.push(1);
        expected.extend_from_slice(&[0x22; 16]);
        assert_eq!(aad, expected);
    }

    #[test]
    fn item_key_aad_layout_matches_the_doc() {
        let aad = item_key_aad(&ITEM, &Owner::space([0x33; 16]), 7);
        let mut expected = b"kemlock/v1/item-key".to_vec();
        expected.extend_from_slice(&ITEM);
        expected.push(2);
        expected.extend_from_slice(&[0x33; 16]);
        expected.extend_from_slice(&[0, 0, 0, 7]);
        assert_eq!(aad, expected);
    }

    #[test]
    fn a_bad_kind_is_refused_when_sealing() {
        let key = SecretKey::from_bytes(&[1; 32]);
        assert!(seal_item(&key, &ITEM, 1, "Login", &owner(), b"{}").is_err());
        assert!(item_aad(&ITEM, 1, "", &owner()).is_err());
    }

    #[test]
    fn an_item_round_trips() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[1; 32]);
            let json = br#"{"name":"example","password":"hunter2"}"#;
            let sealed = seal_item_in::<B>(&key, &ITEM, 4, "login", &owner(), json).expect("seal");
            assert_eq!(sealed.len(), json.len() + 28);
            let opened = open_item_in::<B>(&key, &ITEM, 4, "login", &owner(), &sealed).expect("open");
            assert_eq!(opened.as_slice(), json, "{}", B::NAME);
        });
    }

    #[test]
    fn every_bound_field_is_checked() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[1; 32]);
            let sealed = seal_item_in::<B>(&key, &ITEM, 4, "login", &owner(), b"{}").expect("seal");
            let open = |id: &[u8; 16], rev: u64, kind: &str, owner: &Owner| {
                open_item_in::<B>(&key, id, rev, kind, owner, &sealed).is_ok()
            };
            assert!(open(&ITEM, 4, "login", &owner()));
            assert!(!open(&[0x12; 16], 4, "login", &owner()), "another item id");
            assert!(!open(&ITEM, 3, "login", &owner()), "a rolled-back revision");
            assert!(!open(&ITEM, 5, "login", &owner()), "a newer revision");
            assert!(!open(&ITEM, 4, "note", &owner()), "another kind");
            assert!(!open(&ITEM, 4, "login", &Owner::user([0x23; 16])), "another owner");
            assert!(!open(&ITEM, 4, "login", &Owner::space([0x22; 16])), "another owner type");
            let wrong_key = SecretKey::from_bytes(&[2; 32]);
            assert!(open_item_in::<B>(&wrong_key, &ITEM, 4, "login", &owner(), &sealed).is_err());
        });
    }

    #[test]
    fn tampering_and_short_input_fail() {
        for_backends!(B => {
            let key = SecretKey::from_bytes(&[1; 32]);
            let sealed = seal_item_in::<B>(&key, &ITEM, 4, "login", &owner(), b"{}").expect("seal");
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 1;
                assert!(open_item_in::<B>(&key, &ITEM, 4, "login", &owner(), &bad).is_err(), "byte {i}");
            }
            assert!(open_item_in::<B>(&key, &ITEM, 4, "login", &owner(), &sealed[..27]).is_err());
        });
    }

    #[test]
    fn item_keys_wrap_and_unwrap() {
        for_backends!(B => {
            let user = RootKey::from_bytes(&[5; 64]).user_key_in::<B>().expect("user key");
            let wrap = user.child_in::<B>(ITEM_WRAP_LABEL).expect("child");
            let item_key = SecretKey::from_bytes(&[9; 32]);
            let wrapped = wrap_item_key_in::<B>(&wrap, &item_key, &ITEM, &owner(), 1).expect("wrap");
            assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
            assert_eq!(WRAPPED_KEY_LEN, 60);
            let unwrapped = unwrap_item_key_in::<B>(&wrap, &wrapped, &ITEM, &owner(), 1).expect("unwrap");
            assert_eq!(unwrapped.as_bytes(), item_key.as_bytes(), "{}", B::NAME);
        });
    }

    #[test]
    fn a_wrapped_key_is_bound_to_item_owner_and_key_version_but_not_revision() {
        for_backends!(B => {
            let wrap = SecretKey::from_bytes(&[3; 32]);
            let item_key = SecretKey::from_bytes(&[9; 32]);
            let wrapped = wrap_item_key_in::<B>(&wrap, &item_key, &ITEM, &owner(), 1).expect("wrap");
            assert!(unwrap_item_key_in::<B>(&wrap, &wrapped, &[0; 16], &owner(), 1).is_err());
            assert!(unwrap_item_key_in::<B>(&wrap, &wrapped, &ITEM, &Owner::space([0x22; 16]), 1).is_err());
            assert!(unwrap_item_key_in::<B>(&wrap, &wrapped, &ITEM, &owner(), 2).is_err());
            assert!(unwrap_item_key_in::<B>(&SecretKey::from_bytes(&[4; 32]), &wrapped, &ITEM, &owner(), 1).is_err());
            for i in 0..wrapped.len() {
                let mut bad = wrapped.clone();
                bad[i] ^= 1;
                assert!(unwrap_item_key_in::<B>(&wrap, &bad, &ITEM, &owner(), 1).is_err(), "byte {i}");
            }
            assert!(unwrap_item_key_in::<B>(&wrap, &wrapped[1..], &ITEM, &owner(), 1).is_err());
            // Editing an item keeps its key: the same wrapped key opens revisions 1 and 2.
            let key = unwrap_item_key_in::<B>(&wrap, &wrapped, &ITEM, &owner(), 1).expect("unwrap");
            for revision in [1u64, 2] {
                let sealed = seal_item_in::<B>(&key, &ITEM, revision, "note", &owner(), b"{}").expect("seal");
                open_item_in::<B>(&key, &ITEM, revision, "note", &owner(), &sealed).expect("open");
            }
        });
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn items_sealed_on_one_backend_open_on_the_other() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let key = SecretKey::from_bytes(&[1; 32]);
        let a = seal_item_in::<AwsLc>(&key, &ITEM, 1, "note", &owner(), b"one").expect("seal");
        let b = seal_item_in::<RustCrypto>(&key, &ITEM, 1, "note", &owner(), b"two").expect("seal");
        assert_eq!(
            open_item_in::<RustCrypto>(&key, &ITEM, 1, "note", &owner(), &a)
                .expect("open")
                .as_slice(),
            b"one"
        );
        assert_eq!(
            open_item_in::<AwsLc>(&key, &ITEM, 1, "note", &owner(), &b)
                .expect("open")
                .as_slice(),
            b"two"
        );
    }
}
