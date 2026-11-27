//! Rotating the root key: the byte-level pieces of docs/crypto.md, "Rotating the root key".
//!
//! A rotation makes a new root key at the next key version and moves everything the old one
//! protected under it. The wraps of the new root key (password, kit, passkey, device, emergency,
//! recovery) and the new private keys are the formats that already exist, made with the new key and
//! `u32be(new version)`. What a rotation adds is the re-encryption of what sits under the old key:
//!
//! - an **item** gets a fresh item key and is sealed again at the next revision, and the new item
//!   key is wrapped under the new `item-wrap` key. Re-wrapping the old item key would leave the
//!   ciphertext openable by anyone who holds an old wrap of it;
//! - a **Send** keeps its link key (it is in links already given out) but its sealed key and meta
//!   move to the new `item-wrap` key and key version.

use zeroize::Zeroizing;

use crate::{
    Error,
    backend::{Active, Backend},
    kem1,
    keys::SecretKey,
    owner::Owner,
    send::{self, Kind},
};

/// An item sealed again under the new keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResealedItem {
    /// `nonce ‖ ciphertext ‖ tag`, sealed at [`revision`](Self::revision) under a fresh item key.
    pub ciphertext: Vec<u8>,
    /// The fresh item key, wrapped under the new `item-wrap` key at the new key version.
    pub item_key: Vec<u8>,
    /// The revision the new ciphertext is sealed at: the old one plus one.
    pub revision: u64,
}

/// A Send's owner-side parts moved to the new `item-wrap` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResealedSend {
    /// `u32be(new key version) ‖ …`, the same link key under the new `item-wrap` key, 64 bytes.
    pub sealed_key: Vec<u8>,
    /// The owner's meta under the meta key of the new `item-wrap` key and version.
    pub meta: Vec<u8>,
}

/// Opens an item under the old keys and seals it again under a fresh item key, at the next
/// revision, wrapped under the new `item-wrap` key with `new_version`.
///
/// `old_version` is the key version the item says its key was wrapped under. The JSON is carried
/// over byte for byte. Fails when the item does not open under the old keys (another id, owner,
/// kind or revision, a wrong key, any altered byte), and when the revision cannot go up.
#[allow(clippy::too_many_arguments)]
pub fn reseal_item(
    old_wrap: &SecretKey,
    old_version: u32,
    new_wrap: &SecretKey,
    new_version: u32,
    item_id: &[u8; 16],
    owner: &Owner,
    kind: &str,
    revision: u64,
    ciphertext: &[u8],
    item_key: &[u8],
) -> Result<ResealedItem, Error> {
    reseal_item_in::<Active>(
        old_wrap,
        old_version,
        new_wrap,
        new_version,
        item_id,
        owner,
        kind,
        revision,
        ciphertext,
        item_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reseal_item_in<B: Backend>(
    old_wrap: &SecretKey,
    old_version: u32,
    new_wrap: &SecretKey,
    new_version: u32,
    item_id: &[u8; 16],
    owner: &Owner,
    kind: &str,
    revision: u64,
    ciphertext: &[u8],
    item_key: &[u8],
) -> Result<ResealedItem, Error> {
    let next = revision.checked_add(1).ok_or_else(Error::invalid)?;
    let old_key = kem1::unwrap_item_key_in::<B>(old_wrap, item_key, item_id, owner, old_version)?;
    let json = Zeroizing::new(
        kem1::open_item_in::<B>(&old_key, item_id, revision, kind, owner, ciphertext)?.to_vec(),
    );
    let fresh = SecretKey::generate();
    let sealed = kem1::seal_item_in::<B>(&fresh, item_id, next, kind, owner, &json)?;
    let wrapped = kem1::wrap_item_key_in::<B>(new_wrap, &fresh, item_id, owner, new_version)?;
    Ok(ResealedItem {
        ciphertext: sealed,
        item_key: wrapped,
        revision: next,
    })
}

/// Moves a Send's sealed link key and meta from the old `item-wrap` key to the new one. The link key
/// and the payload do not change. The meta is opened at the key version the old `sealed_key` names
/// and sealed at `new_version`.
pub fn reseal_send(
    old_wrap: &SecretKey,
    new_wrap: &SecretKey,
    new_version: u32,
    send_id: &[u8; 16],
    kind: Kind,
    sealed_key: &[u8],
    meta: &[u8],
) -> Result<ResealedSend, Error> {
    reseal_send_in::<Active>(
        old_wrap,
        new_wrap,
        new_version,
        send_id,
        kind,
        sealed_key,
        meta,
    )
}

pub(crate) fn reseal_send_in<B: Backend>(
    old_wrap: &SecretKey,
    new_wrap: &SecretKey,
    new_version: u32,
    send_id: &[u8; 16],
    kind: Kind,
    sealed_key: &[u8],
    meta: &[u8],
) -> Result<ResealedSend, Error> {
    let (link_key, old_version) = send::unwrap_link_key_in::<B>(old_wrap, sealed_key, send_id)?;
    let plain = send::open_meta_in::<B>(old_wrap, send_id, old_version, kind, meta)?;
    Ok(ResealedSend {
        sealed_key: send::wrap_link_key_in::<B>(new_wrap, &link_key, send_id, new_version)?,
        meta: send::seal_meta_in::<B>(new_wrap, send_id, new_version, kind, &plain)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ITEM_WRAP_LABEL, RootKey};

    const ID: [u8; 16] = [0x11; 16];

    fn wrap_of(root: &RootKey) -> SecretKey {
        root.user_key()
            .expect("user key")
            .child(ITEM_WRAP_LABEL)
            .expect("item-wrap child")
    }

    fn owner() -> Owner {
        Owner::user([0x22; 16])
    }

    fn sealed_item(
        wrap: &SecretKey,
        version: u32,
        revision: u64,
        json: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key = SecretKey::generate();
        let ciphertext =
            kem1::seal_item(&key, &ID, revision, "login", &owner(), json).expect("seals");
        let wrapped = kem1::wrap_item_key(wrap, &key, &ID, &owner(), version).expect("wraps");
        (ciphertext, wrapped)
    }

    #[test]
    fn an_item_moves_to_a_fresh_key_and_the_next_revision() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let json = br#"{"name":"bank","password":"hunter2"}"#;
        let (ciphertext, wrapped) = sealed_item(&old_wrap, 1, 4, json);

        let moved = reseal_item(
            &old_wrap,
            1,
            &new_wrap,
            2,
            &ID,
            &owner(),
            "login",
            4,
            &ciphertext,
            &wrapped,
        )
        .expect("reseals");
        assert_eq!(moved.revision, 5);
        assert_ne!(moved.ciphertext, ciphertext);
        assert_ne!(moved.item_key, wrapped);

        let key = kem1::unwrap_item_key(&new_wrap, &moved.item_key, &ID, &owner(), 2)
            .expect("the new wrap opens");
        let opened = kem1::open_item(&key, &ID, 5, "login", &owner(), &moved.ciphertext)
            .expect("the new envelope opens at the next revision");
        assert_eq!(opened.as_slice(), json.as_slice());
    }

    #[test]
    fn nothing_new_opens_under_the_old_keys() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let (ciphertext, wrapped) = sealed_item(&old_wrap, 1, 1, b"{}");
        let moved = reseal_item(
            &old_wrap,
            1,
            &new_wrap,
            2,
            &ID,
            &owner(),
            "login",
            1,
            &ciphertext,
            &wrapped,
        )
        .expect("reseals");

        // The old wrap key opens no new item key, whatever version it is tried at.
        for version in [1, 2] {
            assert!(
                kem1::unwrap_item_key(&old_wrap, &moved.item_key, &ID, &owner(), version).is_err()
            );
        }
        // The old item key opens no new ciphertext: the key is fresh, not re-wrapped.
        let old_key = kem1::unwrap_item_key(&old_wrap, &wrapped, &ID, &owner(), 1).expect("opens");
        for revision in [1, 2] {
            assert!(
                kem1::open_item(
                    &old_key,
                    &ID,
                    revision,
                    "login",
                    &owner(),
                    &moved.ciphertext
                )
                .is_err()
            );
        }
    }

    #[test]
    fn an_item_that_does_not_open_is_not_moved() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let (ciphertext, wrapped) = sealed_item(&old_wrap, 1, 3, b"{}");
        let try_it = |revision: u64, version: u32, kind: &str, wrapped: &[u8], ct: &[u8]| {
            reseal_item(
                &old_wrap,
                version,
                &new_wrap,
                2,
                &ID,
                &owner(),
                kind,
                revision,
                ct,
                wrapped,
            )
        };
        assert!(try_it(3, 1, "login", &wrapped, &ciphertext).is_ok());
        assert!(try_it(2, 1, "login", &wrapped, &ciphertext).is_err());
        assert!(try_it(3, 2, "login", &wrapped, &ciphertext).is_err());
        assert!(try_it(3, 1, "note", &wrapped, &ciphertext).is_err());
        let mut bad = ciphertext.clone();
        bad[20] ^= 1;
        assert!(try_it(3, 1, "login", &wrapped, &bad).is_err());
        let wrong = wrap_of(&RootKey::generate());
        assert!(
            reseal_item(
                &wrong,
                1,
                &new_wrap,
                2,
                &ID,
                &owner(),
                "login",
                3,
                &ciphertext,
                &wrapped
            )
            .is_err()
        );
    }

    #[test]
    fn the_last_revision_cannot_go_up() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let (ciphertext, wrapped) = sealed_item(&old_wrap, 1, u64::MAX, b"{}");
        assert!(
            reseal_item(
                &old_wrap,
                1,
                &new_wrap,
                2,
                &ID,
                &owner(),
                "login",
                u64::MAX,
                &ciphertext,
                &wrapped
            )
            .is_err()
        );
    }

    #[test]
    fn a_send_keeps_its_link_key_and_moves_its_wraps() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let link = send::generate_link_key();
        let sealed_key = send::wrap_link_key(&old_wrap, &link, &ID, 1).expect("wraps");
        let meta = send::seal_meta(
            &old_wrap,
            &ID,
            1,
            Kind::Text,
            br#"{"name":"a","notes":"b"}"#,
        )
        .expect("seals");

        let moved = reseal_send(&old_wrap, &new_wrap, 2, &ID, Kind::Text, &sealed_key, &meta)
            .expect("reseals");
        assert_eq!(
            send::sealed_key_version(&moved.sealed_key).expect("version"),
            2
        );
        let (opened, version) =
            send::unwrap_link_key(&new_wrap, &moved.sealed_key, &ID).expect("opens");
        assert_eq!(version, 2);
        assert_eq!(opened.as_bytes(), link.as_bytes());
        let plain = send::open_meta(&new_wrap, &ID, 2, Kind::Text, &moved.meta).expect("opens");
        assert_eq!(plain.as_slice(), br#"{"name":"a","notes":"b"}"#.as_slice());

        assert!(send::unwrap_link_key(&old_wrap, &moved.sealed_key, &ID).is_err());
        assert!(send::open_meta(&old_wrap, &ID, 2, Kind::Text, &moved.meta).is_err());
        assert!(send::open_meta(&old_wrap, &ID, 1, Kind::Text, &moved.meta).is_err());
    }

    #[test]
    fn a_send_of_another_id_or_kind_is_not_moved() {
        let (old_root, new_root) = (RootKey::generate(), RootKey::generate());
        let (old_wrap, new_wrap) = (wrap_of(&old_root), wrap_of(&new_root));
        let link = send::generate_link_key();
        let sealed_key = send::wrap_link_key(&old_wrap, &link, &ID, 1).expect("wraps");
        let meta = send::seal_meta(&old_wrap, &ID, 1, Kind::Text, b"{}").expect("seals");
        assert!(
            reseal_send(
                &old_wrap,
                &new_wrap,
                2,
                &[9; 16],
                Kind::Text,
                &sealed_key,
                &meta
            )
            .is_err()
        );
        assert!(reseal_send(&old_wrap, &new_wrap, 2, &ID, Kind::File, &sealed_key, &meta).is_err());
    }
}
