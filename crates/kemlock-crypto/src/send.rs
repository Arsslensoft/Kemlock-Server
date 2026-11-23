//! Sends: a note or a file shared by a link whose key never reaches the server.
//!
//! ```text
//! link key K  = 32 random bytes, in the link's fragment: https://<host>/#/send/<access id>/<K>
//! send id     = a UUID v4 the client chooses; the access id is its 16 bytes in base64url
//!
//! payload key = HKDF(K, salt = absent, info = "kemlock/v1/send-payload", L = 32)
//! proof salt  = HKDF(K, salt = absent, info = "kemlock/v1/send-proof" ‖ send id, L = 16)
//! meta key    = HKDF(owner's item-wrap key, salt = absent,
//!                    info = "kemlock/v1/send-meta" ‖ send id ‖ u32be(key version), L = 32)
//!
//! aad         = label ‖ send id (16) ‖ lp(kind)                    kind is "text" or "file"
//! payload     = AES-256-GCM(payload key, nonce, payload JSON, aad "kemlock/v1/send-payload")
//! meta        = AES-256-GCM(meta key, nonce, meta JSON, aad "kemlock/v1/send-meta")
//!               (the key version is the one the sealed key names)
//! sealed key  = u32be(key version) ‖ AES-256-GCM(owner's item-wrap key, nonce, K,
//!               aad = "kemlock/v1/send-key" ‖ send id ‖ u32be(key version))          (64 bytes)
//! proof       = Argon2id(NFC password, proof salt, m = 19456 KiB, t = 2, p = 1, L = 32)
//! ```
//!
//! This is `docs/crypto.md`'s "Sends" section. A file Send's bytes are [`crate::kma1`] under the
//! payload key. The JSON inside the payload and the meta is the caller's: these functions seal and
//! open bytes, and bind the Send's id and kind so the server can't pass one Send's parts off as
//! another's. The meta key comes from the owner's item-wrap key, not from K, so whoever holds the
//! link can never read the owner's notes.

use zeroize::Zeroizing;

use crate::{
    Error, aead, argon2id,
    backend::{Active, Backend},
    dedup::normalise::nfc,
    keys::{KEY_LEN, SecretKey},
    wire::{Reader, lp},
};

/// The length of a link key.
pub const LINK_KEY_LEN: usize = KEY_LEN;
/// The length of a sealed link key: the key version, a nonce, the key and a tag.
pub const SEALED_KEY_LEN: usize = 4 + KEY_LEN + aead::OVERHEAD;
/// The shortest a sealed payload or meta can be: a nonce and a tag around nothing.
pub const MIN_SEALED_LEN: usize = aead::OVERHEAD;
/// The length of a password proof.
pub const PROOF_LEN: usize = 32;
/// The length of the proof's salt.
pub const PROOF_SALT_LEN: usize = 16;
/// The proof's Argon2id memory cost in KiB, fixed by the format.
pub const PROOF_MEMORY_KIB: u32 = 19456;
/// The proof's Argon2id iterations.
pub const PROOF_ITERATIONS: u32 = 2;
/// The proof's Argon2id lanes.
pub const PROOF_PARALLELISM: u32 = 1;

/// The label of the payload key and of the payload's AAD.
pub const PAYLOAD_LABEL: &str = "kemlock/v1/send-payload";
/// The label of the meta key and of the meta's AAD.
pub const META_LABEL: &str = "kemlock/v1/send-meta";
/// The label the proof salt derives under.
pub const PROOF_LABEL: &str = "kemlock/v1/send-proof";
/// The label of the sealed link key's AAD.
pub const KEY_LABEL: &str = "kemlock/v1/send-key";

/// What a Send holds. The kind is part of every AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    File,
}

impl Kind {
    /// `text` or `file`, as it is written in the AAD and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::File => "file",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "text" => Some(Kind::Text),
            "file" => Some(Kind::File),
            _ => None,
        }
    }
}

/// A fresh random link key.
pub fn generate_link_key() -> SecretKey {
    SecretKey::generate()
}

/// The payload key: the key a note's text, a file's descriptor and a file's `KMA1` bytes are
/// sealed under.
pub fn payload_key(link_key: &SecretKey) -> Result<SecretKey, Error> {
    link_key.child(PAYLOAD_LABEL)
}

/// The meta key, which seals the owner's name and notes. It comes from the owner's item-wrap key
/// (the user key's `"kemlock/v1/item-wrap"` child), so a holder of the link key can't derive it.
pub fn meta_key(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
) -> Result<SecretKey, Error> {
    meta_key_in::<Active>(wrap_key, send_id, key_version)
}

pub(crate) fn meta_key_in<B: Backend>(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
) -> Result<SecretKey, Error> {
    let mut info = Vec::with_capacity(META_LABEL.len() + 16 + 4);
    info.extend_from_slice(META_LABEL.as_bytes());
    info.extend_from_slice(send_id);
    info.extend_from_slice(&key_version.to_be_bytes());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    B::hkdf_sha256(wrap_key.as_bytes(), None, &info, &mut *out)?;
    Ok(SecretKey::from_bytes(&out))
}

/// The key version a sealed link key names: its first four bytes. The owner derives the meta key
/// from it without opening the link key.
pub fn sealed_key_version(sealed_key: &[u8]) -> Result<u32, Error> {
    if sealed_key.len() != SEALED_KEY_LEN {
        return Err(Error::invalid());
    }
    Reader::new(sealed_key).u32()
}

/// The salt of the password proof, bound to the link key and the Send.
pub fn proof_salt(link_key: &SecretKey, send_id: &[u8; 16]) -> Result<[u8; PROOF_SALT_LEN], Error> {
    proof_salt_in::<Active>(link_key, send_id)
}

pub(crate) fn proof_salt_in<B: Backend>(
    link_key: &SecretKey,
    send_id: &[u8; 16],
) -> Result<[u8; PROOF_SALT_LEN], Error> {
    let mut info = Vec::with_capacity(PROOF_LABEL.len() + 16);
    info.extend_from_slice(PROOF_LABEL.as_bytes());
    info.extend_from_slice(send_id);
    let mut out = [0u8; PROOF_SALT_LEN];
    B::hkdf_sha256(link_key.as_bytes(), None, &info, &mut out)?;
    Ok(out)
}

/// The additional data of a payload (`label = PAYLOAD_LABEL`) or a meta (`META_LABEL`):
/// `label ‖ send id ‖ lp(kind)`.
pub fn aad(label: &str, send_id: &[u8; 16], kind: Kind) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(label.len() + 16 + 4 + 4);
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(send_id);
    lp(&mut out, kind.as_str().as_bytes())?;
    Ok(out)
}

/// The additional data of a sealed link key: `"kemlock/v1/send-key" ‖ send id ‖ u32be(key version)`.
pub fn key_aad(send_id: &[u8; 16], key_version: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_LABEL.len() + 16 + 4);
    out.extend_from_slice(KEY_LABEL.as_bytes());
    out.extend_from_slice(send_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    out
}

/// Seals a payload's JSON under the payload key: `nonce(12) ‖ ciphertext ‖ tag(16)`.
pub fn seal_payload(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    kind: Kind,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_payload_in::<Active>(link_key, send_id, kind, plaintext)
}

pub(crate) fn seal_payload_in<B: Backend>(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    kind: Kind,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = link_key.child_in::<B>(PAYLOAD_LABEL)?;
    aead::seal::<B>(
        key.as_bytes(),
        &aad(PAYLOAD_LABEL, send_id, kind)?,
        plaintext,
    )
}

/// Opens a payload. Fails under another link key, Send id or kind and for any altered byte.
pub fn open_payload(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    kind: Kind,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_payload_in::<Active>(link_key, send_id, kind, sealed)
}

pub(crate) fn open_payload_in<B: Backend>(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    kind: Kind,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = link_key.child_in::<B>(PAYLOAD_LABEL)?;
    aead::open::<B>(key.as_bytes(), &aad(PAYLOAD_LABEL, send_id, kind)?, sealed)
}

/// Seals the owner's name and notes under the meta key from `wrap_key`, at the key version the
/// Send's sealed key names.
pub fn seal_meta(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
    kind: Kind,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_meta_in::<Active>(wrap_key, send_id, key_version, kind, plaintext)
}

pub(crate) fn seal_meta_in<B: Backend>(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
    kind: Kind,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = meta_key_in::<B>(wrap_key, send_id, key_version)?;
    aead::seal::<B>(key.as_bytes(), &aad(META_LABEL, send_id, kind)?, plaintext)
}

/// Opens the owner's name and notes. Fails under another wrap key, Send id, key version or kind,
/// and for the link key: it opens a payload, never this.
pub fn open_meta(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
    kind: Kind,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_meta_in::<Active>(wrap_key, send_id, key_version, kind, sealed)
}

pub(crate) fn open_meta_in<B: Backend>(
    wrap_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
    kind: Kind,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = meta_key_in::<B>(wrap_key, send_id, key_version)?;
    aead::open::<B>(key.as_bytes(), &aad(META_LABEL, send_id, kind)?, sealed)
}

/// Seals the link key for its owner: `u32be(key version) ‖ AES-256-GCM(wrap_key, …)`, 64 bytes.
/// `wrap_key` is the user key's `"kemlock/v1/item-wrap"` child.
pub fn wrap_link_key(
    wrap_key: &SecretKey,
    link_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    wrap_link_key_in::<Active>(wrap_key, link_key, send_id, key_version)
}

pub(crate) fn wrap_link_key_in<B: Backend>(
    wrap_key: &SecretKey,
    link_key: &SecretKey,
    send_id: &[u8; 16],
    key_version: u32,
) -> Result<Vec<u8>, Error> {
    let sealed = aead::seal::<B>(
        wrap_key.as_bytes(),
        &key_aad(send_id, key_version),
        link_key.as_bytes(),
    )?;
    let mut out = Vec::with_capacity(SEALED_KEY_LEN);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a sealed link key and returns it with the key version it names. Fails for any other
/// length, under another wrap key or Send id, and for any altered byte (the version included).
pub fn unwrap_link_key(
    wrap_key: &SecretKey,
    sealed_key: &[u8],
    send_id: &[u8; 16],
) -> Result<(SecretKey, u32), Error> {
    unwrap_link_key_in::<Active>(wrap_key, sealed_key, send_id)
}

pub(crate) fn unwrap_link_key_in<B: Backend>(
    wrap_key: &SecretKey,
    sealed_key: &[u8],
    send_id: &[u8; 16],
) -> Result<(SecretKey, u32), Error> {
    if sealed_key.len() != SEALED_KEY_LEN {
        return Err(Error::invalid());
    }
    let mut reader = Reader::new(sealed_key);
    let key_version = reader.u32()?;
    let sealed = reader.take(SEALED_KEY_LEN - 4)?;
    let opened = aead::open::<B>(wrap_key.as_bytes(), &key_aad(send_id, key_version), sealed)?;
    let key: &[u8; KEY_LEN] = opened.as_slice().try_into().map_err(|_| Error::invalid())?;
    Ok((SecretKey::from_bytes(key), key_version))
}

/// The password proof: `Argon2id(NFC password, proof salt, m = 19456 KiB, t = 2, p = 1, L = 32)`.
/// The password is normalised to NFC here, so every client derives the same proof.
pub fn password_proof(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    password: &str,
) -> Result<Zeroizing<[u8; PROOF_LEN]>, Error> {
    password_proof_in::<Active>(link_key, send_id, password)
}

pub(crate) fn password_proof_in<B: Backend>(
    link_key: &SecretKey,
    send_id: &[u8; 16],
    password: &str,
) -> Result<Zeroizing<[u8; PROOF_LEN]>, Error> {
    let salt = proof_salt_in::<B>(link_key, send_id)?;
    let text = Zeroizing::new(nfc(password));
    argon2id::master_key(
        text.as_bytes(),
        &salt,
        PROOF_MEMORY_KIB,
        PROOF_ITERATIONS,
        PROOF_PARALLELISM,
    )
    .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [3; 16];

    fn link_key() -> SecretKey {
        SecretKey::from_bytes(&[9; 32])
    }

    #[test]
    fn sizes_match_the_format() {
        assert_eq!(SEALED_KEY_LEN, 64);
        assert_eq!(MIN_SEALED_LEN, 28);
    }

    #[test]
    fn kinds_are_their_ascii_names() {
        assert_eq!(Kind::Text.as_str(), "text");
        assert_eq!(Kind::File.as_str(), "file");
        assert_eq!(Kind::parse("text"), Some(Kind::Text));
        assert_eq!(Kind::parse("file"), Some(Kind::File));
        for bad in ["", "Text", "note", "text "] {
            assert_eq!(Kind::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keys_derive_from_the_link_key_by_label() {
        for_backends!(B => {
            let k = link_key();
            let mut expected = [0u8; 32];
            B::hkdf_sha256(k.as_bytes(), None, b"kemlock/v1/send-payload", &mut expected).expect("hkdf");
            assert_eq!(k.child_in::<B>(PAYLOAD_LABEL).expect("child").as_bytes(), &expected);
            // The meta key is from the owner's item-wrap key, the send id and the key version.
            let wrap = SecretKey::from_bytes(&[5; 32]);
            let mut info = b"kemlock/v1/send-meta".to_vec();
            info.extend_from_slice(&ID);
            info.extend_from_slice(&[0, 0, 0, 7]);
            B::hkdf_sha256(wrap.as_bytes(), None, &info, &mut expected).expect("hkdf");
            let meta = meta_key_in::<B>(&wrap, &ID, 7).expect("meta key");
            assert_eq!(meta.as_bytes(), &expected, "{}", B::NAME);
            assert_ne!(meta_key_in::<B>(&wrap, &[4; 16], 7).expect("key").as_bytes(), &expected);
            assert_ne!(meta_key_in::<B>(&wrap, &ID, 8).expect("key").as_bytes(), &expected);
            assert_ne!(payload_key(&k).expect("key").as_bytes(), meta.as_bytes());
            let mut info = b"kemlock/v1/send-proof".to_vec();
            info.extend_from_slice(&ID);
            let mut salt = [0u8; 16];
            B::hkdf_sha256(k.as_bytes(), None, &info, &mut salt).expect("hkdf");
            assert_eq!(proof_salt_in::<B>(&k, &ID).expect("salt"), salt, "{}", B::NAME);
            assert_ne!(proof_salt_in::<B>(&k, &[4; 16]).expect("salt"), salt);
        });
    }

    #[test]
    fn aads_follow_the_layout() {
        let payload = aad(PAYLOAD_LABEL, &ID, Kind::Text).expect("aad");
        assert_eq!(&payload[..23], b"kemlock/v1/send-payload");
        assert_eq!(&payload[23..39], &ID);
        assert_eq!(&payload[39..], &[0, 0, 0, 4, b't', b'e', b'x', b't']);
        let meta = aad(META_LABEL, &ID, Kind::File).expect("aad");
        assert_eq!(&meta[..20], b"kemlock/v1/send-meta");
        assert_eq!(&meta[36..], &[0, 0, 0, 4, b'f', b'i', b'l', b'e']);
        let key = key_aad(&ID, 0x0102_0304);
        assert_eq!(&key[..19], b"kemlock/v1/send-key");
        assert_eq!(&key[19..35], &ID);
        assert_eq!(&key[35..], &[1, 2, 3, 4]);
    }

    #[test]
    fn payload_and_meta_round_trip_and_bind_the_send() {
        for_backends!(B => {
            let k = link_key();
            let json: &[u8] = br#"{"name":"n","text":"t"}"#;
            let payload = seal_payload_in::<B>(&k, &ID, Kind::Text, json).expect("seal");
            assert_eq!(payload.len(), json.len() + aead::OVERHEAD, "{}", B::NAME);
            let opened = open_payload_in::<B>(&k, &ID, Kind::Text, &payload).expect("open");
            assert_eq!(opened.as_slice(), json);
            assert!(open_payload_in::<B>(&k, &[4; 16], Kind::Text, &payload).is_err(), "id");
            assert!(open_payload_in::<B>(&k, &ID, Kind::File, &payload).is_err(), "kind");
            let other = SecretKey::from_bytes(&[8; 32]);
            assert!(open_payload_in::<B>(&other, &ID, Kind::Text, &payload).is_err(), "key");
            // A payload is not a meta, and a meta is not a payload.
            let wrap = SecretKey::from_bytes(&[5; 32]);
            assert!(open_meta_in::<B>(&wrap, &ID, 1, Kind::Text, &payload).is_err(), "label");

            let notes: &[u8] = br#"{"name":"n","notes":""}"#;
            let meta = seal_meta_in::<B>(&wrap, &ID, 1, Kind::File, notes).expect("seal");
            let opened = open_meta_in::<B>(&wrap, &ID, 1, Kind::File, &meta).expect("open");
            assert_eq!(opened.as_slice(), notes);
            assert!(open_meta_in::<B>(&wrap, &[4; 16], 1, Kind::File, &meta).is_err(), "id");
            assert!(open_meta_in::<B>(&wrap, &ID, 2, Kind::File, &meta).is_err(), "version");
            assert!(open_meta_in::<B>(&wrap, &ID, 1, Kind::Text, &meta).is_err(), "kind");
            assert!(open_meta_in::<B>(&other, &ID, 1, Kind::File, &meta).is_err(), "wrap key");
            assert!(open_payload_in::<B>(&k, &ID, Kind::File, &meta).is_err());
        });
    }

    #[test]
    fn a_holder_of_the_link_key_alone_cannot_open_the_meta() {
        for_backends!(B => {
            let wrap = SecretKey::from_bytes(&[5; 32]);
            let k = link_key();
            let notes: &[u8] = br#"{"name":"n","notes":"private"}"#;
            let meta = seal_meta_in::<B>(&wrap, &ID, 1, Kind::Text, notes).expect("seal");
            // K is the only key a recipient has: as the wrap key, as the payload key (what K
            // derives), and as the meta key derived from itself, it opens nothing.
            assert!(open_meta_in::<B>(&k, &ID, 1, Kind::Text, &meta).is_err(), "K as the wrap key");
            let from_k = k.child_in::<B>(META_LABEL).expect("child");
            let opened = aead::open::<B>(
                from_k.as_bytes(),
                &aad(META_LABEL, &ID, Kind::Text).expect("aad"),
                &meta,
            );
            assert!(opened.is_err(), "the old derivation from K");
            let payload_key = k.child_in::<B>(PAYLOAD_LABEL).expect("child");
            let opened = aead::open::<B>(
                payload_key.as_bytes(),
                &aad(META_LABEL, &ID, Kind::Text).expect("aad"),
                &meta,
            );
            assert!(opened.is_err(), "the payload key");
        });
    }

    #[test]
    fn the_sealed_key_names_the_version_the_meta_key_needs() {
        let wrap = SecretKey::from_bytes(&[5; 32]);
        let sealed = wrap_link_key(&wrap, &link_key(), &ID, 0x0102_0304).expect("wrap");
        assert_eq!(sealed_key_version(&sealed), Ok(0x0102_0304));
        assert!(sealed_key_version(&sealed[1..]).is_err());
        assert!(sealed_key_version(&[]).is_err());
    }

    #[test]
    fn a_changed_byte_or_length_fails() {
        for_backends!(B => {
            let k = link_key();
            let sealed = seal_payload_in::<B>(&k, &ID, Kind::Text, b"{}").expect("seal");
            for index in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[index] ^= 1;
                let opened = open_payload_in::<B>(&k, &ID, Kind::Text, &bad);
                assert!(opened.is_err(), "{} byte {index}", B::NAME);
            }
            assert!(open_payload_in::<B>(&k, &ID, Kind::Text, &sealed[1..]).is_err());
            let short = &sealed[..MIN_SEALED_LEN - 1];
            assert!(open_payload_in::<B>(&k, &ID, Kind::Text, short).is_err());
        });
    }

    #[test]
    fn the_link_key_round_trips_through_its_wrap() {
        for_backends!(B => {
            let wrap = SecretKey::from_bytes(&[5; 32]);
            let k = link_key();
            let sealed = wrap_link_key_in::<B>(&wrap, &k, &ID, 7).expect("wrap");
            assert_eq!(sealed.len(), SEALED_KEY_LEN, "{}", B::NAME);
            assert_eq!(&sealed[..4], &[0, 0, 0, 7]);
            let (opened, version) = unwrap_link_key_in::<B>(&wrap, &sealed, &ID).expect("unwrap");
            assert_eq!(opened.as_bytes(), k.as_bytes());
            assert_eq!(version, 7);
        });
    }

    #[test]
    fn the_wrap_binds_the_wrap_key_the_send_and_the_version() {
        for_backends!(B => {
            let wrap = SecretKey::from_bytes(&[5; 32]);
            let sealed = wrap_link_key_in::<B>(&wrap, &link_key(), &ID, 7).expect("wrap");
            let other = SecretKey::from_bytes(&[6; 32]);
            assert!(unwrap_link_key_in::<B>(&other, &sealed, &ID).is_err());
            assert!(unwrap_link_key_in::<B>(&wrap, &sealed, &[4; 16]).is_err());
            // The version is a prefix outside the seal, so changing it breaks the AAD.
            let mut other_version = sealed.clone();
            other_version[3] = 8;
            assert!(unwrap_link_key_in::<B>(&wrap, &other_version, &ID).is_err());
            for index in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[index] ^= 1;
                let opened = unwrap_link_key_in::<B>(&wrap, &bad, &ID);
                assert!(opened.is_err(), "{} byte {index}", B::NAME);
            }
            assert!(unwrap_link_key_in::<B>(&wrap, &sealed[1..], &ID).is_err());
            let mut long = sealed.clone();
            long.push(0);
            assert!(unwrap_link_key_in::<B>(&wrap, &long, &ID).is_err());
        });
    }

    #[test]
    fn the_proof_depends_on_the_password_the_link_key_and_the_send() {
        let k = link_key();
        let proof = password_proof(&k, &ID, "correct horse").expect("proof");
        assert_ne!(*proof, [0u8; PROOF_LEN]);
        let again = password_proof(&k, &ID, "correct horse").expect("proof");
        assert_eq!(*proof, *again);
        let typo = password_proof(&k, &ID, "correct horsf").expect("proof");
        assert_ne!(*proof, *typo);
        let other_send = password_proof(&k, &[4; 16], "correct horse").expect("proof");
        assert_ne!(*proof, *other_send);
        let other_key = SecretKey::from_bytes(&[8; 32]);
        let other_link = password_proof(&other_key, &ID, "correct horse").expect("proof");
        assert_ne!(*proof, *other_link);
    }

    #[test]
    fn the_proof_is_argon2id_of_the_nfc_password_under_the_proof_salt() {
        let k = link_key();
        let salt = proof_salt(&k, &ID).expect("salt");
        let expected =
            argon2id::master_key("caf\u{e9}".as_bytes(), &salt, 19456, 2, 1).expect("argon2");
        // A decomposed é gives the same proof as the composed one.
        let composed = password_proof(&k, &ID, "caf\u{e9}").expect("proof");
        let decomposed = password_proof(&k, &ID, "cafe\u{301}").expect("proof");
        assert_eq!(*composed, expected);
        assert_eq!(*decomposed, expected);
    }
}
