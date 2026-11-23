//! Sends, in plain Rust: the operations `docs/crypto.md`'s "Sends" section fixes, over the bytes
//! the web vault's worker hands in and out.
//!
//! The link key has to leave WebAssembly: it is the one secret that goes into a URL's fragment.
//! So these calls take and return it as base64url text, and the page keeps it only as long as the
//! link is on screen. Everything the server stores comes out sealed, and the password never leaves
//! as anything but its proof. What needs the unlocked account lives on the session: wrapping the
//! link key for its owner and sealing and opening the meta, whose key comes from the owner's
//! item-wrap key and never from the link key, so a link holder can't read it.

use kemlock_crypto::{
    keys::SecretKey,
    kma1,
    send::{self, Kind},
};
use zeroize::Zeroizing;

use crate::{b64, error::Error, ids};

/// A fresh link key, as the link carries it: 43 characters of base64url.
pub(crate) fn new_link_key() -> String {
    b64::encode(send::generate_link_key().as_bytes())
}

/// A link key from its base64url text; anything but 32 bytes is refused.
pub(crate) fn parse_link_key(text: &str) -> Result<SecretKey, Error> {
    let bytes = Zeroizing::new(b64::decode(text)?);
    let key: &[u8; send::LINK_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| Error::Invalid)?;
    Ok(SecretKey::from_bytes(key))
}

/// `text` or `file`.
pub(crate) fn kind(text: &str) -> Result<Kind, Error> {
    Kind::parse(text).ok_or(Error::Invalid)
}

/// The id a link names: its access id's 16 bytes, or a Send id as a hyphenated UUID.
pub(crate) fn send_id(text: &str) -> Result<[u8; 16], Error> {
    if let Ok(id) = ids::parse_uuid(text) {
        return Ok(id);
    }
    let bytes = b64::decode(text)?;
    bytes.as_slice().try_into().map_err(|_| Error::Invalid)
}

/// Seals a Send's payload JSON under the payload key from the link key, binding the Send's id and
/// kind. The meta is sealed by the session, because its key comes from the owner's account.
pub(crate) fn seal_payload(
    id: &[u8; 16],
    kind: Kind,
    link_key: &SecretKey,
    payload_json: &[u8],
) -> Result<Vec<u8>, Error> {
    Ok(send::seal_payload(link_key, id, kind, payload_json)?)
}

/// A payload's JSON text. Fails for another id, kind or key and for any altered byte.
pub(crate) fn open_payload(
    id: &[u8; 16],
    kind: Kind,
    link_key: &SecretKey,
    sealed: &[u8],
) -> Result<String, Error> {
    let plain = send::open_payload(link_key, id, kind, sealed)?;
    String::from_utf8(plain.to_vec()).map_err(|_| Error::Invalid)
}

/// The password proof, 32 bytes. The caller wipes the password it passed.
pub(crate) fn proof(
    id: &[u8; 16],
    link_key: &SecretKey,
    password: &str,
) -> Result<Zeroizing<[u8; send::PROOF_LEN]>, Error> {
    Ok(send::password_proof(link_key, id, password)?)
}

/// A file as a `KMA1` file under the Send's payload key.
pub(crate) fn seal_file(link_key: &SecretKey, plain: &[u8]) -> Result<Vec<u8>, Error> {
    let key = send::payload_key(link_key)?;
    Ok(kma1::seal(&key, plain)?)
}

/// The plaintext of a Send's `KMA1` file.
pub(crate) fn open_file(link_key: &SecretKey, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = send::payload_key(link_key)?;
    Ok(kma1::open(&key, file)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_TEXT: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
    const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    fn key() -> SecretKey {
        SecretKey::from_bytes(&[9; 32])
    }

    #[test]
    fn a_new_link_key_is_43_characters_of_base64url() {
        let text = new_link_key();
        assert_eq!(text.len(), 43);
        assert_ne!(text, new_link_key());
        let parsed = parse_link_key(&text).expect("it parses");
        assert_eq!(b64::encode(parsed.as_bytes()), text);
    }

    #[test]
    fn a_link_key_must_be_32_bytes_of_canonical_base64url() {
        assert!(parse_link_key(&"A".repeat(43)).is_ok(), "32 zero bytes");
        for bad in [
            String::new(),
            "AAAA".to_owned(),
            // 31 and 33 bytes.
            "A".repeat(42),
            "A".repeat(44),
            // Padded, and in the standard alphabet.
            format!("{}=", "A".repeat(43)),
            format!("{}8", "+".repeat(42)),
        ] {
            assert!(parse_link_key(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_id_is_a_uuid_or_an_access_id() {
        let access = b64::encode(&ID);
        assert_eq!(access.len(), 22);
        assert_eq!(send_id(ID_TEXT), Ok(ID));
        assert_eq!(send_id(&access), Ok(ID));
        for bad in ["", "nope", "AAAA", "00010203-0405-0607-0809-0A0B0C0D0E0F"] {
            assert!(send_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn kinds_are_text_or_file() {
        assert_eq!(kind("text"), Ok(Kind::Text));
        assert_eq!(kind("file"), Ok(Kind::File));
        assert!(kind("Text").is_err());
        assert!(kind("").is_err());
    }

    #[test]
    fn parts_seal_and_open_with_the_id_and_kind_bound() {
        let k = key();
        let note = br#"{"name":"a","text":"b"}"#;
        let payload = seal_payload(&ID, Kind::Text, &k, note).expect("seal");
        assert_eq!(
            open_payload(&ID, Kind::Text, &k, &payload).as_deref(),
            Ok(r#"{"name":"a","text":"b"}"#)
        );
        assert!(open_payload(&[0; 16], Kind::Text, &k, &payload).is_err());
        assert!(open_payload(&ID, Kind::File, &k, &payload).is_err());
        let other = SecretKey::from_bytes(&[1; 32]);
        assert!(open_payload(&ID, Kind::Text, &other, &payload).is_err());
    }

    #[test]
    fn a_file_is_a_kma1_file_under_the_payload_key() {
        let k = key();
        let plain = vec![7u8; 70_000];
        let file = seal_file(&k, &plain).expect("seal");
        assert_eq!(file.len(), kma1::sealed_len(plain.len()));
        assert_eq!(&file[..4], b"KMA1");
        assert_eq!(
            open_file(&k, &file).expect("open").as_slice(),
            plain.as_slice()
        );
        // Opening by hand with the payload key gives the same bytes.
        let payload_key = send::payload_key(&k).expect("key");
        assert_eq!(
            kma1::open(&payload_key, &file).expect("open").as_slice(),
            plain.as_slice()
        );
        assert!(open_file(&SecretKey::from_bytes(&[1; 32]), &file).is_err());
        assert!(open_file(&k, &file[..file.len() - 1]).is_err());
    }

    #[test]
    fn the_proof_is_32_bytes_and_follows_the_password() {
        let k = key();
        let proof = proof(&ID, &k, "hunter2").expect("proof");
        assert_eq!(proof.len(), 32);
        assert_eq!(*proof, *super::proof(&ID, &k, "hunter2").expect("proof"));
        assert_ne!(*proof, *super::proof(&ID, &k, "hunter3").expect("proof"));
        assert_eq!(
            *super::proof(&ID, &k, "caf\u{e9}").expect("proof"),
            *super::proof(&ID, &k, "cafe\u{301}").expect("proof")
        );
    }
}
