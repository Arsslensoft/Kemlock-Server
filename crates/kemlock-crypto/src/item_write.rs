//! The signed item write: the statement the writing account signs for each `kem1` write
//! (docs/crypto.md, "Signed item writes").
//!
//! ```text
//! statement = "kemlock/v1/item-write" ‖ owner (17) ‖ item id (16) ‖ lp(kind) ‖ u64be(revision)
//!             ‖ u64be(replaces) ‖ u8(deleted) ‖ envelope hash (32)
//!             ‖ writer account id (16) ‖ u32be(writer key version)
//! envelope hash = SHA-256(u32be(key version) ‖ lp(ciphertext) ‖ lp(item key)), or 32 zero bytes
//!                 for a tombstone
//! ```
//!
//! `replaces` is the revision the write replaces, `revision - 1`. The writer signs the statement
//! with their own `sig1` key under context `"item-write"`.

use crate::{
    Error,
    bundle::Bundle,
    hash::sha256,
    owner::{self, Owner},
    sig1::{self, context::ITEM_WRITE},
    wire::lp,
};

const LABEL: &[u8] = b"kemlock/v1/item-write";
/// The longest item kind, as the server accepts it.
pub const MAX_KIND_LEN: usize = 64;
/// The length of the stored form of a signature: writer id, key version and the `sig1` signature.
pub const STORED_LEN: usize = 16 + 4 + sig1::SIGNATURE_LEN;

/// The hash of an envelope, which the statement carries: `SHA-256(u32be(key version) ‖
/// lp(ciphertext) ‖ lp(item key))` for a live write, 32 zero bytes for a tombstone (`sealed` is
/// `None`). `key_version` is the one the item carries on the wire.
pub fn envelope_hash(key_version: u32, sealed: Option<(&[u8], &[u8])>) -> Result<[u8; 32], Error> {
    let Some((ciphertext, item_key)) = sealed else {
        return Ok([0; 32]);
    };
    let mut data = Vec::with_capacity(12 + ciphertext.len() + item_key.len());
    data.extend_from_slice(&key_version.to_be_bytes());
    lp(&mut data, ciphertext)?;
    lp(&mut data, item_key)?;
    Ok(sha256(&data))
}

/// What a write says: who wrote which revision of which item, and the hash of what they wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    pub owner: Owner,
    pub item_id: [u8; 16],
    pub kind: &'a str,
    /// The revision written, from 1.
    pub revision: u64,
    pub deleted: bool,
    /// [`envelope_hash`] of the write; zero for a tombstone.
    pub envelope: [u8; 32],
    pub writer: [u8; 16],
    pub writer_key_version: u32,
}

impl Statement<'_> {
    /// The bytes that are signed. Fails for a revision of 0, a kind that isn't 1 to 64 bytes, and
    /// a tombstone whose hash isn't zero.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.revision == 0
            || self.kind.is_empty()
            || self.kind.len() > MAX_KIND_LEN
            || (self.deleted && self.envelope != [0; 32])
        {
            return Err(Error::invalid());
        }
        let mut out = Vec::with_capacity(LABEL.len() + owner::LEN + 16 + 4 + self.kind.len() + 69);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.owner.to_bytes());
        out.extend_from_slice(&self.item_id);
        lp(&mut out, self.kind.as_bytes())?;
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&(self.revision - 1).to_be_bytes());
        out.push(u8::from(self.deleted));
        out.extend_from_slice(&self.envelope);
        out.extend_from_slice(&self.writer);
        out.extend_from_slice(&self.writer_key_version.to_be_bytes());
        Ok(out)
    }

    /// Signs the statement with the writer's own `sig1` key under context `"item-write"`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Vec<u8>, Error> {
        key.sign(ITEM_WRITE, &self.to_bytes()?)
    }

    /// Passes only when `signature` is the `sig1` signature of exactly this statement, made with
    /// the key `writer_public`.
    pub fn verify(&self, writer_public: &sig1::PublicKey, signature: &[u8]) -> Result<(), Error> {
        writer_public.verify(ITEM_WRITE, &self.to_bytes()?, signature)
    }
}

/// Checks `signature` against the writer's `bundle`: the bundle must be the writer's own, at the
/// key version the statement names, and its `sig1` key must have made the signature.
pub fn verify_with_bundle(
    statement: &Statement<'_>,
    bundle: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let bundle = Bundle::from_bytes(bundle)?;
    if bundle.account_id != statement.writer || bundle.key_version != statement.writer_key_version {
        return Err(Error::invalid());
    }
    statement.verify(&bundle.sig1_public, signature)
}

/// The stored and federated form of a write's signature: `writer (16) ‖ u32be(key version) ‖
/// signature (3373)`.
pub fn to_stored(writer: &[u8; 16], key_version: u32, signature: &[u8]) -> Result<Vec<u8>, Error> {
    if signature.len() != sig1::SIGNATURE_LEN {
        return Err(Error::invalid());
    }
    let mut out = Vec::with_capacity(STORED_LEN);
    out.extend_from_slice(writer);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// Splits the stored form into the writer, the key version and the signature.
pub fn from_stored(stored: &[u8]) -> Result<([u8; 16], u32, &[u8]), Error> {
    if stored.len() != STORED_LEN {
        return Err(Error::invalid());
    }
    let mut writer = [0u8; 16];
    writer.copy_from_slice(&stored[..16]);
    let mut version = [0u8; 4];
    version.copy_from_slice(&stored[16..20]);
    Ok((writer, u32::from_be_bytes(version), &stored[20..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(envelope: [u8; 32], deleted: bool) -> Statement<'static> {
        Statement {
            owner: Owner::space([0x51; 16]),
            item_id: [0x17; 16],
            kind: "login",
            revision: 4,
            deleted,
            envelope,
            writer: [0xA1; 16],
            writer_key_version: 2,
        }
    }

    fn live() -> Statement<'static> {
        statement(
            envelope_hash(3, Some((b"cipher".as_slice(), b"wrapped".as_slice()))).expect("hash"),
            false,
        )
    }

    #[test]
    fn layout_matches_the_doc() {
        let bytes = live().to_bytes().expect("encode");
        assert_eq!(bytes.len(), 21 + 17 + 16 + 4 + 5 + 8 + 8 + 1 + 32 + 16 + 4);
        assert_eq!(&bytes[..21], b"kemlock/v1/item-write");
        assert_eq!(bytes[21], 2);
        assert_eq!(&bytes[22..38], &[0x51; 16]);
        assert_eq!(&bytes[38..54], &[0x17; 16]);
        assert_eq!(&bytes[54..58], &[0, 0, 0, 5]);
        assert_eq!(&bytes[58..63], b"login");
        assert_eq!(&bytes[63..71], &[0, 0, 0, 0, 0, 0, 0, 4]);
        assert_eq!(&bytes[71..79], &[0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(bytes[79], 0);
        assert_eq!(&bytes[80..112], &live().envelope);
        assert_eq!(&bytes[112..128], &[0xA1; 16]);
        assert_eq!(&bytes[128..], &[0, 0, 0, 2]);
    }

    #[test]
    fn the_envelope_hash_covers_the_key_version_ciphertext_and_item_key() {
        let base = envelope_hash(3, Some((b"cipher".as_slice(), b"wrapped".as_slice())));
        let mut data = 3u32.to_be_bytes().to_vec();
        data.extend_from_slice(&6u32.to_be_bytes());
        data.extend_from_slice(b"cipher");
        data.extend_from_slice(&7u32.to_be_bytes());
        data.extend_from_slice(b"wrapped");
        assert_eq!(base, Ok(sha256(&data)));
        for other in [
            envelope_hash(4, Some((b"cipher".as_slice(), b"wrapped".as_slice()))),
            envelope_hash(3, Some((b"cipheR".as_slice(), b"wrapped".as_slice()))),
            envelope_hash(3, Some((b"cipher".as_slice(), b"wrappeD".as_slice()))),
            // The lengths are part of it: the bytes can't be moved between the two values.
            envelope_hash(3, Some((b"ciphe".as_slice(), b"rwrapped".as_slice()))),
        ] {
            assert_ne!(other, base);
        }
        assert_eq!(envelope_hash(3, None), Ok([0; 32]));
    }

    #[test]
    fn a_write_verifies_for_the_writer_only() {
        let key = sig1::SigningKey::from_bytes(&[31; 64]);
        let public = key.public_key().expect("public key");
        let signature = live().sign(&key).expect("sign");
        assert_eq!(signature.len(), sig1::SIGNATURE_LEN);
        live().verify(&public, &signature).expect("verifies");
        let other = sig1::SigningKey::from_bytes(&[32; 64])
            .public_key()
            .expect("public key");
        assert!(live().verify(&other, &signature).is_err());
    }

    #[test]
    fn any_other_statement_fails() {
        let key = sig1::SigningKey::from_bytes(&[31; 64]);
        let public = key.public_key().expect("public key");
        let signature = live().sign(&key).expect("sign");
        let changed = [
            Statement {
                owner: Owner::user([0x51; 16]),
                ..live()
            },
            Statement {
                item_id: [0x18; 16],
                ..live()
            },
            Statement {
                kind: "note",
                ..live()
            },
            Statement {
                revision: 5,
                ..live()
            },
            Statement {
                envelope: [9; 32],
                ..live()
            },
            Statement {
                writer: [0xA2; 16],
                ..live()
            },
            Statement {
                writer_key_version: 3,
                ..live()
            },
            statement([0; 32], true),
        ];
        for other in changed {
            assert!(other.verify(&public, &signature).is_err(), "{other:?}");
        }
        // Another context doesn't verify either.
        let bytes = live().to_bytes().expect("encode");
        assert!(public.verify("manifest", &bytes, &signature).is_err());
    }

    #[test]
    fn nonsense_statements_are_not_encoded() {
        assert!(Statement { revision: 0, ..live() }.to_bytes().is_err());
        assert!(Statement { kind: "", ..live() }.to_bytes().is_err());
        let long = "x".repeat(65);
        assert!(Statement { kind: &long, ..live() }.to_bytes().is_err());
        // A tombstone has no envelope hash.
        assert!(statement([1; 32], true).to_bytes().is_err());
        assert!(statement([0; 32], true).to_bytes().is_ok());
    }

    #[test]
    fn the_stored_form_round_trips() {
        let signature = vec![7u8; sig1::SIGNATURE_LEN];
        let stored = to_stored(&[1; 16], 9, &signature).expect("stored");
        assert_eq!(stored.len(), STORED_LEN);
        assert_eq!(
            from_stored(&stored),
            Ok(([1; 16], 9, signature.as_slice()))
        );
        assert!(to_stored(&[1; 16], 9, &signature[1..]).is_err());
        assert!(from_stored(&stored[1..]).is_err());
    }

    #[test]
    fn a_write_verifies_against_the_writers_bundle_only() {
        use crate::kx1;
        let key = sig1::SigningKey::from_bytes(&[31; 64]);
        let bundle = Bundle {
            account_id: [0xA1; 16],
            key_version: 2,
            kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
            sig1_public: key.public_key().expect("public key"),
        };
        let signature = live().sign(&key).expect("sign");
        verify_with_bundle(&live(), &bundle.to_bytes(), &signature).expect("verifies");

        // Another account's bundle, another key version of it, and another key all fail.
        let other_account = Bundle {
            account_id: [0xA2; 16],
            ..bundle.clone()
        };
        let other_version = Bundle {
            key_version: 3,
            ..bundle.clone()
        };
        let other_key = Bundle {
            sig1_public: sig1::SigningKey::from_bytes(&[32; 64])
                .public_key()
                .expect("public key"),
            ..bundle.clone()
        };
        for other in [other_account, other_version, other_key] {
            assert!(verify_with_bundle(&live(), &other.to_bytes(), &signature).is_err());
        }
        assert!(verify_with_bundle(&live(), &[1, 2, 3], &signature).is_err());
    }
}
