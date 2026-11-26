//! The signed key box: what the member who sealed a space key or a collection key to someone signs,
//! so a member of a space with no chain knows who made the box before opening it.
//!
//! ```text
//! statement = "kemlock/v1/key-box" ‖ lp(box context) ‖ lp(aad) ‖ lp(box)
//!             ‖ sealer id (16) ‖ u32be(sealer key version)
//! ```
//!
//! The box context is `"space-key"` or `"collection-key"`, `aad` is that box's own `aad` (the space,
//! the collection, the key version and the recipient, see [`crate::sealed_box`]) and the box is its
//! 1661 bytes. The sealer signs the statement with their own `sig1` key under context `"key-box"`.
//! The signature is kept beside the box, never inside it.

use crate::{
    Error,
    sealed_box::context::{COLLECTION_KEY, SPACE_KEY},
    sig1::{self, context::KEY_BOX},
    wire::lp,
};

const LABEL: &[u8] = b"kemlock/v1/key-box";

/// The length of a sealed space key or collection key: a box of a 32-byte key.
pub const BOX_LEN: usize = 1661;
/// The `aad` of a space key's box: space (16) ‖ key version (4) ‖ recipient (16).
pub const SPACE_AAD_LEN: usize = 36;
/// The `aad` of a collection key's box: space (16) ‖ collection (16) ‖ key version (4) ‖ recipient
/// (16).
pub const COLLECTION_AAD_LEN: usize = 52;

/// Which key a box seals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Space,
    Collection,
}

impl Kind {
    /// The sealed-box context of this kind of key.
    pub fn context(self) -> &'static str {
        match self {
            Kind::Space => SPACE_KEY,
            Kind::Collection => COLLECTION_KEY,
        }
    }

    fn aad_len(self) -> usize {
        match self {
            Kind::Space => SPACE_AAD_LEN,
            Kind::Collection => COLLECTION_AAD_LEN,
        }
    }
}

/// The `aad` of a space key's box.
pub fn space_aad(space: &[u8; 16], key_version: u32, recipient: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SPACE_AAD_LEN);
    out.extend_from_slice(space);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(recipient);
    out
}

/// The `aad` of a collection key's box.
pub fn collection_aad(
    space: &[u8; 16],
    collection: &[u8; 16],
    key_version: u32,
    recipient: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(COLLECTION_AAD_LEN);
    out.extend_from_slice(space);
    out.extend_from_slice(collection);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(recipient);
    out
}

/// What a signature of a key box says: this account, at this key version, sealed this box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    pub kind: Kind,
    /// The box's own `aad`: the space, the collection (for a collection key), the key version and
    /// the recipient.
    pub aad: &'a [u8],
    /// The sealed box, `u8(1) ‖ …`, 1661 bytes.
    pub sealed_box: &'a [u8],
    /// The account that sealed it.
    pub sealer: [u8; 16],
    /// The key version of the sealer's bundle whose `sig1` key signs.
    pub sealer_key_version: u32,
}

impl Statement<'_> {
    /// The bytes that are signed. Refused when the `aad` or the box has the wrong length for the
    /// kind of key, so a statement can't be made over something that isn't a key box.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.aad.len() != self.kind.aad_len() || self.sealed_box.len() != BOX_LEN {
            return Err(Error::invalid());
        }
        let context = self.kind.context();
        let mut out = Vec::with_capacity(
            LABEL.len() + 12 + context.len() + self.aad.len() + self.sealed_box.len() + 20,
        );
        out.extend_from_slice(LABEL);
        lp(&mut out, context.as_bytes())?;
        lp(&mut out, self.aad)?;
        lp(&mut out, self.sealed_box)?;
        out.extend_from_slice(&self.sealer);
        out.extend_from_slice(&self.sealer_key_version.to_be_bytes());
        Ok(out)
    }

    /// Signs the statement with the sealer's own `sig1` key under context `"key-box"`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Vec<u8>, Error> {
        key.sign(KEY_BOX, &self.to_bytes()?)
    }

    /// Passes only when `signature` is the sealer's `sig1` signature over exactly this statement,
    /// checked against `sealer_public`.
    pub fn verify(&self, sealer_public: &sig1::PublicKey, signature: &[u8]) -> Result<(), Error> {
        sealer_public.verify(KEY_BOX, &self.to_bytes()?, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: [u8; 16] = [0x51; 16];
    const COLLECTION: [u8; 16] = [0xC1; 16];
    const RECIPIENT: [u8; 16] = [0x4D; 16];
    const SEALER: [u8; 16] = [0x5E; 16];

    fn boxed() -> Vec<u8> {
        let mut b = vec![0xB0; BOX_LEN];
        b[0] = 1;
        b
    }

    #[test]
    fn layout_matches_the_doc() {
        let aad = space_aad(&SPACE, 3, &RECIPIENT);
        let b = boxed();
        let bytes = Statement {
            kind: Kind::Space,
            aad: &aad,
            sealed_box: &b,
            sealer: SEALER,
            sealer_key_version: 2,
        }
        .to_bytes()
        .expect("statement");
        assert_eq!(bytes.len(), 1756);
        assert_eq!(&bytes[..18], b"kemlock/v1/key-box");
        assert_eq!(&bytes[18..22], &[0, 0, 0, 9]);
        assert_eq!(&bytes[22..31], b"space-key");
        assert_eq!(&bytes[31..35], &[0, 0, 0, 36]);
        assert_eq!(&bytes[35..71], aad.as_slice());
        assert_eq!(&bytes[71..75], &[0, 0, 6, 125]);
        assert_eq!(&bytes[75..75 + BOX_LEN], b.as_slice());
        assert_eq!(&bytes[75 + BOX_LEN..91 + BOX_LEN], &SEALER);
        assert_eq!(&bytes[91 + BOX_LEN..], &[0, 0, 0, 2]);

        let aad = collection_aad(&SPACE, &COLLECTION, 3, &RECIPIENT);
        let bytes = Statement {
            kind: Kind::Collection,
            aad: &aad,
            sealed_box: &b,
            sealer: SEALER,
            sealer_key_version: 2,
        }
        .to_bytes()
        .expect("statement");
        assert_eq!(bytes.len(), 1777);
        assert_eq!(&bytes[22..36], b"collection-key");
    }

    #[test]
    fn a_statement_needs_a_box_and_an_aad_of_the_right_length() {
        let b = boxed();
        let aad = space_aad(&SPACE, 3, &RECIPIENT);
        let good = Statement {
            kind: Kind::Space,
            aad: &aad,
            sealed_box: &b,
            sealer: SEALER,
            sealer_key_version: 2,
        };
        assert!(good.to_bytes().is_ok());
        assert!(
            Statement {
                kind: Kind::Collection,
                ..good
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            Statement {
                sealed_box: &b[1..],
                ..good
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            Statement {
                aad: &aad[1..],
                ..good
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn a_box_verifies_for_its_sealer_only_and_nothing_else_is_covered() {
        let key = sig1::SigningKey::from_bytes(&[31; 64]);
        let public = key.public_key().expect("public key");
        let b = boxed();
        let aad = collection_aad(&SPACE, &COLLECTION, 4, &RECIPIENT);
        let statement = Statement {
            kind: Kind::Collection,
            aad: &aad,
            sealed_box: &b,
            sealer: SEALER,
            sealer_key_version: 2,
        };
        let signature = statement.sign(&key).expect("sign");
        assert_eq!(signature.len(), sig1::SIGNATURE_LEN);
        statement.verify(&public, &signature).expect("verifies");

        let other = sig1::SigningKey::from_bytes(&[32; 64])
            .public_key()
            .expect("public key");
        assert!(statement.verify(&other, &signature).is_err());

        // Another box, recipient, version, sealer or sealer version isn't covered.
        let mut other_box = b.clone();
        other_box[700] ^= 1;
        let other_aad = collection_aad(&SPACE, &COLLECTION, 5, &RECIPIENT);
        for changed in [
            Statement {
                sealed_box: &other_box,
                ..statement
            },
            Statement {
                aad: &other_aad,
                ..statement
            },
            Statement {
                sealer: [0x5F; 16],
                ..statement
            },
            Statement {
                sealer_key_version: 3,
                ..statement
            },
        ] {
            assert!(changed.verify(&public, &signature).is_err());
        }
        // A signature of the same bytes under another context isn't a key box signature.
        let as_confirm = key
            .sign("confirm", &statement.to_bytes().expect("bytes"))
            .expect("sign");
        assert!(statement.verify(&public, &as_confirm).is_err());
    }
}
