//! The member-confirmation statement: what someone who is already in a space signs after they
//! compared a new member's fingerprint with the member's own screen.
//!
//! ```text
//! statement = "kemlock/v1/confirm" ‖ space id (16) ‖ member id (16) ‖ u32be(member key version)
//!             ‖ fingerprint (64) ‖ confirmer id (16)
//! ```
//!
//! The statement is 134 bytes. The confirmer signs it with their own `sig1` key under context
//! `"confirm"`.

use crate::{
    Error,
    bundle::FINGERPRINT_LEN,
    sig1::{self, context::CONFIRM},
};

const LABEL: &[u8] = b"kemlock/v1/confirm";

/// The length of a statement.
pub const STATEMENT_LEN: usize = 18 + 16 + 16 + 4 + FINGERPRINT_LEN + 16;

/// What a confirmation says: who compared whose fingerprint, for which space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    pub space: [u8; 16],
    pub member: [u8; 16],
    /// The key version of the member's bundle that the fingerprint belongs to.
    pub member_key_version: u32,
    pub fingerprint: &'a [u8; FINGERPRINT_LEN],
    pub confirmer: [u8; 16],
}

impl Statement<'_> {
    /// The bytes that are signed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATEMENT_LEN);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.space);
        out.extend_from_slice(&self.member);
        out.extend_from_slice(&self.member_key_version.to_be_bytes());
        out.extend_from_slice(self.fingerprint);
        out.extend_from_slice(&self.confirmer);
        out
    }

    /// Signs the statement with the confirmer's own `sig1` key under context `"confirm"`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Vec<u8>, Error> {
        key.sign(CONFIRM, &self.to_bytes())
    }

    /// Passes only when `statement` is exactly this statement's bytes and `signature` is the
    /// confirmer's `sig1` signature over them, checked against `confirmer_public`.
    pub fn verify(
        &self,
        confirmer_public: &sig1::PublicKey,
        statement: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if statement != self.to_bytes() {
            return Err(Error::invalid());
        }
        confirmer_public.verify(CONFIRM, statement, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: [u8; FINGERPRINT_LEN] = [0xF0; FINGERPRINT_LEN];

    fn statement() -> Statement<'static> {
        Statement {
            space: [0x51; 16],
            member: [0x4D; 16],
            member_key_version: 2,
            fingerprint: &FINGERPRINT,
            confirmer: [0xC0; 16],
        }
    }

    #[test]
    fn layout_matches_the_doc() {
        let bytes = statement().to_bytes();
        assert_eq!(bytes.len(), STATEMENT_LEN);
        assert_eq!(STATEMENT_LEN, 134);
        assert_eq!(&bytes[..18], b"kemlock/v1/confirm");
        assert_eq!(&bytes[18..34], &[0x51; 16]);
        assert_eq!(&bytes[34..50], &[0x4D; 16]);
        assert_eq!(&bytes[50..54], &[0, 0, 0, 2]);
        assert_eq!(&bytes[54..118], &[0xF0; 64][..]);
        assert_eq!(&bytes[118..], &[0xC0; 16]);
    }

    #[test]
    fn a_confirmation_verifies_for_the_confirmer_only() {
        let key = sig1::SigningKey::from_bytes(&[21; 64]);
        let public = key.public_key().expect("public key");
        let signature = statement().sign(&key).expect("sign");
        assert_eq!(signature.len(), sig1::SIGNATURE_LEN);
        let bytes = statement().to_bytes();
        statement()
            .verify(&public, &bytes, &signature)
            .expect("verifies");

        let other = sig1::SigningKey::from_bytes(&[22; 64])
            .public_key()
            .expect("public key");
        assert!(statement().verify(&other, &bytes, &signature).is_err());
    }

    #[test]
    fn any_other_statement_or_context_fails() {
        let key = sig1::SigningKey::from_bytes(&[21; 64]);
        let public = key.public_key().expect("public key");
        let signature = statement().sign(&key).expect("sign");
        let bytes = statement().to_bytes();

        // The same signature doesn't cover another member, key version or space.
        for changed in [
            Statement {
                member: [0x4E; 16],
                ..statement()
            },
            Statement {
                member_key_version: 3,
                ..statement()
            },
            Statement {
                space: [0x52; 16],
                ..statement()
            },
            Statement {
                confirmer: [0xC1; 16],
                ..statement()
            },
        ] {
            assert!(changed.verify(&public, &bytes, &signature).is_err());
            assert!(
                changed
                    .verify(&public, &changed.to_bytes(), &signature)
                    .is_err()
            );
        }
        // A signature made for another purpose with the same key doesn't pass as a confirmation.
        let as_bundle = key.sign("bundle", &bytes).expect("sign");
        assert!(statement().verify(&public, &bytes, &as_bundle).is_err());
        // Nor does a statement with a byte flipped.
        let mut flipped = bytes.clone();
        flipped[60] ^= 1;
        assert!(statement().verify(&public, &flipped, &signature).is_err());
    }
}
