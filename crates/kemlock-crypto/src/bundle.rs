//! The public-key bundle and its fingerprint.
//!
//! ```text
//! bundle      = "kemlock/v1/bundle" ‖ account id (16) ‖ u32be(key version)
//!               ‖ kx1 public key (1600) ‖ sig1 public key (1984)
//! fingerprint = SHA-512("kemlock/v1/fingerprint" ‖ bundle)
//! ```
//!
//! The bundle is signed with the account's own `sig1` key under context `"bundle"`. People compare
//! the fingerprint as 12 groups of 5 digits: group `i` (0 to 11) is
//! `u40be(fingerprint[5i .. 5i+5]) mod 100000`, written with leading zeros.

use crate::{
    Error,
    backend::{Active, Backend},
    kx1,
    sig1::{self, context::BUNDLE},
    wire::Reader,
};

const BUNDLE_LABEL: &[u8] = b"kemlock/v1/bundle";
const FINGERPRINT_LABEL: &[u8] = b"kemlock/v1/fingerprint";

/// The length of the encoded bundle.
pub const BUNDLE_LEN: usize = 17 + 16 + 4 + kx1::PUBLIC_KEY_LEN + sig1::PUBLIC_KEY_LEN;
/// The length of a fingerprint.
pub const FINGERPRINT_LEN: usize = 64;
/// How many groups of digits a fingerprint is shown as.
pub const FINGERPRINT_GROUPS: usize = 12;

/// An account's public keys at one key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub account_id: [u8; 16],
    pub key_version: u32,
    pub kx1_public: kx1::PublicKey,
    pub sig1_public: sig1::PublicKey,
}

impl Bundle {
    /// The bytes that are signed and fingerprinted.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_LEN);
        out.extend_from_slice(BUNDLE_LABEL);
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(self.kx1_public.as_bytes());
        out.extend_from_slice(self.sig1_public.as_bytes());
        out
    }

    /// Parses a bundle, refusing another label, a wrong length and trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Bundle, Error> {
        if bytes.len() != BUNDLE_LEN {
            return Err(Error::invalid());
        }
        let mut reader = Reader::new(bytes);
        if reader.take(BUNDLE_LABEL.len())? != BUNDLE_LABEL {
            return Err(Error::invalid());
        }
        let account_id = reader.array::<16>()?;
        let key_version = reader.u32()?;
        let kx1_public = kx1::PublicKey::from_bytes(reader.take(kx1::PUBLIC_KEY_LEN)?)?;
        let sig1_public = sig1::PublicKey::from_bytes(reader.take(sig1::PUBLIC_KEY_LEN)?)?;
        reader.finish()?;
        Ok(Bundle {
            account_id,
            key_version,
            kx1_public,
            sig1_public,
        })
    }

    /// `SHA-512("kemlock/v1/fingerprint" ‖ bundle)`.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        fingerprint_in::<Active>(&self.to_bytes())
    }

    /// The fingerprint as the 12 groups of 5 digits people compare, joined by spaces.
    pub fn fingerprint_text(&self) -> String {
        fingerprint_groups(&self.fingerprint()).join(" ")
    }

    /// Signs the bundle with the account's own `sig1` key under context `"bundle"`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Vec<u8>, Error> {
        key.sign(BUNDLE, &self.to_bytes())
    }

    /// Checks a signature of this bundle against the `sig1` public key the bundle itself carries.
    /// This proves the owner of that key published the bundle, not that the key is the right
    /// person's: that is what comparing fingerprints is for.
    pub fn verify_self_signature(&self, signature: &[u8]) -> Result<(), Error> {
        self.sig1_public.verify(BUNDLE, &self.to_bytes(), signature)
    }
}

pub(crate) fn fingerprint_in<B: Backend>(bundle: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let mut input = Vec::with_capacity(FINGERPRINT_LABEL.len() + bundle.len());
    input.extend_from_slice(FINGERPRINT_LABEL);
    input.extend_from_slice(bundle);
    B::sha512(&input)
}

/// Splits a fingerprint into its 12 groups of 5 digits: group `i` is
/// `u40be(fingerprint[5i .. 5i+5]) mod 100000`, with leading zeros.
pub fn fingerprint_groups(fingerprint: &[u8; FINGERPRINT_LEN]) -> [String; FINGERPRINT_GROUPS] {
    core::array::from_fn(|i| {
        let mut value = 0u64;
        for byte in &fingerprint[5 * i..5 * i + 5] {
            value = (value << 8) | u64::from(*byte);
        }
        format!("{:05}", value % 100_000)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Bundle {
        // The key halves needn't be real keys to exercise the encoding.
        Bundle {
            account_id: [0xA1; 16],
            key_version: 3,
            kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
            sig1_public: sig1::PublicKey::from_bytes(&[2; 1984]).expect("length"),
        }
    }

    #[test]
    fn layout_matches_the_doc() {
        let bytes = bundle().to_bytes();
        assert_eq!(bytes.len(), BUNDLE_LEN);
        assert_eq!(BUNDLE_LEN, 3621);
        assert_eq!(&bytes[..17], b"kemlock/v1/bundle");
        assert_eq!(&bytes[17..33], &[0xA1; 16]);
        assert_eq!(&bytes[33..37], &[0, 0, 0, 3]);
        assert_eq!(&bytes[37..1637], &[1u8; 1600][..]);
        assert_eq!(&bytes[1637..], &[2u8; 1984][..]);
    }

    #[test]
    fn round_trips() {
        let b = bundle();
        assert_eq!(Bundle::from_bytes(&b.to_bytes()), Ok(b));
    }

    #[test]
    fn parsing_is_strict() {
        let bytes = bundle().to_bytes();
        assert!(Bundle::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(Bundle::from_bytes(&long).is_err());
        let mut bad_label = bytes.clone();
        bad_label[0] ^= 1;
        assert!(Bundle::from_bytes(&bad_label).is_err());
        assert!(Bundle::from_bytes(&[]).is_err());
    }

    #[test]
    fn fingerprint_is_sha512_of_label_and_bundle() {
        for_backends!(B => {
            let b = bundle();
            let mut input = b"kemlock/v1/fingerprint".to_vec();
            input.extend_from_slice(&b.to_bytes());
            assert_eq!(fingerprint_in::<B>(&b.to_bytes()), B::sha512(&input), "{}", B::NAME);
        });
    }

    #[test]
    fn every_field_changes_the_fingerprint() {
        let base = bundle().fingerprint();
        let mut b = bundle();
        b.account_id[0] ^= 1;
        assert_ne!(b.fingerprint(), base);
        let mut b = bundle();
        b.key_version += 1;
        assert_ne!(b.fingerprint(), base);
        let mut b = bundle();
        b.kx1_public = kx1::PublicKey::from_bytes(&[9; 1600]).expect("length");
        assert_ne!(b.fingerprint(), base);
        let mut b = bundle();
        b.sig1_public = sig1::PublicKey::from_bytes(&[9; 1984]).expect("length");
        assert_ne!(b.fingerprint(), base);
    }

    #[test]
    fn groups_are_five_digits_from_five_bytes_each() {
        let mut fp = [0u8; 64];
        // Group 0: 0x00_0000_0001 -> 1.
        fp[4] = 1;
        // Group 1: u40be(ff ff ff ff ff) = 1_099_511_627_775 -> mod 100000 = 27775.
        fp[5..10].fill(0xFF);
        // Group 11 reads bytes 55..60.
        fp[59] = 0x2A;
        let groups = fingerprint_groups(&fp);
        assert_eq!(groups.len(), 12);
        assert_eq!(groups[0], "00001");
        assert_eq!(groups[1], "27775");
        assert_eq!(groups[2], "00000");
        assert_eq!(groups[11], "00042");
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit()))
        );
    }

    #[test]
    fn text_is_sixty_digits_in_twelve_groups() {
        let text = bundle().fingerprint_text();
        assert_eq!(text.len(), 60 + 11);
        assert_eq!(text.split(' ').count(), 12);
        assert!(text.split(' ').all(|g| g.len() == 5));
    }

    #[test]
    fn a_signed_bundle_verifies_and_a_changed_one_does_not() {
        for_backends!(B => {
            let signing = sig1::SigningKey::from_bytes(&[8; 64]);
            let sig1_public = sig1::public_key_in::<B>(&signing).expect("public key");
            let kx1_private = kx1::PrivateKey::from_bytes(&[4; 96]);
            let kx1_public = kx1::public_key_in::<B>(&kx1_private).expect("public key");
            let b = Bundle {
                account_id: [1; 16],
                key_version: 1,
                kx1_public,
                sig1_public,
            };
            let sig = sig1::sign_in::<B>(&signing, BUNDLE, &b.to_bytes()).expect("sign");
            sig1::verify_in::<B>(&b.sig1_public, BUNDLE, &b.to_bytes(), &sig).expect("verify");
            let mut changed = b.clone();
            changed.key_version = 2;
            assert!(
                sig1::verify_in::<B>(&b.sig1_public, BUNDLE, &changed.to_bytes(), &sig).is_err(),
                "{}", B::NAME
            );
        });
    }

    #[test]
    fn the_public_signing_api_round_trips_on_the_default_backend() {
        // sig1 works on every backend, so this runs with either feature.
        let signing = sig1::SigningKey::from_bytes(&[8; 64]);
        let mut b = bundle();
        b.sig1_public = signing.public_key().expect("public key");
        let sig = b.sign(&signing).expect("sign");
        b.verify_self_signature(&sig).expect("verify");
        b.key_version += 1;
        assert!(b.verify_self_signature(&sig).is_err());
    }
}
