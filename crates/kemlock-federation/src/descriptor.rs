//! The signed descriptor a server publishes at `GET /fed/v1/descriptor`.
//!
//! The descriptor holds the server's identity key (`sig1`, pinned by every peer at pairing), its
//! KEM key (`kx1`, rotated every 30 days and signed by the identity key), the suites it accepts
//! (most preferred first), where to reach it, and a validity window of 37 days (the 30-day
//! rotation plus a week of overlap). It is a [`Signed`] envelope whose body is deterministic
//! CBOR, signed under the context `"federation-descriptor"`. See `docs/federation.md`.

use crate::cbor::Value;
use crate::crypto;
use crate::error::{FedError, Result};
use crate::signed::Signed;
use crate::suite::{self, Suite};
use crate::wire::server_id;
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::ServerId;

/// The descriptor format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of a descriptor's signature.
pub const CONTEXT: &str = "federation-descriptor";
/// How often the KEM key is replaced.
pub const KEM_ROTATION_SECS: u64 = 30 * 86_400;
/// How long a descriptor is valid: the rotation plus a week of overlap.
pub const VALIDITY_SECS: u64 = 37 * 86_400;
/// How far a clock may differ from ours.
pub const SKEW_SECS: u64 = 300;

const MAX_SUITES: usize = 16;
const MAX_SUITE_LEN: usize = 64;
const MAX_ADDRESSES: usize = 8;
const MAX_ADDRESS_LEN: usize = 256;
const MAX_OPERATOR_LEN: usize = 128;

/// What a server says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub server: ServerId,
    pub identity_key: sig1::PublicKey,
    pub kem_key: kx1::PublicKey,
    /// Suite names, most preferred first. Unknown names are kept, so the signature still covers
    /// them and a downgrade through them is visible.
    pub suites: Vec<String>,
    /// Base URLs, such as `https://vault.example.org`.
    pub addresses: Vec<String>,
    /// Who runs the server, shown in the peer's console.
    pub operator: String,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds.
    pub not_after: u64,
}

/// `SHA-256("kemlock/v1/fed/kem-key" ‖ kx1 public key)`: names the KEM key a hello encapsulates
/// to, so a server holding two keys during a rotation knows which to use.
pub fn kem_key_id(key: &kx1::PublicKey) -> [u8; 32] {
    let mut input = b"kemlock/v1/fed/kem-key".to_vec();
    input.extend_from_slice(key.as_bytes());
    crypto::sha256(&input)
}

impl Descriptor {
    /// The canonical CBOR body that is signed.
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.server.as_bytes())),
            (2, Value::bytes(self.identity_key.as_bytes())),
            (3, Value::bytes(self.kem_key.as_bytes())),
            (
                4,
                Value::Array(self.suites.iter().map(|s| Value::text(s)).collect()),
            ),
            (
                5,
                Value::Array(self.addresses.iter().map(|s| Value::text(s)).collect()),
            ),
            (6, Value::text(&self.operator)),
            (7, Value::Uint(self.not_before)),
            (8, Value::Uint(self.not_after)),
        ])
        .encode()
    }

    /// Parses a body, refusing unknown fields, unknown versions and oversized lists.
    pub fn from_body(body: &[u8]) -> Result<Descriptor> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown descriptor version"));
        }
        let operator = f.text(6)?;
        if operator.len() > MAX_OPERATOR_LEN {
            return Err(FedError::Malformed("the operator name is too long"));
        }
        Ok(Descriptor {
            server: server_id(f.fixed::<16>(1)?),
            identity_key: sig1::PublicKey::from_bytes(f.bytes(2)?)
                .map_err(|_| FedError::Malformed("the identity key has the wrong length"))?,
            kem_key: kx1::PublicKey::from_bytes(f.bytes(3)?)
                .map_err(|_| FedError::Malformed("the KEM key has the wrong length"))?,
            suites: f.texts(4, MAX_SUITES, MAX_SUITE_LEN)?,
            addresses: f.texts(5, MAX_ADDRESSES, MAX_ADDRESS_LEN)?,
            operator: operator.to_owned(),
            not_before: f.uint(7)?,
            not_after: f.uint(8)?,
        })
    }

    /// The suites in this descriptor that this build knows, in the descriptor's order.
    pub fn known_suites(&self) -> Vec<Suite> {
        self.suites
            .iter()
            .filter_map(|n| Suite::from_name(n))
            .collect()
    }

    /// The suite a connecting server `ours` would use with this descriptor's server.
    pub fn negotiate(&self, ours: &[Suite]) -> Result<Suite> {
        suite::negotiate(&self.suites, ours)
    }
}

/// A descriptor and its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDescriptor {
    pub descriptor: Descriptor,
    pub envelope: Signed,
}

impl SignedDescriptor {
    /// Signs `descriptor` with the server's identity key.
    pub fn sign(descriptor: Descriptor, key: &sig1::SigningKey) -> Result<SignedDescriptor> {
        let envelope = Signed::sign(key, CONTEXT, descriptor.to_body())?;
        Ok(SignedDescriptor {
            descriptor,
            envelope,
        })
    }

    /// The bytes served at `/fed/v1/descriptor`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.envelope.encode()
    }

    /// Parses the served bytes. The signature isn't checked: call [`verify`](Self::verify).
    pub fn parse(bytes: &[u8]) -> Result<SignedDescriptor> {
        let envelope = Signed::decode(bytes)?;
        let descriptor = Descriptor::from_body(&envelope.body)?;
        Ok(SignedDescriptor {
            descriptor,
            envelope,
        })
    }

    /// Checks the descriptor at `now` (unix seconds): the validity window, the signature under
    /// the descriptor's own identity key, and, when `pinned` is given, that this identity key is
    /// the pinned one. A different key is [`FedError::KeyMismatch`], carrying what was offered.
    pub fn verify(&self, now: u64, pinned: Option<&sig1::PublicKey>) -> Result<()> {
        let d = &self.descriptor;
        if let Some(pinned) = pinned
            && pinned != &d.identity_key
        {
            return Err(FedError::KeyMismatch {
                offered: d.identity_key.as_bytes().to_vec(),
            });
        }
        if self.envelope.body != d.to_body() {
            return Err(FedError::Invalid("the descriptor body is not canonical"));
        }
        self.envelope.verify(&d.identity_key, CONTEXT)?;
        check_window(d.not_before, d.not_after, now)
    }
}

/// The validity window rules: at most 37 days long, not yet valid up to 5 minutes early, never
/// valid after `not_after`.
pub fn check_window(not_before: u64, not_after: u64, now: u64) -> Result<()> {
    if not_after < not_before {
        return Err(FedError::Malformed(
            "the validity window ends before it starts",
        ));
    }
    if not_after - not_before > VALIDITY_SECS {
        return Err(FedError::Invalid(
            "the validity window is longer than 37 days",
        ));
    }
    if now.saturating_add(SKEW_SECS) < not_before {
        return Err(FedError::Expired("the descriptor is not valid yet"));
    }
    if now > not_after {
        return Err(FedError::Expired("the descriptor has expired"));
    }
    Ok(())
}

/// Whether the KEM key is due for rotation at `now`.
pub fn kem_rotation_due(descriptor: &Descriptor, now: u64) -> bool {
    now >= descriptor.not_before.saturating_add(KEM_ROTATION_SECS)
}

/// The suite list a server with these suites publishes.
pub fn suite_names(suites: &[Suite]) -> Vec<String> {
    suite::names(suites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(now: u64) -> (Descriptor, sig1::SigningKey) {
        let signing = sig1::SigningKey::from_bytes(&[1; 64]);
        let (_, kem_key) = crypto::kem_generate().expect("kem key");
        let d = Descriptor {
            server: ServerId::random(),
            identity_key: crypto::sign_public(&signing).expect("identity key"),
            kem_key,
            suites: suite_names(&Suite::IMPLEMENTED),
            addresses: vec!["https://a.example.org".to_owned()],
            operator: "Example".to_owned(),
            not_before: now,
            not_after: now + VALIDITY_SECS,
        };
        (d, signing)
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_descriptor_signs_serves_parses_and_verifies() {
        let (d, key) = sample(NOW);
        let signed = SignedDescriptor::sign(d.clone(), &key).expect("sign");
        let parsed = SignedDescriptor::parse(&signed.to_bytes()).expect("parse");
        assert_eq!(parsed, signed);
        assert_eq!(parsed.descriptor, d);
        parsed.verify(NOW + 10, None).expect("verify");
        parsed
            .verify(NOW + 10, Some(&d.identity_key))
            .expect("verify against the pin");
    }

    #[test]
    fn a_pinned_key_that_differs_is_a_mismatch_with_the_offered_key() {
        let (d, key) = sample(NOW);
        let signed = SignedDescriptor::sign(d.clone(), &key).expect("sign");
        let other = crypto::sign_public(&sig1::SigningKey::from_bytes(&[2; 64])).expect("key");
        assert_eq!(
            signed.verify(NOW, Some(&other)),
            Err(FedError::KeyMismatch {
                offered: d.identity_key.as_bytes().to_vec()
            })
        );
    }

    #[test]
    fn the_window_is_enforced() {
        let (d, key) = sample(NOW);
        let signed = SignedDescriptor::sign(d, &key).expect("sign");
        assert!(signed.verify(NOW - SKEW_SECS, None).is_ok());
        assert!(signed.verify(NOW - SKEW_SECS - 1, None).is_err());
        assert!(signed.verify(NOW + VALIDITY_SECS, None).is_ok());
        assert!(signed.verify(NOW + VALIDITY_SECS + 1, None).is_err());
    }

    #[test]
    fn a_window_longer_than_37_days_is_refused() {
        let (mut d, key) = sample(NOW);
        d.not_after = d.not_before + VALIDITY_SECS + 1;
        let signed = SignedDescriptor::sign(d, &key).expect("sign");
        assert!(signed.verify(NOW, None).is_err());
    }

    #[test]
    fn a_signature_by_another_key_or_over_another_body_fails() {
        let (d, key) = sample(NOW);
        let other = sig1::SigningKey::from_bytes(&[3; 64]);
        let forged = SignedDescriptor::sign(d.clone(), &other).expect("sign");
        assert!(forged.verify(NOW, None).is_err());

        let mut signed = SignedDescriptor::sign(d, &key).expect("sign");
        signed.descriptor.operator = "Someone else".to_owned();
        assert!(signed.verify(NOW, None).is_err());
    }

    #[test]
    fn malformed_bodies_are_refused() {
        let (d, key) = sample(NOW);
        let body = d.to_body();
        // Unknown fields are errors.
        let mut value = Value::decode(&body).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((9, Value::Uint(1)));
        }
        assert!(Descriptor::from_body(&value.encode()).is_err());
        // An unknown version is an error.
        let mut value = Value::decode(&body).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries[0].1 = Value::Uint(2);
        }
        assert!(Descriptor::from_body(&value.encode()).is_err());
        // Short keys are errors.
        let short = Value::map(vec![
            (0, Value::Uint(1)),
            (1, Value::bytes(&[0; 16])),
            (2, Value::bytes(&[0; 10])),
        ]);
        assert!(Descriptor::from_body(&short.encode()).is_err());
        let _ = key;
    }

    #[test]
    fn unknown_suites_survive_and_the_rest_negotiates() {
        let (mut d, key) = sample(NOW);
        d.suites.insert(0, "kfed9-future".to_owned());
        let signed = SignedDescriptor::sign(d.clone(), &key).expect("sign");
        let parsed = SignedDescriptor::parse(&signed.to_bytes()).expect("parse");
        assert_eq!(parsed.descriptor.suites[0], "kfed9-future");
        assert_eq!(parsed.descriptor.known_suites().len(), 2);
        assert_eq!(
            parsed.descriptor.negotiate(&Suite::IMPLEMENTED),
            Ok(Suite::Aes256Gcm)
        );
    }

    #[test]
    fn rotation_falls_due_after_30_days() {
        let (d, _) = sample(NOW);
        assert!(!kem_rotation_due(&d, NOW + KEM_ROTATION_SECS - 1));
        assert!(kem_rotation_due(&d, NOW + KEM_ROTATION_SECS));
    }

    #[test]
    fn the_kem_key_id_depends_on_the_key() {
        let (a, _) = sample(NOW);
        let (b, _) = sample(NOW);
        assert_eq!(kem_key_id(&a.kem_key), kem_key_id(&a.kem_key));
        assert_ne!(kem_key_id(&a.kem_key), kem_key_id(&b.kem_key));
    }
}
