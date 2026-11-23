//! `sig1`, the hybrid signing key: ML-DSA-65 + Ed25519, both must verify.
//!
//! - Public key: `ML-DSA-65 public key (1952) ‖ Ed25519 public key (32)`, 1984 bytes.
//! - Private key: `ML-DSA-65 seed ξ (32) ‖ Ed25519 seed (32)`, 64 bytes.
//! - The signed message is `m' = "kemlock/v1/sig1" ‖ lp(context) ‖ lp(message)`.
//! - Signature: `ML-DSA-65.Sign(sk_m, m', ctx = empty) (3309) ‖ Ed25519.Sign(sk_e, m') (64)`,
//!   3373 bytes.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error,
    backend::{Active, Backend, MLDSA_PUBLIC_LEN, MLDSA_SEED_LEN, MLDSA_SIGNATURE_LEN},
    rand,
    wire::{array, array_ref, lp},
};

const LABEL: &[u8] = b"kemlock/v1/sig1";
const ED25519_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

/// The length of a public key.
pub const PUBLIC_KEY_LEN: usize = MLDSA_PUBLIC_LEN + ED25519_LEN;
/// The length of a private key.
pub const PRIVATE_KEY_LEN: usize = MLDSA_SEED_LEN + ED25519_LEN;
/// The length of a signature.
pub const SIGNATURE_LEN: usize = MLDSA_SIGNATURE_LEN + ED25519_SIGNATURE_LEN;

/// Contexts in use.
pub mod context {
    /// A key bundle, signed by its own account.
    pub const BUNDLE: &str = "bundle";
    /// A signed manifest.
    pub const MANIFEST: &str = "manifest";
    /// A member confirmation, signed by the confirmer.
    pub const CONFIRM: &str = "confirm";
    /// A record of a space chain, signed by the member who made it.
    pub const SPACE_CHAIN: &str = "space-chain";
}

/// A `sig1` public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_LEN]>);

impl PublicKey {
    /// Takes the 1984 bytes of a public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        Ok(PublicKey(Box::new(array(bytes)?)))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Passes only when both the ML-DSA and the Ed25519 signature verify over the same message.
    pub fn verify(&self, context: &str, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_in::<Active>(self, context, message, signature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("sig1::PublicKey").finish_non_exhaustive()
    }
}

/// A `sig1` private key. Wiped on drop; `Debug` shows no contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey([u8; PRIVATE_KEY_LEN]);

impl SigningKey {
    /// A fresh random key.
    pub fn generate() -> SigningKey {
        SigningKey(rand::bytes())
    }

    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_LEN]) -> SigningKey {
        SigningKey(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.0
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        public_key_in::<Active>(self)
    }

    /// Signs `message` under `context`: 3373 bytes.
    pub fn sign(&self, context: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        sign_in::<Active>(self, context, message)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("sig1::SigningKey").finish_non_exhaustive()
    }
}

/// `"kemlock/v1/sig1" ‖ lp(context) ‖ lp(message)`, what both algorithms sign.
fn signed_message(context: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(LABEL.len() + 8 + context.len() + message.len());
    out.extend_from_slice(LABEL);
    lp(&mut out, context.as_bytes())?;
    lp(&mut out, message)?;
    Ok(out)
}

pub(crate) fn public_key_in<B: Backend>(key: &SigningKey) -> Result<PublicKey, Error> {
    let seed_m: &[u8; MLDSA_SEED_LEN] = array_ref(&key.0[..MLDSA_SEED_LEN])?;
    let seed_e: &[u8; ED25519_LEN] = array_ref(&key.0[MLDSA_SEED_LEN..])?;
    let public_m = B::mldsa65_public(seed_m)?;
    if public_m.len() != MLDSA_PUBLIC_LEN {
        return Err(Error::invalid());
    }
    let public_e = B::ed25519_public(seed_e)?;
    let mut out = Box::new([0u8; PUBLIC_KEY_LEN]);
    out[..MLDSA_PUBLIC_LEN].copy_from_slice(&public_m);
    out[MLDSA_PUBLIC_LEN..].copy_from_slice(&public_e);
    Ok(PublicKey(out))
}

pub(crate) fn sign_in<B: Backend>(
    key: &SigningKey,
    context: &str,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let seed_m: &[u8; MLDSA_SEED_LEN] = array_ref(&key.0[..MLDSA_SEED_LEN])?;
    let seed_e: &[u8; ED25519_LEN] = array_ref(&key.0[MLDSA_SEED_LEN..])?;
    let signed = Zeroizing::new(signed_message(context, message)?);
    let sig_m = B::mldsa65_sign(seed_m, &signed)?;
    if sig_m.len() != MLDSA_SIGNATURE_LEN {
        return Err(Error::invalid());
    }
    let sig_e = B::ed25519_sign(seed_e, &signed)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN);
    out.extend_from_slice(&sig_m);
    out.extend_from_slice(&sig_e);
    Ok(out)
}

pub(crate) fn verify_in<B: Backend>(
    public: &PublicKey,
    context: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let signature: &[u8; SIGNATURE_LEN] = array_ref(signature)?;
    let public_m = &public.0[..MLDSA_PUBLIC_LEN];
    let public_e: &[u8; ED25519_LEN] = array_ref(&public.0[MLDSA_PUBLIC_LEN..])?;
    let signed = signed_message(context, message)?;
    // Both are checked whichever fails first, so the time doesn't say which half was wrong.
    let m = B::mldsa65_verify(public_m, &signed, &signature[..MLDSA_SIGNATURE_LEN]);
    let e = B::ed25519_verify(public_e, &signed, &signature[MLDSA_SIGNATURE_LEN..]);
    if m.is_ok() && e.is_ok() {
        Ok(())
    } else {
        Err(Error::invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_the_doc() {
        assert_eq!(PUBLIC_KEY_LEN, 1984);
        assert_eq!(PRIVATE_KEY_LEN, 64);
        assert_eq!(SIGNATURE_LEN, 3373);
    }

    #[test]
    fn signed_message_layout() {
        let m = signed_message("ctx", b"msg").expect("short");
        let mut expected = b"kemlock/v1/sig1".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"ctx");
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"msg");
        assert_eq!(m, expected);
    }

    #[test]
    fn debug_shows_no_contents() {
        assert!(!format!("{:?}", SigningKey::from_bytes(&[0xEE; 64])).contains("238"));
    }

    #[test]
    fn signing_and_verifying_round_trip() {
        for_backends!(B => {
            let key = SigningKey::from_bytes(&[11; 64]);
            let public = public_key_in::<B>(&key).expect("public key");
            let sig = sign_in::<B>(&key, "bundle", b"hello").expect("sign");
            assert_eq!(sig.len(), SIGNATURE_LEN, "{}", B::NAME);
            verify_in::<B>(&public, "bundle", b"hello", &sig).expect("verify");
        });
    }

    #[test]
    fn wrong_context_message_key_or_length_fails() {
        for_backends!(B => {
            let key = SigningKey::from_bytes(&[11; 64]);
            let public = public_key_in::<B>(&key).expect("public key");
            let other = public_key_in::<B>(&SigningKey::from_bytes(&[12; 64])).expect("public key");
            let sig = sign_in::<B>(&key, "bundle", b"hello").expect("sign");
            assert!(verify_in::<B>(&public, "manifest", b"hello", &sig).is_err());
            assert!(verify_in::<B>(&public, "bundle", b"hellp", &sig).is_err());
            assert!(verify_in::<B>(&other, "bundle", b"hello", &sig).is_err());
            assert!(verify_in::<B>(&public, "bundle", b"hello", &sig[..SIGNATURE_LEN - 1]).is_err());
            let mut long = sig.clone();
            long.push(0);
            assert!(verify_in::<B>(&public, "bundle", b"hello", &long).is_err());
        });
    }

    #[test]
    fn both_halves_must_verify() {
        for_backends!(B => {
            let key = SigningKey::from_bytes(&[11; 64]);
            let public = public_key_in::<B>(&key).expect("public key");
            let sig = sign_in::<B>(&key, "bundle", b"hello").expect("sign");
            let other = sign_in::<B>(&SigningKey::from_bytes(&[12; 64]), "bundle", b"hello").expect("sign");

            // Another key's ML-DSA half with the right Ed25519 half, and the other way round.
            let mut mldsa_swapped = sig.clone();
            mldsa_swapped[..MLDSA_SIGNATURE_LEN].copy_from_slice(&other[..MLDSA_SIGNATURE_LEN]);
            assert!(verify_in::<B>(&public, "bundle", b"hello", &mldsa_swapped).is_err());
            let mut ed_swapped = sig.clone();
            ed_swapped[MLDSA_SIGNATURE_LEN..].copy_from_slice(&other[MLDSA_SIGNATURE_LEN..]);
            assert!(verify_in::<B>(&public, "bundle", b"hello", &ed_swapped).is_err());

            // A public key with only one half replaced.
            let other_public = public_key_in::<B>(&SigningKey::from_bytes(&[12; 64])).expect("public key");
            let mut mixed = *public.as_bytes();
            mixed[..MLDSA_PUBLIC_LEN].copy_from_slice(&other_public.as_bytes()[..MLDSA_PUBLIC_LEN]);
            let mixed = PublicKey::from_bytes(&mixed).expect("length");
            assert!(verify_in::<B>(&mixed, "bundle", b"hello", &sig).is_err());
        });
    }

    #[test]
    fn tampering_with_any_region_fails() {
        for_backends!(B => {
            let key = SigningKey::from_bytes(&[11; 64]);
            let public = public_key_in::<B>(&key).expect("public key");
            let sig = sign_in::<B>(&key, "bundle", b"hello").expect("sign");
            for i in [0usize, 1, 1000, 3308, 3309, 3340, 3372] {
                let mut bad = sig.clone();
                bad[i] ^= 1;
                assert!(verify_in::<B>(&public, "bundle", b"hello", &bad).is_err(), "{} byte {i}", B::NAME);
            }
        });
    }

    #[test]
    fn the_same_seed_gives_the_same_public_key_on_every_backend() {
        for_backends!(B => {
            let a = public_key_in::<B>(&SigningKey::from_bytes(&[21; 64])).expect("public key");
            let b = public_key_in::<Active>(&SigningKey::from_bytes(&[21; 64])).expect("public key");
            assert_eq!(a, b, "{}", B::NAME);
        });
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn each_backend_verifies_the_others_signatures() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let key = SigningKey::from_bytes(&[33; 64]);
        let aws_public = public_key_in::<AwsLc>(&key).expect("public key");
        let rc_public = public_key_in::<RustCrypto>(&key).expect("public key");
        assert_eq!(aws_public, rc_public);
        let by_aws = sign_in::<AwsLc>(&key, "manifest", b"data").expect("sign");
        let by_rc = sign_in::<RustCrypto>(&key, "manifest", b"data").expect("sign");
        verify_in::<RustCrypto>(&rc_public, "manifest", b"data", &by_aws)
            .expect("rustcrypto verifies aws-lc");
        verify_in::<AwsLc>(&aws_public, "manifest", b"data", &by_rc)
            .expect("aws-lc verifies rustcrypto");
    }
}
