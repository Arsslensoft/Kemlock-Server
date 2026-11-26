//! Ed25519 for the server's access tokens (EdDSA JWS).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error,
    backend::{Active, Backend},
    rand,
};

/// An Ed25519 signing key. The seed is wiped on drop; `Debug` shows none.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    seed: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
}

impl SigningKey {
    /// A fresh random key.
    pub fn generate() -> SigningKey {
        SigningKey::from_seed(&rand::bytes())
    }

    /// The key of a 32-byte seed (RFC 8032).
    ///
    /// # Panics
    ///
    /// Never in practice: a 32-byte seed always gives a key on both backends.
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        let public = match Active::ed25519_public(seed) {
            Ok(public) => public,
            Err(_) => panic!("Ed25519 key derivation failed for a 32-byte seed"),
        };
        SigningKey {
            seed: *seed,
            public,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The 64-byte signature of `msg`.
    ///
    /// # Panics
    ///
    /// Never for a key made by this crate; the backends sign any message under a 32-byte seed.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        match Active::ed25519_sign(&self.seed, msg) {
            Ok(sig) => sig,
            Err(_) => panic!("Ed25519 signing failed under a 32-byte seed"),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ed25519::SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Refuses an Ed25519 public key that is not a canonical encoding or that has small order (the key
/// half of the verification rule in docs/crypto.md, "Ed25519 verification rule").
///
/// It is a check of bytes: a 32-byte value that passes may still not be a point on the curve, which
/// verification finds out (no signature verifies under it). Run it on every key that comes from
/// outside, before it is stored or used; `sig1::PublicKey::from_bytes` does.
pub fn check_public_key(public_key: &[u8; 32]) -> Result<(), Error> {
    crate::backend::ed25519_rule::check_point(public_key)
}

/// Verifies an Ed25519 signature under the one rule of docs/crypto.md, "Ed25519 verification rule",
/// the same on every backend: the key and the signature's `R` must be canonical points that do not
/// have small order, `S` must be below the group order, and the equation must hold exactly.
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    Active::ed25519_verify(public_key, msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 section 7.1, test 1 (empty message).
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    fn seed() -> [u8; 32] {
        hex::decode(SEED)
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn rfc8032_test_1() {
        let key = SigningKey::from_seed(&seed());
        assert_eq!(hex::encode(key.public_key()), PUBLIC);
        assert_eq!(hex::encode(key.sign(b"")), SIG);
        assert_eq!(key.seed(), seed());
        let public: [u8; 32] = hex::decode(PUBLIC)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        verify(&public, b"", &hex::decode(SIG).expect("hex")).expect("verify");
    }

    #[test]
    fn rfc8032_test_1_on_every_backend() {
        for_backends!(B => {
            assert_eq!(hex::encode(B::ed25519_public(&seed()).expect("public")), PUBLIC, "{}", B::NAME);
            assert_eq!(hex::encode(B::ed25519_sign(&seed(), b"").expect("sign")), SIG, "{}", B::NAME);
        });
    }

    #[test]
    fn generated_keys_sign_and_verify() {
        let key = SigningKey::generate();
        let sig = key.sign(b"header.payload");
        verify(&key.public_key(), b"header.payload", &sig).expect("verify");
        assert_ne!(SigningKey::generate().seed(), key.seed());
    }

    #[test]
    fn wrong_message_key_or_length_fails() {
        let key = SigningKey::from_seed(&[1; 32]);
        let other = SigningKey::from_seed(&[2; 32]);
        let sig = key.sign(b"msg");
        assert!(verify(&key.public_key(), b"msh", &sig).is_err());
        assert!(verify(&other.public_key(), b"msg", &sig).is_err());
        assert!(verify(&key.public_key(), b"msg", &sig[..63]).is_err());
        assert!(verify(&key.public_key(), b"msg", &[]).is_err());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify(&key.public_key(), b"msg", &bad).is_err());
    }

    /// The identity point: with it as the key, R = identity and S = 0 verify on any message
    /// unless the key is refused.
    const IDENTITY: [u8; 32] = {
        let mut point = [0u8; 32];
        point[0] = 1;
        point
    };

    #[test]
    fn a_small_order_key_never_verifies_on_any_backend() {
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);
        for_backends!(B => {
            assert!(B::ed25519_verify(&IDENTITY, b"anything", &forged).is_err(), "{}", B::NAME);
            assert!(B::ed25519_verify(&IDENTITY, b"", &forged).is_err(), "{}", B::NAME);
        });
        assert!(verify(&IDENTITY, b"anything", &forged).is_err());
        assert!(check_public_key(&IDENTITY).is_err());
        // The same key written as y = p + 1 is not canonical.
        let mut non_canonical = [0xff; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert!(check_public_key(&non_canonical).is_err());
        assert!(check_public_key(&SigningKey::from_seed(&[1; 32]).public_key()).is_ok());
    }

    #[test]
    fn debug_hides_the_seed() {
        let text = format!("{:?}", SigningKey::from_seed(&[0xEE; 32]));
        assert!(text.contains("public"));
        assert!(!text.contains("seed"));
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn each_backend_verifies_the_others_signatures() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let seed = [3; 32];
        let public = AwsLc::ed25519_public(&seed).expect("public");
        assert_eq!(public, RustCrypto::ed25519_public(&seed).expect("public"));
        let by_aws = AwsLc::ed25519_sign(&seed, b"m").expect("sign");
        let by_rc = RustCrypto::ed25519_sign(&seed, b"m").expect("sign");
        assert_eq!(by_aws, by_rc, "Ed25519 is deterministic");
        RustCrypto::ed25519_verify(&public, b"m", &by_aws).expect("verify");
        AwsLc::ed25519_verify(&public, b"m", &by_rc).expect("verify");
    }
}
