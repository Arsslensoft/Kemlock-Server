//! P-256 ECDSA for DPoP proofs from phones' hardware keys (ES256). The server only verifies; the
//! signing key is for tests and tools.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error,
    backend::{Active, Backend},
    rand,
};

/// A P-256 signing key, for tests and tools. The scalar is wiped on drop; `Debug` shows none.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    secret: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 65],
}

impl SigningKey {
    /// A fresh random key.
    ///
    /// # Panics
    ///
    /// If the random source fails, or fifty random scalars in a row are out of range.
    pub fn generate() -> SigningKey {
        for _ in 0..50 {
            let secret: [u8; 32] = rand::bytes();
            // A random 256-bit value is a valid scalar unless it is zero or at least the group
            // order, which is about one in 2^32.
            if let Ok(public) = Active::p256_public(&secret) {
                return SigningKey { secret, public };
            }
        }
        panic!("no valid P-256 scalar after fifty tries");
    }

    /// The public point's coordinates `(x, y)`, 32 bytes each.
    pub fn public_xy(&self) -> ([u8; 32], [u8; 32]) {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&self.public[1..33]);
        y.copy_from_slice(&self.public[33..65]);
        (x, y)
    }

    /// ECDSA-SHA-256 of `msg` as `r ‖ s`, the form JWS ES256 wants.
    ///
    /// # Panics
    ///
    /// Never for a key made by [`SigningKey::generate`].
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        match Active::p256_sign(&self.secret, msg) {
            Ok(sig) => sig,
            Err(_) => panic!("P-256 signing failed under a valid key"),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("p256::SigningKey").finish_non_exhaustive()
    }
}

/// Verifies an ES256 signature (`r ‖ s`, 64 bytes) of `msg` by the public point `(x, y)`.
pub fn verify_es256(x: &[u8; 32], y: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..].copy_from_slice(y);
    Active::p256_verify(&point, msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6979 appendix A.2.5: P-256 with SHA-256, message "sample".
    const RFC6979_KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const RFC6979_SIG: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                               f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

    #[test]
    fn rfc6979_signature_verifies_on_every_backend() {
        for_backends!(B => {
            let secret: [u8; 32] = hex::decode(RFC6979_KEY).expect("hex").try_into().expect("32 bytes");
            let public = B::p256_public(&secret).expect("public");
            assert_eq!(public[0], 4);
            let sig = hex::decode(RFC6979_SIG).expect("hex");
            B::p256_verify(&public, b"sample", &sig).expect("the RFC's signature verifies");
            assert!(B::p256_verify(&public, b"sampl3", &sig).is_err(), "{}", B::NAME);
        });
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::generate();
        let (x, y) = key.public_xy();
        let sig = key.sign(b"dpop proof");
        assert_eq!(sig.len(), 64);
        verify_es256(&x, &y, b"dpop proof", &sig).expect("verify");
    }

    #[test]
    fn wrong_message_key_or_length_fails() {
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let (x, y) = key.public_xy();
        let (ox, oy) = other.public_xy();
        let sig = key.sign(b"msg");
        assert!(verify_es256(&x, &y, b"msh", &sig).is_err());
        assert!(verify_es256(&ox, &oy, b"msg", &sig).is_err());
        assert!(verify_es256(&x, &y, b"msg", &sig[..63]).is_err());
        assert!(verify_es256(&x, &y, b"msg", &[]).is_err());
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(verify_es256(&x, &y, b"msg", &bad).is_err());
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        let key = SigningKey::generate();
        let (x, mut y) = key.public_xy();
        let sig = key.sign(b"msg");
        y[31] ^= 1;
        assert!(verify_es256(&x, &y, b"msg", &sig).is_err());
        assert!(verify_es256(&[0; 32], &[0; 32], b"msg", &sig).is_err());
    }

    #[test]
    fn distinct_keys_each_time() {
        assert_ne!(
            SigningKey::generate().public_xy(),
            SigningKey::generate().public_xy()
        );
    }

    #[test]
    fn debug_shows_no_contents() {
        assert!(!format!("{:?}", SigningKey::generate()).contains("secret"));
    }

    #[cfg(feature = "aws-lc")]
    #[test]
    fn each_backend_verifies_the_others_signatures() {
        use crate::backend::{aws_lc::AwsLc, rustcrypto::RustCrypto};
        let secret = [0x42u8; 32];
        let public = AwsLc::p256_public(&secret).expect("public");
        assert_eq!(public, RustCrypto::p256_public(&secret).expect("public"));
        let by_aws = AwsLc::p256_sign(&secret, b"m").expect("sign");
        let by_rc = RustCrypto::p256_sign(&secret, b"m").expect("sign");
        RustCrypto::p256_verify(&public, b"m", &by_aws).expect("rustcrypto verifies aws-lc");
        AwsLc::p256_verify(&public, b"m", &by_rc).expect("aws-lc verifies rustcrypto");
    }
}
