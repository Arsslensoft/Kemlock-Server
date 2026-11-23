//! The pure-Rust backend by name, for the test-vector generators (feature `vectors`).
//!
//! The public functions run on aws-lc, whose ML-KEM encapsulation and ML-DSA signing draw their own
//! randomness, so a generator that must write the same bytes every run (`kemlock-fed-vectors`)
//! calls these instead: on the RustCrypto backend every random byte comes from the seeded stream
//! and ML-DSA signing is deterministic. Nothing in a server build uses this module, and it exists
//! only with `vectors`, which turns the RustCrypto backend on and so can't be built with `fips`.
//! Output is byte for byte what the public functions give on a RustCrypto-only build.

use crate::{
    Error,
    backend::rustcrypto::RustCrypto,
    kx1::{self, Ciphertext, PrivateKey, PublicKey, SharedSecret},
    sig1,
};

/// `kx1` on the RustCrypto backend.
pub mod exchange {
    use super::*;

    /// A fresh `kx1` key pair.
    pub fn generate() -> Result<(PrivateKey, PublicKey), Error> {
        kx1::generate_in::<RustCrypto>()
    }

    /// The public key of a private key.
    pub fn public_key(private: &PrivateKey) -> Result<PublicKey, Error> {
        kx1::public_key_in::<RustCrypto>(private)
    }

    /// Encapsulates to `public`: a ciphertext for its holder and the shared secret.
    pub fn encapsulate(public: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
        kx1::encapsulate_in::<RustCrypto>(public)
    }

    /// Recovers the shared secret from a ciphertext.
    pub fn decapsulate(private: &PrivateKey, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
        kx1::decapsulate_in::<RustCrypto>(private, ciphertext)
    }
}

/// `sig1` on the RustCrypto backend.
pub mod signing {
    use super::*;

    /// The public key of a signing key.
    pub fn public_key(key: &sig1::SigningKey) -> Result<sig1::PublicKey, Error> {
        sig1::public_key_in::<RustCrypto>(key)
    }

    /// Signs `message` under `context`, deterministically.
    pub fn sign(key: &sig1::SigningKey, context: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        sig1::sign_in::<RustCrypto>(key, context, message)
    }

    /// Verifies a signature.
    pub fn verify(
        public: &sig1::PublicKey,
        context: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        sig1::verify_in::<RustCrypto>(public, context, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_round_trips() {
        let (private, public) = exchange::generate().expect("generate");
        assert_eq!(exchange::public_key(&private).expect("public"), public);
        let (ct, sent) = exchange::encapsulate(&public).expect("encaps");
        let got = exchange::decapsulate(&private, &ct).expect("decaps");
        assert_eq!(sent.as_bytes(), got.as_bytes());
    }

    #[test]
    fn signing_round_trips_and_is_deterministic() {
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let public = signing::public_key(&key).expect("public");
        let a = signing::sign(&key, "ctx", b"msg").expect("sign");
        let b = signing::sign(&key, "ctx", b"msg").expect("sign");
        assert_eq!(a, b);
        signing::verify(&public, "ctx", b"msg", &a).expect("verify");
        assert!(signing::verify(&public, "other", b"msg", &a).is_err());
    }
}
