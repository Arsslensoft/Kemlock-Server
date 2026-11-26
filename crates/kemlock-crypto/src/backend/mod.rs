//! The primitives every format is built from, behind one trait with two implementations.
//!
//! Formats are written once, generic over [`Backend`]; the public functions use [`Active`] and the
//! cross-check tests run the same code on both backends. Under test both backends are always
//! built (the RustCrypto one from the dev-dependencies), whichever features are on.
//!
//! Two modules hold what a backend can't do for itself, so that the exceptions are in one place:
//! `mlkem_seed` (ML-KEM from a 64-byte seed, aws-lc-rs has no way to) and `mldsa_soft` (ML-DSA
//! in a FIPS build, where aws-lc-rs has none). Both are RustCrypto code, both are named where
//! they are used, and nothing else crosses from the native backend into RustCrypto.

use crate::Error;

#[cfg(feature = "aws-lc")]
pub(crate) mod aws_lc;
pub(crate) mod ed25519_rule;
#[cfg(any(test, feature = "rustcrypto", feature = "fips"))]
pub(crate) mod mldsa_soft;
#[cfg(any(test, feature = "aws-lc", feature = "rustcrypto"))]
pub(crate) mod mlkem_seed;
#[cfg(any(test, feature = "rustcrypto"))]
pub(crate) mod rustcrypto;

/// The backend the public functions use: aws-lc-rs when it is compiled in, else RustCrypto.
#[cfg(feature = "aws-lc")]
pub(crate) type Active = aws_lc::AwsLc;
#[cfg(all(feature = "rustcrypto", not(feature = "aws-lc")))]
pub(crate) type Active = rustcrypto::RustCrypto;

pub(crate) const MLKEM_SEED_LEN: usize = 64;
pub(crate) const MLKEM_PUBLIC_LEN: usize = 1568;
pub(crate) const MLKEM_CIPHERTEXT_LEN: usize = 1568;
pub(crate) const MLDSA_SEED_LEN: usize = 32;
pub(crate) const MLDSA_PUBLIC_LEN: usize = 1952;
pub(crate) const MLDSA_SIGNATURE_LEN: usize = 3309;

// Not every primitive is used by a format yet (HKDF-SHA512 is here for OPAQUE's parameter set,
// which opaque-ke runs itself), and a backend that isn't `Active` is only built for the tests.
#[allow(dead_code)]
pub(crate) trait Backend {
    /// A short name for test failure messages.
    const NAME: &'static str;

    /// Fills `buf` from the operating system's random source. Callers go through
    /// `crate::rand::try_fill`, which lets the test-vector generator substitute a seeded stream.
    fn random(buf: &mut [u8]) -> Result<(), Error>;

    fn sha256(data: &[u8]) -> [u8; 32];
    fn sha512(data: &[u8]) -> [u8; 64];
    fn sha3_256(data: &[u8]) -> [u8; 32];
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32];
    fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20];

    /// HKDF-SHA256 (RFC 5869). An absent salt is the hash length of zero bytes.
    fn hkdf_sha256(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error>;
    fn hkdf_sha512(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error>;

    /// AES-256-GCM with a caller-chosen 12-byte nonce; returns `ciphertext ‖ tag(16)`.
    fn aes256gcm_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error>;
    /// Takes `ciphertext ‖ tag(16)`; returns the plaintext.
    fn aes256gcm_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// `X25519(secret, 9)`.
    fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32], Error>;
    /// `X25519(secret, peer)`; an all-zero result is an error.
    fn x25519(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error>;

    /// The ML-KEM-1024 encapsulation key of `ML-KEM.KeyGen_internal(d, z)` for the seed `d ‖ z`.
    fn mlkem1024_public(seed: &[u8; MLKEM_SEED_LEN]) -> Result<Vec<u8>, Error>;
    /// Encapsulates to an encapsulation key with fresh randomness; returns `(ciphertext, secret)`.
    fn mlkem1024_encaps(public: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Error>;
    /// Decapsulates with the key expanded from the seed; implicit rejection applies.
    fn mlkem1024_decaps(seed: &[u8; MLKEM_SEED_LEN], ciphertext: &[u8]) -> Result<[u8; 32], Error>;

    fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32], Error>;
    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error>;
    fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), Error>;

    /// The ML-DSA-65 public key for the 32-byte seed ξ.
    fn mldsa65_public(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Vec<u8>, Error>;
    /// Pure ML-DSA-65 with an empty context. Hedged or deterministic, whichever the backend does.
    fn mldsa65_sign(seed: &[u8; MLDSA_SEED_LEN], msg: &[u8]) -> Result<Vec<u8>, Error>;
    fn mldsa65_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error>;

    /// The uncompressed SEC1 point (`04 ‖ x ‖ y`) of a P-256 secret scalar.
    fn p256_public(secret: &[u8; 32]) -> Result<[u8; 65], Error>;
    /// ECDSA-P256-SHA256, fixed `r ‖ s`.
    fn p256_sign(secret: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error>;
    fn p256_verify(public: &[u8; 65], msg: &[u8], sig: &[u8]) -> Result<(), Error>;
}

#[cfg(test)]
mod tests;
