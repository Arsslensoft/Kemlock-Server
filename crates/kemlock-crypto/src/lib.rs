//! ML-KEM-1024 + X25519, ML-DSA-65 + Ed25519, AES-256-GCM, Argon2id, HKDF and OPAQUE, on aws-lc-rs
//! natively and RustCrypto in WebAssembly.
//!
//! The byte formats are fixed by `docs/crypto.md`; `test-vectors/` pins each one.
//!
//! # Backends
//!
//! Every primitive sits behind one internal trait with two implementations: aws-lc-rs (feature
//! `aws-lc`, the default) and RustCrypto (feature `rustcrypto`, for WebAssembly and for the
//! test-vector generator). When both features are on, aws-lc-rs serves the public functions. Under
//! `cargo test` both backends are always built, and the cross-backend tests run in every build.
//!
//! The aws-lc backend hands exactly two things to RustCrypto, each named at its call site:
//!
//! - **ML-KEM-1024 from a 64-byte seed** (deriving the encapsulation key, and decapsulating). The
//!   `kx1` private key is that seed (`docs/crypto.md`), and aws-lc-rs has no way to rebuild a key
//!   from it: `DecapsulationKey::new` takes the expanded 3168-byte key, and neither 1.19 nor its
//!   `unstable` module nor `aws-lc-sys`'s safe surface has seed-based ML-KEM key generation.
//!   Expanding the seed ourselves from the backend's SHA3/SHAKE would be writing the KEM, so
//!   `backend::mlkem_seed` runs RustCrypto's `ml-kem` for these two operations. Encapsulation, which
//!   takes only the public key, stays on aws-lc.
//! - **ML-DSA-65 in the FIPS build** (below).
//!
//! # The `fips` feature
//!
//! Feature `fips` builds aws-lc-rs on the AWS-LC FIPS module (`aws-lc-fips-sys`; the image pins
//! aws-lc-rs 1.17.x, see `docker/fips/overlay.sh`) and serves everything the module certifies from
//! it: ML-KEM encapsulation, AES-256-GCM, HKDF, HMAC, SHA-2 and SHA-3, Ed25519 and ECDSA P-256. It
//! is a distinct build, not a runtime switch, and these are outside the module:
//!
//! - ML-DSA-65, which no aws-lc-rs FIPS build has, runs on RustCrypto's `ml-dsa`
//!   (`backend::mldsa_soft`); it is unvalidated in either library;
//! - ML-KEM seed expansion and decapsulation, as above, so a `kx1` private key is expanded and used
//!   in RustCrypto, never in the module;
//! - OPAQUE's SHA-512 (opaque-ke is generic over digest 0.10, so it runs `sha2` 0.10) and Argon2id.
//!
//! The feature refuses to compile beside `rustcrypto` (and so beside `vectors`): that would link the
//! whole pure-Rust backend into a build that promises the module, and `kemlock-wasm` is the one
//! workspace crate that asks for it. `fips::verify` checks at start-up that the module is the one
//! linked and in FIPS mode.

#[cfg(not(any(feature = "aws-lc", feature = "rustcrypto")))]
compile_error!("kemlock-crypto needs the `aws-lc` or the `rustcrypto` feature");

#[cfg(all(feature = "fips", feature = "rustcrypto"))]
compile_error!(
    "kemlock-crypto: `fips` and `rustcrypto` (or `vectors`, which turns it on) can't be combined; \
     a FIPS build routes only ML-DSA and ML-KEM seed expansion to RustCrypto, and the full \
     RustCrypto backend would sit in the binary beside the validated module"
);

/// Runs a block once per backend that is built: aws-lc when the feature is on, and RustCrypto
/// always (the tests build it from the dev-dependencies).
#[cfg(test)]
macro_rules! for_backends {
    ($b:ident => $body:block) => {{
        #[cfg(feature = "aws-lc")]
        {
            #[allow(dead_code)]
            type $b = $crate::backend::aws_lc::AwsLc;
            $body
        }
        {
            #[allow(dead_code)]
            type $b = $crate::backend::rustcrypto::RustCrypto;
            $body
        }
    }};
}

mod aead;
mod backend;
mod error;
mod wire;

pub mod argon2id;
pub mod bundle;
pub mod confirm;
pub mod dedup;
pub mod ed25519;
#[cfg(feature = "fips")]
pub mod fips;
pub mod hash;
pub mod kem1;
pub mod key_box;
pub mod keys;
pub mod kma1;
pub mod kx1;
pub mod legacy_id;
pub mod manifest;
pub mod opaque;
pub mod owner;
pub mod p256;
pub mod password_wrap;
pub mod prf_wrap;
pub mod private_keys;
pub mod rand;
pub mod recovery_kit;
pub mod seal;
pub mod sealed_box;
pub mod send;
pub mod sig1;
#[cfg(feature = "vectors")]
#[doc(hidden)]
pub mod software;
pub mod space_chain;
pub mod totp;

#[cfg(any(test, feature = "vectors"))]
#[doc(hidden)]
pub mod vectors;

pub use error::Error;

/// Runs `f` with every random byte this crate draws coming from a ChaCha20 stream seeded with
/// `seed`, on this thread only. For the test-vector generator; the aws-lc backend still draws its
/// own ML-KEM and ML-DSA randomness, so only the RustCrypto backend is fully reproducible.
#[cfg(any(test, feature = "vectors"))]
#[doc(hidden)]
pub fn with_seeded_random<R>(seed: [u8; 32], f: impl FnOnce() -> R) -> R {
    rand::deterministic::with_seed(seed, f)
}
