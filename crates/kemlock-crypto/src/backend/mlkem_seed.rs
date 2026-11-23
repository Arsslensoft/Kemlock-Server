//! ML-KEM-1024 from a 64-byte seed, on RustCrypto's `ml-kem`, for every backend.
//!
//! The `kx1` private key holds the seed `d ‖ z` (`docs/crypto.md`), so deriving the encapsulation
//! key and decapsulating both start by expanding it with FIPS 203's `KeyGen_internal`. aws-lc-rs
//! can't do that (1.19, the newest release when this was written): `kem::DecapsulationKey::new`
//! takes the 3168-byte expanded key, `DecapsulationKey::generate` keeps its seed to itself, the
//! `unstable` module has no ML-KEM, and `aws-lc-sys`'s `ml_kem_1024_keypair_deterministic` is a raw
//! binding that this crate (`unsafe_code = "forbid"`) can't call. Expanding the seed by hand with the
//! backend's SHA3/SHAKE would be reimplementing the KEM, so these two operations, and only these
//! two, run on RustCrypto on every backend, aws-lc included. Encapsulation, the third ML-KEM
//! operation, stays on the backend's own implementation.
//!
//! Both aws-lc and RustCrypto implement FIPS 203, so a key expanded here encapsulates and
//! decapsulates against either (`backend::tests` checks both directions).

use ml_kem::{
    Ciphertext, Decapsulate as _, KeyExport as _, MlKem1024, Seed, ml_kem_1024::DecapsulationKey,
};

use super::MLKEM_SEED_LEN;
use crate::{Error, wire::fixed};

fn invalid<E>(_: E) -> Error {
    Error::invalid()
}

/// The encapsulation key of `ML-KEM.KeyGen_internal(d, z)` for the seed `d ‖ z`.
pub(crate) fn public(seed: &[u8; MLKEM_SEED_LEN]) -> Result<Vec<u8>, Error> {
    let key = DecapsulationKey::from_seed(Seed::from(*seed));
    Ok(key.encapsulation_key().to_bytes().as_slice().to_vec())
}

/// Decapsulates with the key expanded from the seed; implicit rejection applies, so a ciphertext
/// of the right length always gives a secret.
pub(crate) fn decaps(seed: &[u8; MLKEM_SEED_LEN], ciphertext: &[u8]) -> Result<[u8; 32], Error> {
    let key = DecapsulationKey::from_seed(Seed::from(*seed));
    let ciphertext: &Ciphertext<MlKem1024> = ciphertext.try_into().map_err(invalid)?;
    let secret = key.decapsulate(ciphertext);
    Ok(fixed(secret.as_slice()))
}
