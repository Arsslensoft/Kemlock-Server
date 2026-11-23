//! ML-DSA-65 on RustCrypto's `ml-dsa`, for the backends that have no ML-DSA of their own.
//!
//! No aws-lc-rs FIPS build has ML-DSA: its `pqdsa` module is compiled out under `fips` in 1.17, and
//! the AWS-LC FIPS module's certificate doesn't list it. So the `fips` build routes the ML-DSA-65
//! half of `sig1` here and keeps everything the module does certify on aws-lc. ML-DSA is
//! unvalidated in both libraries anyway (design, Security), so this takes nothing from the
//! validated boundary that was in it.
//!
//! Signing is the deterministic variant of FIPS 204, which the format allows ("hedged or
//! deterministic; verifiers accept both").

use ml_dsa::{
    EncodedVerifyingKey, Keypair as _, MlDsa65, Seed, Signature, Signer as _, SigningKey,
    Verifier as _, VerifyingKey,
};

use super::MLDSA_SEED_LEN;
use crate::Error;

fn invalid<E>(_: E) -> Error {
    Error::invalid()
}

/// The ML-DSA-65 public key for the 32-byte seed ξ.
pub(crate) fn public(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Vec<u8>, Error> {
    let key = SigningKey::<MlDsa65>::from_seed(&Seed::from(*seed));
    Ok(key.verifying_key().encode().as_slice().to_vec())
}

/// Pure ML-DSA-65 with an empty context, deterministic.
pub(crate) fn sign(seed: &[u8; MLDSA_SEED_LEN], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let key = SigningKey::<MlDsa65>::from_seed(&Seed::from(*seed));
    let sig: Signature<MlDsa65> = key.try_sign(msg).map_err(invalid)?;
    Ok(sig.encode().as_slice().to_vec())
}

pub(crate) fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let encoded: &EncodedVerifyingKey<MlDsa65> = public.try_into().map_err(invalid)?;
    let key = VerifyingKey::<MlDsa65>::decode(encoded);
    let sig = Signature::<MlDsa65>::try_from(sig).map_err(invalid)?;
    key.verify(msg, &sig).map_err(invalid)
}
