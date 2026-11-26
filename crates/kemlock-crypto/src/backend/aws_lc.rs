//! The native backend: aws-lc-rs (1.19 by default, the 1.17 FIPS build under feature `fips`).
//!
//! Everything here runs on aws-lc-rs except two things it cannot do, which are routed to RustCrypto
//! explicitly and only for those:
//!
//! - **ML-KEM from a 64-byte seed** (`mlkem1024_public`, `mlkem1024_decaps`), on every aws-lc-rs
//!   release: `kem::DecapsulationKey::new` takes the 3168-byte expanded key, and no public API
//!   expands `d ‖ z`. The `kx1` private key is that seed, so these go to `mlkem_seed`; see there
//!   for what was checked. Encapsulation (`mlkem1024_encaps`) stays on aws-lc: `EncapsulationKey::new`
//!   takes the public key bytes. In the FIPS build that means ML-KEM encapsulation is inside the
//!   validated module, and expanding a `kx1` seed and decapsulating are not.
//! - **ML-DSA-65 under `fips`**: no aws-lc-rs FIPS build has it, so the three ML-DSA operations go
//!   to `mldsa_soft`. Without `fips` they use aws-lc-rs's `signature::ML_DSA_65` (in `signature`
//!   in 1.19; the `unstable::signature` paths are deprecated aliases), so the `unstable` feature the
//!   workspace turns on isn't needed for it.
//!
//! Neither exists on aws-lc-rs as deterministic ML-KEM encapsulation or ML-DSA signing, so aws-lc
//! output for them is not reproducible; the test-vector generator runs on the RustCrypto backend.
//!
//! Every API used here exists with the same signature in aws-lc-rs 1.17.4 and 1.19.0, which is what
//! lets one source build against both.

use aws_lc_rs::{
    aead, agreement, digest, hkdf, hmac, kem, rand as aws_rand,
    signature::{self, KeyPair, UnparsedPublicKey},
};

use super::{Backend, MLDSA_SEED_LEN, MLKEM_SEED_LEN, ed25519_rule, mlkem_seed};
use crate::{Error, wire::fixed};

/// ML-DSA-65: aws-lc-rs where it has it, the RustCrypto module where it doesn't.
#[cfg(feature = "fips")]
use super::mldsa_soft as mldsa;

#[cfg(not(feature = "fips"))]
mod mldsa {
    use aws_lc_rs::signature::{self, KeyPair, UnparsedPublicKey};

    use crate::{Error, backend::MLDSA_SEED_LEN};

    fn invalid<E>(_: E) -> Error {
        Error::invalid()
    }

    pub(super) fn public(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Vec<u8>, Error> {
        let pair = signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, seed)
            .map_err(invalid)?;
        Ok(pair.public_key().as_ref().to_vec())
    }

    pub(super) fn sign(seed: &[u8; MLDSA_SEED_LEN], msg: &[u8]) -> Result<Vec<u8>, Error> {
        let pair = signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, seed)
            .map_err(invalid)?;
        let mut sig = vec![0u8; signature::ML_DSA_65_SIGNING.signature_len()];
        let len = pair.sign(msg, &mut sig).map_err(invalid)?;
        sig.truncate(len);
        Ok(sig)
    }

    pub(super) fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&signature::ML_DSA_65, public)
            .verify(msg, sig)
            .map_err(invalid)
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct AwsLc;

fn invalid<E>(_: E) -> Error {
    Error::invalid()
}

/// The output length of an HKDF expansion, for aws-lc-rs's `KeyType` parameter.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_fill(
    algorithm: hkdf::Algorithm,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // An empty salt is HMAC keyed with nothing, which RFC 5869 defines as the hash length of
    // zero bytes.
    let prk = hkdf::Salt::new(algorithm, salt.unwrap_or(&[])).extract(ikm);
    let info_parts = [info];
    prk.expand(&info_parts, OutLen(out.len()))
        .map_err(invalid)?
        .fill(out)
        .map_err(invalid)
}

fn gcm_key(key: &[u8; 32]) -> Result<aead::LessSafeKey, Error> {
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(invalid)?;
    Ok(aead::LessSafeKey::new(unbound))
}

impl Backend for AwsLc {
    const NAME: &'static str = "aws-lc";

    fn random(buf: &mut [u8]) -> Result<(), Error> {
        aws_rand::fill(buf).map_err(invalid)
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        fixed(digest::digest(&digest::SHA256, data).as_ref())
    }

    fn sha512(data: &[u8]) -> [u8; 64] {
        fixed(digest::digest(&digest::SHA512, data).as_ref())
    }

    fn sha3_256(data: &[u8]) -> [u8; 32] {
        fixed(digest::digest(&digest::SHA3_256, data).as_ref())
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        fixed(hmac::sign(&key, data).as_ref())
    }

    fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        fixed(hmac::sign(&key, data).as_ref())
    }

    fn hkdf_sha256(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        hkdf_fill(hkdf::HKDF_SHA256, ikm, salt, info, out)
    }

    fn hkdf_sha512(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        hkdf_fill(hkdf::HKDF_SHA512, ikm, salt, info, out)
    }

    fn aes256gcm_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = gcm_key(key)?;
        let mut buf = Vec::with_capacity(plaintext.len() + 16);
        buf.extend_from_slice(plaintext);
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut buf,
        )
        .map_err(invalid)?;
        Ok(buf)
    }

    fn aes256gcm_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = gcm_key(key)?;
        let mut buf = ciphertext_and_tag.to_vec();
        let plain_len = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                &mut buf,
            )
            .map_err(invalid)?
            .len();
        buf.truncate(plain_len);
        Ok(buf)
    }

    fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32], Error> {
        let key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, secret).map_err(invalid)?;
        let public = key.compute_public_key().map_err(invalid)?;
        Ok(fixed(public.as_ref()))
    }

    fn x25519(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, secret).map_err(invalid)?;
        // aws-lc-rs fails the agreement when the result is all zero (RFC 7748 section 6.1).
        agreement::agree(
            &key,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
            Error::invalid(),
            |shared| Ok(fixed(shared)),
        )
    }

    fn mlkem1024_public(seed: &[u8; MLKEM_SEED_LEN]) -> Result<Vec<u8>, Error> {
        // RustCrypto, on purpose: aws-lc-rs can't expand an ML-KEM seed (see the module comment).
        mlkem_seed::public(seed)
    }

    fn mlkem1024_encaps(public: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let key = kem::EncapsulationKey::new(&kem::ML_KEM_1024, public).map_err(invalid)?;
        let (ciphertext, secret) = key.encapsulate().map_err(invalid)?;
        Ok((ciphertext.as_ref().to_vec(), fixed(secret.as_ref())))
    }

    fn mlkem1024_decaps(seed: &[u8; MLKEM_SEED_LEN], ciphertext: &[u8]) -> Result<[u8; 32], Error> {
        // RustCrypto, on purpose: the key can't be expanded from its seed on aws-lc-rs.
        mlkem_seed::decaps(seed, ciphertext)
    }

    fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(invalid)?;
        Ok(fixed(pair.public_key().as_ref()))
    }

    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(invalid)?;
        Ok(fixed(pair.sign(msg).as_ref()))
    }

    fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        // aws-lc alone is not known to refuse small-order keys, non-canonical encodings or an S
        // between L and 2^253. The rule (docs/crypto.md, "Ed25519 verification rule") refuses
        // them first, so this verifies exactly as RustCrypto's `verify_strict` does.
        ed25519_rule::check_inputs(public, sig)?;
        UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(msg, sig)
            .map_err(invalid)
    }

    fn mldsa65_public(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Vec<u8>, Error> {
        mldsa::public(seed)
    }

    fn mldsa65_sign(seed: &[u8; MLDSA_SEED_LEN], msg: &[u8]) -> Result<Vec<u8>, Error> {
        mldsa::sign(seed, msg)
    }

    fn mldsa65_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        mldsa::verify(public, msg, sig)
    }

    fn p256_public(secret: &[u8; 32]) -> Result<[u8; 65], Error> {
        let key = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, secret)
            .map_err(invalid)?;
        let public = key.compute_public_key().map_err(invalid)?;
        let bytes = public.as_ref();
        if bytes.len() != 65 {
            return Err(Error::invalid());
        }
        Ok(fixed(bytes))
    }

    fn p256_sign(secret: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
        let public = Self::p256_public(secret)?;
        let pair = signature::EcdsaKeyPair::from_private_key_and_public_key(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            secret,
            &public,
        )
        .map_err(invalid)?;
        let sig = pair
            .sign(&aws_rand::SystemRandom::new(), msg)
            .map_err(invalid)?;
        Ok(fixed(sig.as_ref()))
    }

    fn p256_verify(public: &[u8; 65], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public)
            .verify(msg, sig)
            .map_err(invalid)
    }
}
