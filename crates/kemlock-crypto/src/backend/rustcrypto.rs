//! The pure-Rust backend: RustCrypto's `ml-kem`, `ml-dsa`, `x25519-dalek`, `ed25519-dalek`,
//! `aes-gcm`, `hkdf`, `hmac`, `sha2`, `sha3`, `sha1` and `p256`. It is the one that runs in
//! WebAssembly and the one that can be driven by a seeded random stream.
//!
//! ML-DSA signing here is the deterministic variant of FIPS 204 (the `ml-dsa` crate's `Signer`),
//! which the format allows ("hedged or deterministic; verifiers accept both").

use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{Backend, MLDSA_SEED_LEN, MLKEM_SEED_LEN, ed25519_rule, mldsa_soft, mlkem_seed};
use crate::{Error, wire::fixed};

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RustCrypto;

fn invalid<E>(_: E) -> Error {
    Error::invalid()
}

impl Backend for RustCrypto {
    const NAME: &'static str = "rustcrypto";

    fn random(buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(invalid)
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        fixed(&Sha256::digest(data))
    }

    fn sha512(data: &[u8]) -> [u8; 64] {
        fixed(&Sha512::digest(data))
    }

    fn sha3_256(data: &[u8]) -> [u8; 32] {
        fixed(&sha3::Sha3_256::digest(data))
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        match Hmac::<Sha256>::new_from_slice(key) {
            Ok(mut mac) => {
                mac.update(data);
                fixed(&mac.finalize().into_bytes())
            }
            // HMAC takes keys of any length, so this arm can't be reached.
            Err(_) => [0u8; 32],
        }
    }

    fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        match Hmac::<sha1::Sha1>::new_from_slice(key) {
            Ok(mut mac) => {
                mac.update(data);
                fixed(&mac.finalize().into_bytes())
            }
            Err(_) => [0u8; 20],
        }
    }

    fn hkdf_sha256(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        hkdf::Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, out)
            .map_err(invalid)
    }

    fn hkdf_sha512(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        hkdf::Hkdf::<Sha512>::new(salt, ikm)
            .expand(info, out)
            .map_err(invalid)
    }

    fn aes256gcm_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use aes_gcm::{
            Aes256Gcm, KeyInit as _,
            aead::{Aead as _, Payload},
        };
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(invalid)
    }

    fn aes256gcm_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use aes_gcm::{
            Aes256Gcm, KeyInit as _,
            aead::{Aead as _, Payload},
        };
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext_and_tag,
                    aad,
                },
            )
            .map_err(invalid)
    }

    fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(x25519_dalek::x25519(
            *secret,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    fn x25519(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let shared = Zeroizing::new(x25519_dalek::x25519(*secret, *peer));
        if bool::from(shared.ct_eq(&[0u8; 32])) {
            return Err(Error::invalid());
        }
        Ok(*shared)
    }

    fn mlkem1024_public(seed: &[u8; MLKEM_SEED_LEN]) -> Result<Vec<u8>, Error> {
        mlkem_seed::public(seed)
    }

    fn mlkem1024_encaps(public: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Error> {
        use ml_kem::{B32, Key, ml_kem_1024::EncapsulationKey};
        let key: &Key<EncapsulationKey> = public.try_into().map_err(invalid)?;
        let key = EncapsulationKey::new(key).map_err(invalid)?;
        let mut m = Zeroizing::new([0u8; 32]);
        crate::rand::try_fill::<Self>(&mut *m)?;
        let (ciphertext, secret) = key.encapsulate_deterministic(&B32::from(*m));
        Ok((ciphertext.as_slice().to_vec(), fixed(secret.as_slice())))
    }

    fn mlkem1024_decaps(seed: &[u8; MLKEM_SEED_LEN], ciphertext: &[u8]) -> Result<[u8; 32], Error> {
        mlkem_seed::decaps(seed, ciphertext)
    }

    fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes())
    }

    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer as _;
        let sig = ed25519_dalek::SigningKey::from_bytes(seed)
            .try_sign(msg)
            .map_err(invalid)?;
        Ok(sig.to_bytes())
    }

    fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        // The rule's byte checks (canonical points, S below L) run here too, so that both backends
        // are held to the same list in one place and a library change can't loosen it.
        ed25519_rule::check_inputs(public, sig)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(public).map_err(invalid)?;
        let sig = ed25519_dalek::Signature::from_slice(sig).map_err(invalid)?;
        // `verify_strict` refuses a small-order key or R and any S not below L, and compares the
        // recomputed R with the one sent byte for byte. It accepts a non-canonical key (y of p or
        // more), which `ed25519_rule` has refused above; aws-lc lacks the small-order checks, so
        // its backend runs the same rule first.
        key.verify_strict(msg, &sig).map_err(invalid)
    }

    fn mldsa65_public(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Vec<u8>, Error> {
        mldsa_soft::public(seed)
    }

    fn mldsa65_sign(seed: &[u8; MLDSA_SEED_LEN], msg: &[u8]) -> Result<Vec<u8>, Error> {
        mldsa_soft::sign(seed, msg)
    }

    fn mldsa65_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        mldsa_soft::verify(public, msg, sig)
    }

    fn p256_public(secret: &[u8; 32]) -> Result<[u8; 65], Error> {
        use ::p256::ecdsa::SigningKey;
        let bytes: ::p256::FieldBytes = (*secret).into();
        let key = SigningKey::from_bytes(&bytes).map_err(invalid)?;
        let point = key.verifying_key().to_sec1_point(false);
        if point.as_bytes().len() != 65 {
            return Err(Error::invalid());
        }
        Ok(fixed(point.as_bytes()))
    }

    fn p256_sign(secret: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
        use ::p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
        let bytes: ::p256::FieldBytes = (*secret).into();
        let key = SigningKey::from_bytes(&bytes).map_err(invalid)?;
        let sig: Signature = key.try_sign(msg).map_err(invalid)?;
        Ok(fixed(sig.to_bytes().as_slice()))
    }

    fn p256_verify(public: &[u8; 65], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use ::p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
        let key = VerifyingKey::from_sec1_bytes(public).map_err(invalid)?;
        let sig = Signature::from_slice(sig).map_err(invalid)?;
        key.verify(msg, &sig).map_err(invalid)
    }
}
