//! The primitives the federation formats are built from, over `kemlock-crypto` and aws-lc-rs.
//!
//! - Hashing and HMAC come from `kemlock_crypto::hash`; SHA-512 from aws-lc-rs.
//! - HKDF-SHA256 (RFC 5869) is written here from HMAC: extract is `HMAC(salt, ikm)` and every
//!   expansion this crate asks for is at most 32 bytes, so expand is `HMAC(prk, info ‖ 0x01)`
//!   truncated, which is RFC 5869's first block.
//! - Frames are sealed with AES-256-GCM or ChaCha20-Poly1305 under a caller-chosen nonce.
//! - `kx1` and `sig1` run on kemlock-crypto's public functions: aws-lc-rs natively, with the ML-KEM
//!   seed expansion kemlock-crypto routes to RustCrypto itself. Only the test-vector generator
//!   (feature `vectors`) calls the RustCrypto backend instead, because that is the one a seeded
//!   random stream drives end to end (aws-lc's ML-KEM encapsulation and ML-DSA signing draw their
//!   own randomness); both backends are cross-checked against the shared vectors.

use crate::error::{FedError, Result};
use aws_lc_rs::aead;
use kemlock_crypto::{hash, kx1, sig1};
use zeroize::Zeroizing;

/// `kx1` and `sig1` on kemlock-crypto's public functions.
#[cfg(not(feature = "vectors"))]
mod primitives {
    use kemlock_crypto::{
        Error,
        kx1::{self, Ciphertext, PrivateKey, PublicKey, SharedSecret},
        sig1,
    };

    pub(super) fn kem_generate() -> Result<(PrivateKey, PublicKey), Error> {
        kx1::generate()
    }

    pub(super) fn kem_public(private: &PrivateKey) -> Result<PublicKey, Error> {
        private.public_key()
    }

    pub(super) fn kem_encapsulate(public: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
        public.encapsulate()
    }

    pub(super) fn kem_decapsulate(
        private: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, Error> {
        private.decapsulate(ciphertext)
    }

    pub(super) fn sign_public(key: &sig1::SigningKey) -> Result<sig1::PublicKey, Error> {
        key.public_key()
    }

    pub(super) fn sign(
        key: &sig1::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        key.sign(context, message)
    }
}

/// The same operations on the RustCrypto backend, so the generator's output is reproducible.
#[cfg(feature = "vectors")]
mod primitives {
    use kemlock_crypto::{
        Error,
        kx1::{Ciphertext, PrivateKey, PublicKey, SharedSecret},
        sig1,
        software::{exchange, signing},
    };

    pub(super) fn kem_generate() -> Result<(PrivateKey, PublicKey), Error> {
        exchange::generate()
    }

    pub(super) fn kem_public(private: &PrivateKey) -> Result<PublicKey, Error> {
        exchange::public_key(private)
    }

    pub(super) fn kem_encapsulate(public: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
        exchange::encapsulate(public)
    }

    pub(super) fn kem_decapsulate(
        private: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, Error> {
        exchange::decapsulate(private, ciphertext)
    }

    pub(super) fn sign_public(key: &sig1::SigningKey) -> Result<sig1::PublicKey, Error> {
        signing::public_key(key)
    }

    pub(super) fn sign(
        key: &sig1::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        signing::sign(key, context, message)
    }
}

/// `u32be(len(x)) ‖ x`, as in `docs/crypto.md`.
pub fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_be_bytes());
    out.extend_from_slice(x);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    hash::sha256(data)
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_ref());
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hash::hmac_sha256(key, data)
}

/// HKDF-Extract with SHA-256: `HMAC(salt, ikm)`.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(salt, ikm))
}

/// HKDF-Expand with SHA-256 for an output of at most 32 bytes.
pub fn hkdf_expand<const N: usize>(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; N]> {
    const { assert!(N <= 32) };
    let mut input = Vec::with_capacity(info.len() + 1);
    input.extend_from_slice(info);
    input.push(1);
    let block = Zeroizing::new(hmac_sha256(prk, &input));
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&block[..N]);
    out
}

/// The AEAD of a suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aead {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

impl Aead {
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Aead::Aes256Gcm => &aead::AES_256_GCM,
            Aead::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    fn key(self, key: &[u8; 32]) -> Result<aead::LessSafeKey> {
        let unbound = aead::UnboundKey::new(self.algorithm(), key).map_err(|_| FedError::Crypto)?;
        Ok(aead::LessSafeKey::new(unbound))
    }

    /// `ciphertext ‖ tag(16)`.
    pub fn seal(
        self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.key(key)?;
        let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
        buf.extend_from_slice(plaintext);
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| FedError::Crypto)?;
        Ok(buf)
    }

    /// Opens `ciphertext ‖ tag(16)`; the length is checked first.
    pub fn open(
        self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < TAG_LEN {
            return Err(FedError::Frame("too short to hold a tag"));
        }
        let key = self.key(key)?;
        let mut buf = Zeroizing::new(sealed.to_vec());
        let n = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| FedError::Frame("authentication failed"))?
            .len();
        buf.truncate(n);
        Ok(buf)
    }
}

/// A fresh `kx1` key pair.
pub fn kem_generate() -> Result<(kx1::PrivateKey, kx1::PublicKey)> {
    Ok(primitives::kem_generate()?)
}

/// The public key of a private key.
pub fn kem_public(private: &kx1::PrivateKey) -> Result<kx1::PublicKey> {
    Ok(primitives::kem_public(private)?)
}

/// Encapsulates to `public`: `(ciphertext, shared secret)`.
pub fn kem_encapsulate(public: &kx1::PublicKey) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let (ct, ss) = primitives::kem_encapsulate(public)?;
    Ok((ct.to_vec(), Zeroizing::new(*ss.as_bytes())))
}

/// Recovers the shared secret from a ciphertext.
pub fn kem_decapsulate(
    private: &kx1::PrivateKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let ss = primitives::kem_decapsulate(private, ciphertext)?;
    Ok(Zeroizing::new(*ss.as_bytes()))
}

/// The public key of a signing key.
pub fn sign_public(key: &sig1::SigningKey) -> Result<sig1::PublicKey> {
    Ok(primitives::sign_public(key)?)
}

/// Signs `message` under `context` (`sig1`: ML-DSA-65 + Ed25519).
pub fn sign(key: &sig1::SigningKey, context: &str, message: &[u8]) -> Result<Vec<u8>> {
    Ok(primitives::sign(key, context, message)?)
}

/// Verifies a `sig1` signature.
pub fn verify(
    public: &sig1::PublicKey,
    context: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    public
        .verify(context, message, signature)
        .map_err(|_| FedError::Invalid("a signature does not verify"))
}

/// A fresh random array.
pub fn random<const N: usize>() -> [u8; N] {
    kemlock_crypto::rand::bytes::<N>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc_5869_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex::encode(*prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        // The first 32 bytes of OKM of the RFC's L = 42 case are T(1).
        let okm = hkdf_expand::<32>(&prk, &info);
        assert_eq!(
            hex::encode(*okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn expand_truncates_for_short_outputs() {
        let prk = [3u8; 32];
        let long = hkdf_expand::<32>(&prk, b"info");
        let short = hkdf_expand::<12>(&prk, b"info");
        assert_eq!(&long[..12], &short[..]);
    }

    #[test]
    fn both_aeads_round_trip_and_bind_everything() {
        for aead in [Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
            let key = [7u8; 32];
            let nonce = [1u8; 12];
            let sealed = aead.seal(&key, &nonce, b"aad", b"hello").expect("seal");
            assert_eq!(sealed.len(), 5 + TAG_LEN);
            let opened = aead.open(&key, &nonce, b"aad", &sealed).expect("open");
            assert_eq!(&opened[..], b"hello");
            assert!(aead.open(&[8u8; 32], &nonce, b"aad", &sealed).is_err());
            assert!(aead.open(&key, &[2u8; 12], b"aad", &sealed).is_err());
            assert!(aead.open(&key, &nonce, b"other", &sealed).is_err());
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 1;
                assert!(aead.open(&key, &nonce, b"aad", &bad).is_err(), "byte {i}");
            }
            assert!(aead.open(&key, &nonce, b"aad", &sealed[..5]).is_err());
        }
    }

    #[test]
    fn sha512_has_its_known_answer() {
        assert_eq!(
            hex::encode(sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn lp_prefixes_the_length() {
        let mut out = Vec::new();
        lp(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn signatures_and_exchange_work_through_the_facade() {
        let key = sig1::SigningKey::from_bytes(&[9; 64]);
        let public = sign_public(&key).expect("public");
        let sig = sign(&key, "ctx", b"m").expect("sign");
        verify(&public, "ctx", b"m", &sig).expect("verify");
        assert!(verify(&public, "ctx", b"n", &sig).is_err());

        let (private, public) = kem_generate().expect("generate");
        let (ct, a) = kem_encapsulate(&public).expect("encaps");
        let b = kem_decapsulate(&private, &ct).expect("decaps");
        assert_eq!(*a, *b);
    }
}
