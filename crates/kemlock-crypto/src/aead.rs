//! The `aead1` seal of `docs/crypto.md`: AES-256-GCM with a random 12-byte nonce, written as
//! `nonce(12) ‖ ciphertext ‖ tag(16)`.

use zeroize::Zeroizing;

use crate::{Error, backend::Backend, rand};

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
/// What a sealed value adds to its plaintext.
pub(crate) const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Seals `plaintext` under `key`, binding `aad`.
pub(crate) fn seal<B: Backend>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = rand::try_bytes::<B, NONCE_LEN>()?;
    let sealed = B::aes256gcm_seal(key, &nonce, aad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a value made by [`seal`]. The length is checked before anything is decrypted.
pub(crate) fn open<B: Backend>(
    key: &[u8; 32],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < OVERHEAD {
        return Err(Error::invalid());
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::invalid())?;
    B::aes256gcm_open(key, &nonce, aad, rest).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_has_the_documented_overhead() {
        for_backends!(B => {
            let key = [9u8; 32];
            let sealed = seal::<B>(&key, b"aad", b"hello").expect("seal");
            assert_eq!(sealed.len(), 5 + OVERHEAD, "{}", B::NAME);
            let opened = open::<B>(&key, b"aad", &sealed).expect("open");
            assert_eq!(opened.as_slice(), b"hello", "{}", B::NAME);
        });
    }

    #[test]
    fn nonces_are_fresh() {
        for_backends!(B => {
            let key = [9u8; 32];
            let a = seal::<B>(&key, b"", b"x").expect("seal");
            let b = seal::<B>(&key, b"", b"x").expect("seal");
            assert_ne!(a, b, "{}", B::NAME);
        });
    }

    #[test]
    fn wrong_key_aad_or_tampering_fails() {
        for_backends!(B => {
            let key = [9u8; 32];
            let sealed = seal::<B>(&key, b"aad", b"hello").expect("seal");
            assert!(open::<B>(&[8u8; 32], b"aad", &sealed).is_err(), "{}", B::NAME);
            assert!(open::<B>(&key, b"other", &sealed).is_err(), "{}", B::NAME);
            for i in 0..sealed.len() {
                let mut bad = sealed.clone();
                bad[i] ^= 1;
                assert!(open::<B>(&key, b"aad", &bad).is_err(), "{} byte {i}", B::NAME);
            }
        });
    }

    #[test]
    fn short_input_is_refused_before_decrypting() {
        for_backends!(B => {
            let key = [9u8; 32];
            for len in 0..OVERHEAD {
                assert!(open::<B>(&key, b"", &vec![0u8; len]).is_err(), "{}", B::NAME);
            }
        });
    }

    #[test]
    fn empty_plaintext_round_trips() {
        for_backends!(B => {
            let key = [1u8; 32];
            let sealed = seal::<B>(&key, b"", b"").expect("seal");
            assert_eq!(sealed.len(), OVERHEAD);
            assert!(open::<B>(&key, b"", &sealed).expect("open").is_empty());
        });
    }
}
