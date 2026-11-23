//! SHA-256, HMAC-SHA-256 and a constant-time comparison.

use subtle::ConstantTimeEq as _;

use crate::backend::{Active, Backend};

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Active::sha256(data)
}

/// HMAC-SHA-256 of `data` under `key` (any length).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    Active::hmac_sha256(key, data)
}

/// Compares two byte strings in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case_2() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn ct_eq_compares_lengths_and_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"ab", b"abc"));
    }
}
