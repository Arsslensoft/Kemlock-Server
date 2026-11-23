//! The server-side check of the master password hash, exactly as Vaultwarden does it: PBKDF2 with
//! HMAC-SHA-256 over the text of the client's `masterPasswordHash`, the account's salt and its
//! rounds, 32 bytes out. The client's hash is already a stretched key, so this only keeps a copy
//! of the database from being replayed as a sign-in.

use aws_lc_rs::pbkdf2;
use std::num::NonZeroU32;

/// The 32-byte PBKDF2 result for `secret`.
pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let rounds = NonZeroU32::new(iterations).unwrap_or(NonZeroU32::MIN);
    let mut out = vec![0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, rounds, salt, secret, &mut out);
    out
}

/// Whether `previous` is the hash of `secret`, compared in constant time. An empty `previous` (an
/// account with no password) never matches.
pub fn verify_password(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let Some(rounds) = NonZeroU32::new(iterations) else {
        return false;
    };
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, rounds, salt, secret, previous).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for b in bytes {
            write!(out, "{b:02x}").expect("writing to a String");
        }
        out
    }

    #[test]
    fn pbkdf2_sha256_matches_the_rfc_7914_vector() {
        // RFC 7914, section 11: PBKDF2-HMAC-SHA-256, "passwd", "salt", c = 1, 64 bytes; the first
        // 32 bytes are what a 32-byte derivation gives too.
        assert_eq!(
            hex(&hash_password(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn verification_checks_secret_salt_and_rounds() {
        let stored = hash_password(b"hash-from-the-client", b"salty", 1_000);
        assert!(verify_password(
            b"hash-from-the-client",
            b"salty",
            &stored,
            1_000
        ));
        assert!(!verify_password(b"another", b"salty", &stored, 1_000));
        assert!(!verify_password(
            b"hash-from-the-client",
            b"pepper",
            &stored,
            1_000
        ));
        assert!(!verify_password(
            b"hash-from-the-client",
            b"salty",
            &stored,
            1_001
        ));
        assert!(!verify_password(
            b"hash-from-the-client",
            b"salty",
            &[],
            1_000
        ));
        assert!(!verify_password(
            b"hash-from-the-client",
            b"salty",
            &stored,
            0
        ));
    }
}
