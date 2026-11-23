//! The master key: Argon2id, version 0x13, 32 output bytes.
//!
//! The password is the UTF-8 of its NFC form; normalising it is the caller's job, as is picking the
//! parameters. New accounts use `m = 65536` KiB, `t = 3`, `p = 4` and a random 16-byte salt.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::Error;

/// Memory cost of new accounts, in KiB.
pub const DEFAULT_MEMORY_KIB: u32 = 65536;
/// Iterations of new accounts.
pub const DEFAULT_ITERATIONS: u32 = 3;
/// Lanes of new accounts.
pub const DEFAULT_PARALLELISM: u32 = 4;
/// The salt length new accounts use.
pub const SALT_LEN: usize = 16;

/// `Argon2id(password, salt, m, t, p, L = 32)`.
///
/// Fails when the parameters are out of Argon2's range (a salt under 8 bytes, a memory cost under
/// 8 × `parallelism` KiB, a zero count) or the memory can't be allocated.
pub fn master_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; 32], Error> {
    let params =
        Params::new(memory_kib, iterations, parallelism, Some(32)).map_err(|_| Error::invalid())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| Error::invalid())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small parameters keep the tests quick; the format doesn't depend on them.
    const M: u32 = 64;
    const T: u32 = 2;
    const P: u32 = 1;

    #[test]
    fn is_deterministic_and_32_bytes() {
        let a = master_key(b"password", b"0123456789abcdef", M, T, P).expect("argon2");
        let b = master_key(b"password", b"0123456789abcdef", M, T, P).expect("argon2");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn password_salt_and_every_parameter_matter() {
        let base = master_key(b"password", b"0123456789abcdef", M, T, P).expect("argon2");
        assert_ne!(
            base,
            master_key(b"Password", b"0123456789abcdef", M, T, P).expect("argon2")
        );
        assert_ne!(
            base,
            master_key(b"password", b"0123456789abcdeg", M, T, P).expect("argon2")
        );
        assert_ne!(
            base,
            master_key(b"password", b"0123456789abcdef", M * 2, T, P).expect("argon2")
        );
        assert_ne!(
            base,
            master_key(b"password", b"0123456789abcdef", M, T + 1, P).expect("argon2")
        );
        assert_ne!(
            base,
            master_key(b"password", b"0123456789abcdef", M * 2, T, 2).expect("argon2")
        );
    }

    #[test]
    fn bad_parameters_are_errors_not_panics() {
        assert!(
            master_key(b"p", b"short", M, T, P).is_err(),
            "salt under 8 bytes"
        );
        assert!(
            master_key(b"p", b"0123456789abcdef", M, 0, P).is_err(),
            "zero iterations"
        );
        assert!(
            master_key(b"p", b"0123456789abcdef", M, T, 0).is_err(),
            "zero lanes"
        );
        assert!(
            master_key(b"p", b"0123456789abcdef", 1, T, P).is_err(),
            "too little memory"
        );
    }

    #[test]
    fn unicode_passwords_are_taken_as_bytes() {
        // Normalisation (NFC) is the caller's job; the same bytes always give the same key.
        let nfc = "caf\u{e9}".as_bytes();
        let nfd = "cafe\u{301}".as_bytes();
        let a = master_key(nfc, b"0123456789abcdef", M, T, P).expect("argon2");
        let b = master_key(nfd, b"0123456789abcdef", M, T, P).expect("argon2");
        assert_ne!(a, b);
    }
}
