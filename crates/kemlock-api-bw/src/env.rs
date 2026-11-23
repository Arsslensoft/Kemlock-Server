//! The clock and the random source: what the API needs from its surroundings besides stores.
//! Tests replace both, so tokens expire and revision dates move on command.

use time::OffsetDateTime;
use uuid::Uuid;

pub trait Env: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
    fn fill(&self, buf: &mut [u8]);
}

/// The wall clock and the operating system's random source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn fill(&self, buf: &mut [u8]) {
        kemlock_crypto::rand::fill(buf);
    }
}

/// `N` random bytes.
pub(crate) fn random_bytes<const N: usize>(env: &dyn Env) -> [u8; N] {
    let mut out = [0u8; N];
    env.fill(&mut out);
    out
}

/// A random version-4 UUID.
pub(crate) fn random_uuid(env: &dyn Env) -> Uuid {
    uuid::Builder::from_random_bytes(random_bytes::<16>(env)).into_uuid()
}

/// `N` random bytes as lower-case hex, as Vaultwarden makes attachment ids.
pub(crate) fn random_hex<const N: usize>(env: &dyn Env) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(N * 2);
    for byte in random_bytes::<N>(env) {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}

/// A random string over `[A-Za-z0-9]`, as Vaultwarden's 30-character API keys. Bytes above the
/// largest multiple of 62 are redrawn so every character is equally likely.
pub(crate) fn random_alphanumeric(env: &dyn Env, len: usize) -> String {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for byte in random_bytes::<32>(env) {
            if out.len() == len {
                break;
            }
            if byte < 248 {
                out.push(char::from(ALPHABET[usize::from(byte) % 62]));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_values_have_the_shapes_asked_for() {
        let env = SystemEnv;
        let id = random_uuid(&env);
        assert_eq!(id.get_version_num(), 4);
        let hex = random_hex::<10>(&env);
        assert_eq!(hex.len(), 20);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let key = random_alphanumeric(&env, 30);
        assert_eq!(key.len(), 30);
        assert!(key.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_ne!(random_hex::<10>(&env), hex);
    }
}
