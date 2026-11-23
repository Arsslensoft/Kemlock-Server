//! Ports that ports.rs doesn't carry: hashing, and the bundle of environment ports (time,
//! randomness, hashing) most use cases need together.
//!
//! `ports.rs` has no hash port, yet refresh tokens are stored as their SHA-256 and an unknown
//! account's sign-in settings come from an HMAC, so use cases need one. The server wires it to
//! `kemlock-crypto`; tests wire it too.

use crate::ports::{Clock, Random};
use uuid::Uuid;

/// SHA-256 and HMAC-SHA-256.
pub trait Hasher: Send + Sync {
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];
}

/// Time, randomness and hashing: what a use case needs from its surroundings besides stores.
pub trait Platform: Clock + Random + Hasher {}

impl<T: Clock + Random + Hasher> Platform for T {}

/// A random version-4 UUID from the `Random` port, so tests can make ids repeatable.
pub fn random_uuid<R: Random>(random: &R) -> Uuid {
    uuid::Builder::from_random_bytes(random.bytes::<16>()).into_uuid()
}
