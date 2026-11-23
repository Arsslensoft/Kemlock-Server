//! The signed manifest of an owner's items, as the server keeps it.
//!
//! The manifest is a signed list of item ids, revisions and ciphertext hashes (docs/crypto.md,
//! "Signed manifest"). The server can't make one: it stores the exact bytes a writer signed, the
//! `sig1` signature and who signed, so any device can check the signature against the signer's
//! bundle and notice a server that rolled items back.

use crate::ids::UserId;
use crate::owner::Owner;
use time::OffsetDateTime;

/// The latest manifest of one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedManifest {
    pub owner: Owner,
    /// The manifest's counter, read from its bytes. It only goes up.
    pub counter: u64,
    /// The signed bytes, exactly as the writer made them.
    pub bytes: Vec<u8>,
    /// The `sig1` signature over `bytes` under context `"manifest"`.
    pub signature: Vec<u8>,
    /// The account whose bundle's `sig1` key made the signature.
    pub signer: UserId,
    /// When the server stored it.
    pub stored_at: OffsetDateTime,
}

impl SignedManifest {
    /// The largest manifest accepted: 2 MiB of bytes, the body limit, is about 36,000 entries.
    pub const MAX_BYTES: usize = 2 * 1024 * 1024;
    /// A `sig1` signature: ML-DSA-65 (3309) and Ed25519 (64).
    pub const SIGNATURE_LEN: usize = 3309 + 64;
    /// The counter is kept in a signed 64-bit column, so it can't pass `i64::MAX`.
    pub const MAX_COUNTER: u64 = i64::MAX as u64;
}
