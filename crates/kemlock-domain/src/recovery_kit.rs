//! The Recovery Kit's record: the non-secret facts the server keeps (docs/crypto.md, "The Recovery
//! Kit").
//!
//! The account's root key is wrapped under a random kit key that is split into pieces, any 2 of 3
//! of which rebuild it. The server keeps the wrap, which only the pieces open, and never a piece.

use time::OffsetDateTime;

/// An account's Recovery Kit. There is at most one.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKit {
    /// Ties the pieces to this record: 8 base32 characters.
    pub kit_id: String,
    /// The root key wrapped under the kit key: `nonce(12) ‖ ciphertext(64) ‖ tag(16)`. Its tag is
    /// also the check that rebuilt pieces are the right ones.
    pub wrapped_key: Vec<u8>,
    /// The account's key version the wrap's AAD names. A kit for another version than the
    /// account's current one is stale: no piece opens it.
    pub key_version: u32,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKit")
            .field("kit_id", &self.kit_id)
            .field("key_version", &self.key_version)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}
