//! What the admin console shows beyond the federation rows themselves: the vaults an admin may
//! federate with their size, what is known of a peer's descriptor and KEM key, and the record of a
//! peer that offered an identity key other than the pinned one.
//!
//! These are plain values; the storage ports that read and write them are default methods of
//! [`FedAdminRepo`](crate::extra::FedAdminRepo), so a store that keeps none of it (the in-memory
//! fake aside) answers "nothing known".

use kemlock_domain::{Owner, ServerId};

/// A vault homed on this server as the console lists it.
///
/// A vault's name is ciphertext under a key only its members hold, so the server cannot give one:
/// it gives what it knows. An account's vault is named by the owner's email address; a space has
/// no email, so `owner_email` is `None` and the console falls back to the space's short id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub vault: Owner,
    /// The owner's email address, for an account's vault.
    pub owner_email: Option<String>,
    /// People who can open the vault: 1 for an account's vault, the members of a space that
    /// haven't been revoked.
    pub members: u64,
    /// What the vault takes here: the stored size of its items plus its ready attachments, bytes.
    pub size_bytes: u64,
}

/// What this server last learned of a peer's published descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSecurityRecord {
    pub peer: ServerId,
    /// The signed descriptor as the peer served it. Stored only after it verified against the
    /// pinned identity key.
    pub descriptor: Vec<u8>,
    /// Unix seconds when it was read.
    pub fetched_at: u64,
    /// `kem_key_id` of the KEM key in that descriptor.
    pub kem_key_id: Vec<u8>,
    /// Unix seconds when this server first saw that KEM key. A KEM key's creation time is not in
    /// the descriptor, so this is the nearest this server can say of its age.
    pub kem_first_seen: u64,
    /// The suite the last session used, if one was noted.
    pub suite: Option<String>,
}

/// A peer that offered an identity key other than the one pinned for it: "Possible man in the
/// middle". One row per peer; a different offered key starts a new row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MismatchRecord {
    pub peer: ServerId,
    /// The `sig1` public key it offered.
    pub offered_key: Vec<u8>,
    /// Unix seconds of the first and the latest offer of this key.
    pub first_at: u64,
    pub last_at: u64,
    /// Connection attempts that met this key.
    pub attempts: u64,
    /// The address this server dialled when it met the key.
    pub source: String,
    /// When an admin chose to keep blocking, and who, if one did.
    pub kept_blocking_at: Option<u64>,
    pub kept_blocking_by: Option<String>,
}
