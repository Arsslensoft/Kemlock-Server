//! The space chain: every change to who is in a space, their roles, the collections, groups and
//! grants, the key versions and the seals, the policies, the recovery key and the space's home
//! epoch is a signed, hash-linked record (docs/crypto.md, "Space chain").
//!
//! The server stores and serves the chain but holds no member's signing key, so it can't make a
//! record, and every member's client verifies the whole chain from the creator's self-signed first
//! record. This module is the contract both sides implement, as pure functions:
//!
//! - [`Record`] and [`SignedRecord`]: the nine-member record, its 21 [`Body`] kinds, its one
//!   spelling ([`Record::to_bytes`], [`Record::parse`]) and its wire form;
//! - [`seals`]: the labelled hash [`link`](seals::link), [`sign_record`](seals::sign_record), and
//!   the commitments' digests and key checks;
//! - [`State`]: what a chain gives, and [`State::apply`], which checks one record against it with
//!   the spec's reasons in the spec's order ([`Reason`]);
//! - [`verify_chain`]: a whole chain against a device's [`Anchor`].

pub mod b64;
pub mod client;
mod codec;
mod json;
pub mod model;
pub mod seals;
pub mod state;
pub mod verify;

#[cfg(any(test, feature = "vectors"))]
pub(crate) mod scenarios;
#[cfg(any(test, feature = "vectors"))]
pub(crate) mod testkit;

#[cfg(test)]
mod tests;

pub use model::{
    Body, ChainError, CollectionPerm, Commitment, CustomPerm, Grantee, Hash, Id, KeyRef, Kind,
    MasterPasswordPolicy, NameTarget, Policies, Reason, Record, Rights, Role, SessionTimeoutPolicy,
    SignedRecord, TimeoutAction, parse_uuid, uuid_text,
};
pub use seals::{key_check, link, seal_digest, seal_hash, sign_record, verify_record_signature};
pub use state::{Head, Member, State, Status};
pub use verify::{
    Anchor, Applied, NameCommit, SealCommit, Verified, end_of_chain_allows, verify_chain,
};

/// The limits of "Limits".
#[derive(Clone, Copy, Debug)]
pub struct Limits;

impl Limits {
    /// A record's bytes.
    pub const RECORD_BYTES: usize = 196_608;
    /// Records in a chain.
    pub const CHAIN_RECORDS: u64 = 65_536;
    /// Record bytes in a chain.
    pub const CHAIN_BYTES: usize = 64 * 1024 * 1024;
    /// From this `seq` on, a chain takes from anyone but an Owner only a `remove` record, and a
    /// `keys` record that replaces keys already marked: the last 1,024 records are kept so that no
    /// member can fill the chain and leave no room for an Owner to remove them or replace keys.
    pub const OPEN_RECORDS: u64 = Self::CHAIN_RECORDS - 1_024;
    /// From this `seq` on, a chain takes only an Owner's records: the last 128.
    pub const OWNER_ONLY_FROM: u64 = Self::CHAIN_RECORDS - 128;
    /// Past this many record bytes (the last 4 MiB of `CHAIN_BYTES`) the chain takes the same
    /// narrowed set as past `OPEN_RECORDS`.
    pub const OPEN_BYTES: u64 = Self::CHAIN_BYTES_U64 - 4 * 1024 * 1024;
    /// Past this many record bytes (the last 512 KiB) the chain takes only an Owner's records.
    pub const OWNER_ONLY_BYTES: u64 = Self::CHAIN_BYTES_U64 - 512 * 1024;
    /// `CHAIN_BYTES` as the `u64` the state counts in.
    pub const CHAIN_BYTES_U64: u64 = 64 * 1024 * 1024;
    /// Records in one request to the append route.
    pub const REQUEST_RECORDS: usize = 16;
    /// `invite.grants` and `collection.grants`.
    pub const GRANTS: usize = 1_000;
    /// `group-members.add` and `.remove` together.
    pub const GROUP_MEMBERS: usize = 1_000;
    /// `seal.seals`.
    pub const SEAL_SEALS: usize = 1_001;
    /// `keys.rotate`: the space key and 256 collection keys.
    pub const KEYS_ROTATE: usize = 257;
    /// A commitment's `count`.
    pub const SEAL_COUNT: u32 = 10_000;
    /// Members in the space, invited or confirmed.
    pub const MEMBERS: usize = 10_000;
    /// Collections.
    pub const COLLECTIONS: usize = 1_000;
    /// How deep collections nest.
    pub const DEPTH: usize = 16;
    /// Groups.
    pub const GROUPS: usize = 1_000;
    /// Grants on one collection.
    pub const GRANTS_PER_COLLECTION: usize = 1_000;
    /// A sealed name.
    pub const SEALED_NAME_MAX: usize = 4_096;
    /// The smallest a sealed name can be: nonce, tag and the envelope's header.
    pub const SEALED_NAME_MIN: usize = 28;
    /// A sealed key box.
    pub const BOX_LEN: usize = 1_661;
}
