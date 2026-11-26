//! Kemlock Server federation: servers that pair into a federation and copy chosen vaults between
//! them as ciphertext.
//!
//! The byte formats two implementations must agree on are in `docs/federation.md`; this crate
//! implements them over `kemlock-crypto` and checks them against `test-vectors/federation-*.json`.
//!
//! - [`descriptor`]: the signed descriptor a server publishes (identity key, KEM key, suites).
//! - [`suite`]: the three cipher suites and how two servers pick one.
//! - [`handshake`]: the signed hello and reply, the transcript and the session keys.
//! - [`frame`]: sealed frames with replay, drop, reorder and truncation protection, padding and
//!   rekeying.
//! - [`pairing`]: CPace pairing with a one-time code and the six-word fingerprint.
//! - [`change`], [`conflict`]: origin-signed change records and merging concurrent versions into
//!   siblings.
//! - [`home`]: home epochs, signed promotions and the fence around home-only writes.
//! - [`hashtree`], [`message`], [`replicate`], [`session`]: replication between peers.
//! - [`ports`], [`extra`]: what federation needs from storage; [`memory`] is the in-memory fake.
//! - [`job`], [`net`]: the replication job per peer and the WebSocket client it opens sessions with.
//! - [`hub`], [`admin`], [`consent`], [`members`], [`blobs`], [`erasure`]: pairing as two admin
//!   consoles drive it, the admin facade, consent to a vault and member accounts, attachments, and
//!   an erasure reaching the replicas.
//! - [`spaces`], [`eventsync`], [`forget`], [`keyrecs`], [`relay`], [`tagsync`]: what travels beside
//!   the items: a space's roles, policies and keys as home records, the event logs behind the two
//!   per-peer switches, unpairing that asks the peer to delete, signed identity-key rotation and
//!   revocation, relaying across a chain of pairings, and duplicate tags.
//!
//! Everything but [`session`]'s transports is sans-IO: bytes and the time go in, bytes and values
//! come out.

pub mod addr;
pub mod admin;
pub mod blobs;
pub mod cbor;
pub mod chain;
pub mod change;
pub mod conflict;
pub mod consent;
pub mod crypto;
pub mod descriptor;
pub mod erasure;
pub mod error;
pub mod eventsync;
pub mod extra;
pub mod forget;
pub mod frame;
pub mod handshake;
pub mod hashtree;
pub mod health;
pub mod home;
pub mod hub;
pub mod identity;
pub mod insight;
pub mod job;
pub mod keyrecs;
pub mod members;
pub mod memory;
pub mod message;
pub mod net;
pub mod outbox;
pub mod pairing;
pub mod ports;
mod publish;
pub mod relay;
pub mod replicate;
pub mod sendsync;
pub mod session;
pub mod signed;
pub mod spaces;
pub mod suite;
pub mod tagsync;
#[doc(hidden)]
pub mod testing;
#[cfg(any(test, feature = "vectors"))]
#[doc(hidden)]
pub mod vectors;
pub mod wire;

pub use admin::{
    DescriptorSource, Federation, KeyChange, MismatchView, PausedVault, PeerActivity, PeerCheck,
    PeerConsistency, PeerSecurityView, PeerView, Reach, SelfView, ServerProfile, SuiteRow,
    SuiteSetting, UnpairReport, VaultComparison, VaultView, Waiting,
};
pub use descriptor::{Descriptor, SignedDescriptor};
pub use error::{FedError, Result};
pub use extra::{BlobSync, ErasureOutbox, FedAdminRepo, Leases, MemberStore, VaultErasure};
pub use frame::{FrameReader, FrameWriter, Padding};
pub use handshake::{Initiator, NonceCache, Session, respond};
pub use health::{HealthConfig, HealthStatus, PeerHealth};
pub use hub::{HttpLink, PairingLink, Pairings};
pub use identity::{DescriptorParams, KemPair, KeyDirectory, LocalIdentity};
pub use job::{Connector, PeerRunner};
pub use net::WsConnector;
pub use replicate::{Channel, FedStore, Replica};
pub use session::{SecureChannel, SessionServer, Transport, unix_now};
pub use suite::Suite;
