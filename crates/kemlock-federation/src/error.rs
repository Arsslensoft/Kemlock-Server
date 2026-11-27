//! The one error type of the federation crate.

use kemlock_app::ports::StoreError;

/// Why a federation operation failed. The messages are for logs and the admin console, and none
/// of them says more about a failed check than that it failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FedError {
    /// A message or record that does not parse: wrong length, unknown field, trailing bytes.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// A signature, a key id or a pinned key did not check out.
    #[error("check failed: {0}")]
    Invalid(&'static str),
    /// The peer's identity key is not the one pinned at pairing. `offered` is what it sent, for
    /// the "Possible man in the middle" screen.
    #[error("the peer's identity key does not match the pinned key")]
    KeyMismatch { offered: Vec<u8> },
    /// The peer is not paired with this server.
    #[error("unknown peer")]
    UnknownPeer,
    /// No cipher suite is offered by both sides.
    #[error("no cipher suite in common")]
    NoCommonSuite,
    /// The suite is defined but this build does not implement it.
    #[error("the cipher suite {0} is not available in this build")]
    SuiteUnavailable(String),
    /// A descriptor or timestamp outside its validity window.
    #[error("outside the validity window: {0}")]
    Expired(&'static str),
    /// A handshake nonce seen before.
    #[error("a handshake was replayed")]
    Replay,
    /// A frame that is repeated, dropped, reordered, cut short or changed.
    #[error("bad frame: {0}")]
    Frame(&'static str),
    /// Pairing failed: the code was wrong or a message was changed.
    #[error("pairing failed")]
    Pairing,
    /// The request is not allowed for this peer or in this state.
    #[error("refused: {0}")]
    Refused(&'static str),
    /// An offer of a personal vault whose account this server holds as a copy from another server:
    /// the admin may accept it only as a re-homing. Its own variant so the console can tell it from
    /// the other refusals.
    #[error("refused: this account is a copy that came from another server: accept the offer as a re-homing to make the offering server its home")]
    CopyFromAnotherServer,
    /// This server does not federate that vault (or the peer may not know it exists).
    #[error("unknown vault")]
    UnknownVault,
    /// The peer answered a request with an error.
    #[error("the peer answered with an error: {0}")]
    Remote(String),
    /// A primitive failed.
    #[error("cryptographic failure")]
    Crypto,
    /// The store failed.
    #[error("store: {0}")]
    Store(String),
}

impl From<kemlock_crypto::Error> for FedError {
    fn from(_: kemlock_crypto::Error) -> Self {
        FedError::Crypto
    }
}

impl From<StoreError> for FedError {
    fn from(e: StoreError) -> Self {
        FedError::Store(e.to_string())
    }
}

/// Shorthand for results in this crate.
pub type Result<T> = std::result::Result<T, FedError>;
