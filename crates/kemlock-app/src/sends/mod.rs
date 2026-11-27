//! Sends: a note or a file shared by a link, opened by anyone who has the link.
//!
//! The owner's use cases ([`CreateSend`], [`UpdateSend`], [`ListSends`], [`GetSend`],
//! [`DeleteSend`], [`UploadSendFile`]) run as an authenticated account. [`AccessSend`] is the
//! public one: it takes the access id from the link and, if the Send has a password, a proof of it,
//! and answers with ciphertext only. The key never reaches the server: it is in the link's
//! fragment, which browsers keep to themselves. [`PurgeSends`] is the job that deletes Sends
//! whose date has come.
//!
//! The Bitwarden layer calls the same use cases; see [`ports`].
//!
//! **Password.** A Send with a password keeps a salted HMAC-SHA-256 of a value the client derived
//! from it (a client-side stretch of the password bound to the Send's key), so the server never
//! sees the password and a copy of the database can't be replayed as an access. Wrong tries are
//! counted by the API layer, 10 a minute per Send.
//!
//! **View count.** A note counts a view when it is opened. A file Send's description can be read
//! as often as the recipient likes; the download counts, so a Send limited to one view can still
//! be read before it is downloaded.

pub mod access;
pub mod create;
pub mod erase;
pub mod expire;
pub mod manage;
pub mod ports;
pub mod upload;

pub use access::{AccessSend, Accessed, SendDownload};
pub use create::{CreateSend, CreateSendInput, UpdateSend, UpdateSendInput};
pub use erase::EraseSends;
pub use expire::PurgeSends;
pub use manage::{DeleteSend, GetSend, ListSends};
pub use ports::{NoSendPolicies, SendBlobs, SendPolicies, SendRepo, SendRules, file_send_bytes};
pub use upload::UploadSendFile;

use crate::authenticate::Actor;
use crate::b64url;
use crate::files::BlobError;
use crate::platform::{Hasher, Platform};
use crate::ports::{Event, EventLog, StoreError};
use crate::quota::QuotaRefusal;
use kemlock_domain::sends::{
    PASSWORD_HASH_LEN, PASSWORD_SALT_LEN, SendError, SendId, SendPassword, SendRecord,
    check_password_proof,
};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The settings the Send use cases read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendsConfig {
    pub limits: kemlock_domain::sends::SendLimits,
    /// How long a file Send whose bytes never arrived is kept before [`PurgeSends`] removes it.
    pub abandoned_after: Duration,
    /// The most bytes of file Sends one account may keep, `None` for no limit and `Some(0)` for
    /// none allowed (Vaultwarden's `USER_SEND_LIMIT`, in bytes).
    pub quota: Option<u64>,
}

impl Default for SendsConfig {
    fn default() -> Self {
        SendsConfig {
            limits: kemlock_domain::sends::SendLimits::default(),
            abandoned_after: Duration::hours(24),
            quota: None,
        }
    }
}

/// What a Send use case can fail with. The API layer maps each variant to a status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendsError {
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    #[error("the file is larger than this server allows")]
    TooLarge,
    /// The owner's file Send quota refuses the file.
    #[error("the file Send quota refuses the file")]
    Quota(QuotaRefusal),
    /// No such Send for this caller, or one that is closed (expired, deleted, switched off or out
    /// of views). A recipient can't tell which.
    #[error("not found")]
    NotFound,
    /// A policy of one of the owner's spaces refuses it; the text says which.
    #[error("{0}")]
    Policy(&'static str),
    /// The Send has a password and none was given.
    #[error("this Send needs a password")]
    PasswordRequired,
    #[error("wrong password")]
    WrongPassword,
    #[error("already exists")]
    Duplicate,
    /// The account replaced its keys after the client sealed this: it unlocks again and redoes it.
    #[error("the account's key version is {current}")]
    StaleKeyVersion { current: u32 },
    #[error("the file was uploaded already")]
    AlreadyUploaded,
    /// The body isn't as long as the size announced.
    #[error("the body isn't the size announced")]
    LengthMismatch,
    /// The bytes can't be a `KMA1` file.
    #[error("the file isn't a KMA1 file: {0}")]
    NotKma1(&'static str),
    /// The body broke off before its end.
    #[error("the upload was interrupted")]
    Interrupted,
    /// The database failed; the message is for logs only.
    #[error("store failure: {0}")]
    Store(String),
    /// Blob storage failed; the message is for logs only.
    #[error("file storage failure: {0}")]
    Blob(String),
}

impl From<StoreError> for SendsError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => SendsError::NotFound,
            StoreError::Duplicate => SendsError::Duplicate,
            StoreError::StaleKeyVersion { current } => SendsError::StaleKeyVersion { current },
            other => SendsError::Store(other.to_string()),
        }
    }
}

impl From<BlobError> for SendsError {
    fn from(e: BlobError) -> Self {
        match e {
            BlobError::NotFound => SendsError::NotFound,
            BlobError::TooLarge => SendsError::TooLarge,
            BlobError::NotKma1(why) => SendsError::NotKma1(why),
            BlobError::WrongSize => SendsError::LengthMismatch,
            BlobError::Backend(message) => SendsError::Blob(message),
        }
    }
}

impl From<SendError> for SendsError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::Invalid(why) => SendsError::Invalid(why),
            SendError::TooLarge => SendsError::TooLarge,
        }
    }
}

/// The access id a Send's link carries: its id's 16 bytes in unpadded base64url, as Bitwarden and
/// Vaultwarden write it, so links made by either server read alike.
pub fn access_id(id: SendId) -> String {
    b64url::encode(id.as_bytes())
}

/// The Send an access id names, or `None` for anything that isn't an access id.
pub fn parse_access_id(text: &str) -> Option<SendId> {
    let bytes = b64url::decode(text)?;
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    Some(SendId(Uuid::from_bytes(bytes)))
}

/// The salted hash a Send keeps of a password proof.
pub fn hash_proof<H: Hasher>(hasher: &H, salt: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut message = b"kemlock/v1/send-password".to_vec();
    message.extend_from_slice(proof);
    hasher.hmac_sha256(salt, &message).to_vec()
}

/// A new password from the client's derived proof, with a random salt.
pub fn new_password<E: Platform>(env: &E, proof: &[u8]) -> Result<SendPassword, SendsError> {
    check_password_proof(proof)?;
    let salt = env.bytes::<PASSWORD_SALT_LEN>();
    let hash = hash_proof(env, &salt, proof);
    debug_assert_eq!(hash.len(), PASSWORD_HASH_LEN);
    Ok(SendPassword {
        salt: salt.to_vec(),
        hash,
    })
}

/// Whether `proof` is the proof `password` was made from, compared in constant time.
pub fn proof_matches<H: Hasher>(hasher: &H, password: &SendPassword, proof: &[u8]) -> bool {
    if proof.is_empty() || proof.len() > kemlock_domain::sends::MAX_PASSWORD_PROOF_LEN {
        return false;
    }
    let candidate = hash_proof(hasher, &password.salt, proof);
    bool::from(candidate.ct_eq(&password.hash))
}

/// Records an event; a failure to record is logged, never returned, as in the other use cases.
pub(crate) async fn record<V: EventLog>(
    events: &V,
    actor: &Actor,
    action: &'static str,
    send: SendId,
    at: OffsetDateTime,
) {
    let event = Event {
        actor: Some(actor.user),
        device: Some(actor.device),
        action,
        target: Some(send.to_string()),
        at,
    };
    if let Err(e) = events.record(event).await {
        tracing::warn!(action, error = %e, "couldn't record a Send event");
    }
}

/// An account's own Send. Another account's Send and one that doesn't exist are the same
/// `NotFound`, so ids can't be probed.
pub(crate) async fn own_send<S: SendRepo>(
    sends: &S,
    actor: &Actor,
    id: SendId,
) -> Result<SendRecord, SendsError> {
    match sends.send_by_id(id).await? {
        Some(send) if send.owner == actor.user => Ok(send),
        _ => Err(SendsError::NotFound),
    }
}
