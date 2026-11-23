//! Attachments: files attached to an item, as `KMA1` bytes the server stores but can't read.
//!
//! An upload takes three steps, one use case each: [`StartUpload`] checks the actor may write
//! the item and the size is within the limit, records a pending attachment and hands back its
//! id (and, with pre-signed URLs on, a bucket URL); [`UploadBytes`] streams the body into blob
//! storage, which refuses bytes that don't start like a `KMA1` file; [`FinishUpload`] settles a
//! file that went to the bucket directly. [`Download`] and [`DeleteFile`] read and remove one,
//! and [`PurgeOrphans`] removes what no item names any more.
//!
//! An attachment belongs to an item revision: after uploading, the client writes the item with
//! the attachment's id inside its (sealed) JSON, so devices learn of it through the item's own
//! change. Nothing here touches the change log.
//!
//! The item need not exist when the upload starts, because the client may attach before it first
//! syncs the item; when it does exist it must be the actor's and not a tombstone.

pub mod delete;
pub mod download;
pub mod finish_upload;
pub mod ports;
pub mod purge;
pub mod start_upload;
pub mod upload_bytes;

pub use delete::DeleteFile;
pub use download::{Download, Downloaded};
pub use finish_upload::FinishUpload;
pub use ports::{
    AttachmentRepo, BlobError, BlobRead, BlobStore, BlobUpload, BodyError, BodySource, ByteStream,
    PresignedUrl,
};
pub use purge::PurgeOrphans;
pub use start_upload::{StartUpload, Started};
pub use upload_bytes::UploadBytes;

use crate::authenticate::Actor;
use crate::ports::{ItemStore, StoreError};
use crate::quota::QuotaRefusal;
use kemlock_domain::attachment::may_write;
use kemlock_domain::{Attachment, AttachmentError, AttachmentId, AttachmentLimits, ItemId, Owner};
use time::Duration;

/// Settings the attachment use cases read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesConfig {
    /// The size limit on one file (100 MiB by default).
    pub limits: AttachmentLimits,
    /// How long an attachment no item names, or an upload that never finished, is kept before
    /// [`PurgeOrphans`] removes it. A new item is written after its files are uploaded, so this
    /// must be longer than any upload takes.
    pub orphan_grace: Duration,
    /// The most bytes of attachments an account may keep, `None` for no limit and `Some(0)` for
    /// none allowed (Vaultwarden's `USER_ATTACHMENT_LIMIT`, in bytes).
    pub user_quota: Option<u64>,
    /// The same for a space (`ORG_ATTACHMENT_LIMIT`).
    pub space_quota: Option<u64>,
}

impl Default for FilesConfig {
    fn default() -> Self {
        FilesConfig {
            limits: AttachmentLimits::default(),
            orphan_grace: Duration::hours(24),
            user_quota: None,
            space_quota: None,
        }
    }
}

/// What an attachment use case can fail with. The API layer maps each variant to a status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// The request is well-formed but breaks a rule; the text says which.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    #[error("the file is larger than this server allows")]
    TooLarge,
    /// The owner's attachment quota refuses the file.
    #[error("the attachment quota refuses the file")]
    Quota(QuotaRefusal),
    /// The bytes can't be a `KMA1` file.
    #[error("the file isn't a KMA1 file: {0}")]
    NotKma1(&'static str),
    /// The body isn't as long as the size announced when the upload started.
    #[error("the body isn't the size announced")]
    LengthMismatch,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("the file was uploaded already")]
    AlreadyUploaded,
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

impl From<StoreError> for FileError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => FileError::NotFound,
            StoreError::Duplicate => FileError::AlreadyUploaded,
            other => FileError::Store(other.to_string()),
        }
    }
}

impl From<BlobError> for FileError {
    fn from(e: BlobError) -> Self {
        match e {
            BlobError::NotFound => FileError::NotFound,
            BlobError::TooLarge => FileError::TooLarge,
            BlobError::NotKma1(why) => FileError::NotKma1(why),
            BlobError::WrongSize => FileError::LengthMismatch,
            BlobError::Backend(message) => FileError::Blob(message),
        }
    }
}

impl From<AttachmentError> for FileError {
    fn from(e: AttachmentError) -> Self {
        match e {
            AttachmentError::TooLarge => FileError::TooLarge,
            AttachmentError::Empty => FileError::Invalid("the file is empty"),
            AttachmentError::Forbidden => FileError::Forbidden,
        }
    }
}

/// Who owns what `item` will hold: the stored item's owner when it exists, else the actor's own
/// vault. A tombstone has no files (`NotFound`); another account's item is `Forbidden`.
pub(crate) async fn item_owner<I: ItemStore>(
    items: &I,
    actor: &Actor,
    item: ItemId,
) -> Result<Owner, FileError> {
    match items.get(item).await? {
        None => Ok(Owner::User(actor.user)),
        Some(stored) if stored.is_tombstone() => Err(FileError::NotFound),
        Some(stored) if may_write(stored.owner, actor.user) => Ok(stored.owner),
        Some(_) => Err(FileError::Forbidden),
    }
}

/// The attachment `file` of `item` as `actor` may reach it. One that doesn't exist, belongs to
/// another item or to another account is the same `NotFound`, so ids can't be probed.
pub(crate) async fn own_attachment<A: AttachmentRepo>(
    attachments: &A,
    actor: &Actor,
    item: ItemId,
    file: AttachmentId,
) -> Result<Attachment, FileError> {
    match attachments.by_id(file).await? {
        Some(found) if found.item == item && may_write(found.owner, actor.user) => Ok(found),
        _ => Err(FileError::NotFound),
    }
}
