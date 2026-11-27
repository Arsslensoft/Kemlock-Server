//! The ports the attachment use cases call: blob storage and the attachment table.
//!
//! Like the ports in `crate::ports`, async methods are written as
//! `fn … -> impl Future<Output = …> + Send` so implementers can use `async fn`, and every method
//! is cancel-safe.

use crate::ports::StoreError;
use crate::quota::{QuotaRefusal, check};
use bytes::Bytes;
use futures_core::Stream;
use kemlock_domain::{Attachment, AttachmentId, BlobId, Owner};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use time::OffsetDateTime;

/// Why blob storage refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    #[error("blob not found")]
    NotFound,
    /// More bytes than the upload was allowed.
    #[error("the upload is larger than allowed")]
    TooLarge,
    /// The bytes can't be a `KMA1` file; the text says which rule they break.
    #[error("not a KMA1 file: {0}")]
    NotKma1(&'static str),
    /// A stored blob is not the size the attachment announced.
    #[error("the blob is not the size announced")]
    WrongSize,
    /// The storage failed; the message is for logs, never for clients.
    #[error("blob storage failure: {0}")]
    Backend(String),
}

/// A blob's bytes as they are read: in order, each chunk small enough to hold.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, BlobError>> + Send>>;

/// A blob opened for reading.
pub struct BlobRead {
    /// The blob's size in bytes: the length of `body`.
    pub size: u64,
    pub body: ByteStream,
}

impl fmt::Debug for BlobRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobRead")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// A URL that reaches blob storage directly, for a limited time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresignedUrl {
    pub url: String,
    pub expires_in: Duration,
}

/// One upload in progress. Dropping it without `finish` leaves no blob behind.
pub trait BlobUpload: Send {
    /// Appends the next bytes. Fails with `TooLarge` past the size cap and `NotKma1` as soon as
    /// the first bytes can't be a `KMA1` header.
    fn write(&mut self, chunk: Bytes) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// Makes the blob visible, after checking that its length is one `KMA1` chunks make. Returns
    /// the blob's size. Cleans up after itself when it fails.
    fn finish(self) -> impl Future<Output = Result<u64, BlobError>> + Send;

    /// Throws the bytes written away.
    fn abort(self) -> impl Future<Output = ()> + Send;
}

/// Where attachment bytes live: a local folder or an S3-compatible bucket, under random blob ids,
/// never file names. Implemented by `kemlock-blob`.
pub trait BlobStore: Send + Sync {
    type Upload: BlobUpload;

    /// Starts an upload of at most `max_size` bytes to `blob`. The upload refuses what can't be a
    /// `KMA1` file; the server never decrypts, so this is the header and length rules only.
    fn begin(
        &self,
        blob: BlobId,
        max_size: u64,
    ) -> impl Future<Output = Result<Self::Upload, BlobError>> + Send;

    /// Opens `blob` for reading, whole.
    fn open(&self, blob: BlobId) -> impl Future<Output = Result<BlobRead, BlobError>> + Send;

    /// Checks a blob that was written some other way (a pre-signed upload): it must be
    /// `expected` bytes, start with a `KMA1` header and have a length chunks make. `NotFound`
    /// when nothing is stored; `WrongSize` and `NotKma1` otherwise. A store whose pre-signed URLs
    /// name a staging object checks that and moves it to the blob's own name here, so a later
    /// `PUT` to the URL can't change the blob (see `kemlock-blob`).
    fn verify(
        &self,
        blob: BlobId,
        expected: u64,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// Deletes `blob`. A blob that is already gone is not an error.
    fn delete(&self, blob: BlobId) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// A URL the client may `PUT` the file to directly, or `None` when pre-signed URLs are off or
    /// the storage can't make them (a local folder).
    fn presigned_upload(
        &self,
        blob: BlobId,
    ) -> impl Future<Output = Result<Option<PresignedUrl>, BlobError>> + Send;

    /// A URL the client may `GET` the file from directly, or `None` as above.
    fn presigned_download(
        &self,
        blob: BlobId,
    ) -> impl Future<Output = Result<Option<PresignedUrl>, BlobError>> + Send;

    /// [`presigned_upload`](Self::presigned_upload) for a file of exactly `size` bytes: a store
    /// that can sign the length into the URL does, so what the URL accepts is bounded by what the
    /// upload announced. The default is the unsized URL.
    fn presigned_upload_sized(
        &self,
        blob: BlobId,
        size: u64,
    ) -> impl Future<Output = Result<Option<PresignedUrl>, BlobError>> + Send {
        let _ = size;
        self.presigned_upload(blob)
    }

    /// Removes what pre-signed uploads left behind that no upload still waits for: objects under
    /// the staging name older than `older_than`. Returns how many went. A store with no staging
    /// area has none.
    fn purge_staging(
        &self,
        older_than: std::time::Duration,
    ) -> impl Future<Output = Result<u64, BlobError>> + Send {
        let _ = older_than;
        async { Ok(0) }
    }
}

/// The request body of an upload, read chunk by chunk.
pub trait BodySource: Send {
    /// The next chunk, or `None` at the end of the body.
    fn next_chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, BodyError>> + Send;
}

/// The body broke off: the client went away or sent something that isn't a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the request body failed")]
pub struct BodyError;

pub trait AttachmentRepo: Send + Sync {
    /// Stores a new attachment; `Duplicate` when the id is taken.
    fn add(&self, attachment: &Attachment) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn by_id(
        &self,
        id: AttachmentId,
    ) -> impl Future<Output = Result<Option<Attachment>, StoreError>> + Send;

    /// Marks a pending attachment ready. `false` when it is gone or was ready already, which is
    /// how two uploads of one file are told apart.
    fn mark_ready(&self, id: AttachmentId)
    -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Deletes the row. A row that is already gone is not an error.
    fn remove(&self, id: AttachmentId) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores a new attachment when the owner's attachments, pending ones included, plus its size
    /// fit `limit` (see [`check`]); otherwise stores nothing and says why. A store makes the sum and
    /// the insert one step, so announces that arrive together can't each see room that only one of
    /// them may take. The provided method does them one after the other, which only a store with
    /// no concurrent callers may use.
    fn add_within_quota(
        &self,
        attachment: &Attachment,
        limit: Option<u64>,
    ) -> impl Future<Output = Result<Result<(), QuotaRefusal>, StoreError>> + Send {
        async move {
            if limit.is_some() {
                let used = self.attachment_bytes(attachment.owner).await?;
                if let Err(refusal) = check(limit, used, attachment.size) {
                    return Ok(Err(refusal));
                }
            }
            self.add(attachment).await?;
            Ok(Ok(()))
        }
    }

    /// The bytes the owner's attachments take, pending ones included (the size each announced),
    /// for the storage quota. A store that can't add them up says 0, which leaves no quota to
    /// hold anyone to.
    fn attachment_bytes(
        &self,
        owner: Owner,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let _ = owner;
        async { Ok(0) }
    }

    /// Attachments created before `before` that no item will ever name: those whose item no
    /// longer exists (its tombstone was purged) and those still pending (an abandoned upload).
    /// At most `limit`, oldest first.
    fn orphans(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Attachment>, StoreError>> + Send;
}
