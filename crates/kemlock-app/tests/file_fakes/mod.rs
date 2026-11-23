//! In-memory fakes for the attachment ports. Included with `mod file_fakes;` (the router tests
//! reach it with `#[path]`).
//!
//! `FakeBlobs` keeps to the contract of a real blob store, which `kemlock-blob` tests against the
//! app's fixtures: a size cap, a `KMA1` magic check as bytes arrive, and a length check at the
//! end.
#![allow(dead_code, unused_imports)]

use bytes::Bytes;
use futures_util::StreamExt;
use kemlock_app::files::{
    AttachmentRepo, BlobError, BlobRead, BlobStore, BlobUpload, BodyError, BodySource, PresignedUrl,
};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, BlobId, ItemId, Owner};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use time::OffsetDateTime;

/// The shortest `KMA1` file: a header and one tag.
pub(crate) const MIN_KMA1: usize = 28;

/// `len` bytes that start like a `KMA1` file.
pub(crate) fn kma1_bytes(len: usize) -> Vec<u8> {
    assert!(len >= MIN_KMA1, "a KMA1 file is at least {MIN_KMA1} bytes");
    let mut bytes = b"KMA1".to_vec();
    bytes.extend((0..len - 4).map(|i| (i % 251) as u8));
    bytes
}

// ---------------------------------------------------------------------------------------------
// Blob storage.

#[derive(Default)]
struct BlobsInner {
    blobs: HashMap<BlobId, Vec<u8>>,
    presign: bool,
    fail_deletes: bool,
}

#[derive(Clone, Default)]
pub(crate) struct FakeBlobs {
    inner: Arc<Mutex<BlobsInner>>,
}

impl FakeBlobs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A store that hands out pre-signed URLs, as one on a bucket does.
    pub(crate) fn presigning() -> Self {
        let blobs = Self::default();
        blobs.lock().presign = true;
        blobs
    }

    fn lock(&self) -> MutexGuard<'_, BlobsInner> {
        self.inner.lock().expect("the blob lock isn't poisoned")
    }

    pub(crate) fn get(&self, blob: BlobId) -> Option<Vec<u8>> {
        self.lock().blobs.get(&blob).cloned()
    }

    pub(crate) fn count(&self) -> usize {
        self.lock().blobs.len()
    }

    /// Stores bytes as a client's direct upload to the bucket would.
    pub(crate) fn put_directly(&self, blob: BlobId, bytes: Vec<u8>) {
        self.lock().blobs.insert(blob, bytes);
    }

    pub(crate) fn fail_deletes(&self) {
        self.lock().fail_deletes = true;
    }
}

pub(crate) struct FakeUpload {
    blobs: FakeBlobs,
    blob: BlobId,
    max: u64,
    buffer: Vec<u8>,
}

fn check_magic(bytes: &[u8]) -> Result<(), BlobError> {
    let seen = bytes.len().min(4);
    if bytes[..seen] == b"KMA1"[..seen] {
        Ok(())
    } else {
        Err(BlobError::NotKma1("doesn't start with KMA1"))
    }
}

impl BlobUpload for FakeUpload {
    async fn write(&mut self, chunk: Bytes) -> Result<(), BlobError> {
        if self.buffer.len() as u64 + chunk.len() as u64 > self.max {
            return Err(BlobError::TooLarge);
        }
        self.buffer.extend_from_slice(&chunk);
        check_magic(&self.buffer)
    }

    async fn finish(self) -> Result<u64, BlobError> {
        if self.buffer.len() < MIN_KMA1 {
            return Err(BlobError::NotKma1("shorter than a header and a tag"));
        }
        let size = self.buffer.len() as u64;
        self.blobs.lock().blobs.insert(self.blob, self.buffer);
        Ok(size)
    }

    async fn abort(self) {}
}

impl BlobStore for FakeBlobs {
    type Upload = FakeUpload;

    async fn begin(&self, blob: BlobId, max_size: u64) -> Result<FakeUpload, BlobError> {
        Ok(FakeUpload {
            blobs: self.clone(),
            blob,
            max: max_size,
            buffer: Vec::new(),
        })
    }

    async fn open(&self, blob: BlobId) -> Result<BlobRead, BlobError> {
        let bytes = self.get(blob).ok_or(BlobError::NotFound)?;
        let size = bytes.len() as u64;
        // In small pieces, as a real store streams them.
        let pieces: Vec<Result<Bytes, BlobError>> = bytes
            .chunks(7)
            .map(|piece| Ok(Bytes::copy_from_slice(piece)))
            .collect();
        Ok(BlobRead {
            size,
            body: futures_util::stream::iter(pieces).boxed(),
        })
    }

    async fn verify(&self, blob: BlobId, expected: u64) -> Result<(), BlobError> {
        let bytes = self.get(blob).ok_or(BlobError::NotFound)?;
        if bytes.len() as u64 != expected {
            return Err(BlobError::WrongSize);
        }
        check_magic(&bytes)
    }

    async fn delete(&self, blob: BlobId) -> Result<(), BlobError> {
        let mut inner = self.lock();
        if inner.fail_deletes {
            return Err(BlobError::Backend("the disk is full of tears".to_owned()));
        }
        inner.blobs.remove(&blob);
        Ok(())
    }

    async fn presigned_upload(&self, blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        Ok(self.lock().presign.then(|| PresignedUrl {
            url: format!("https://bucket.test/{blob}?put"),
            expires_in: Duration::from_secs(900),
        }))
    }

    async fn presigned_download(&self, blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        Ok(self.lock().presign.then(|| PresignedUrl {
            url: format!("https://bucket.test/{blob}?get"),
            expires_in: Duration::from_secs(900),
        }))
    }
}

// ---------------------------------------------------------------------------------------------
// The attachment table.

#[derive(Default)]
struct AttachmentsInner {
    rows: HashMap<AttachmentId, Attachment>,
    /// Items whose rows the tombstone purge deleted, as far as the orphan query can tell.
    purged_items: HashSet<ItemId>,
}

#[derive(Clone, Default)]
pub(crate) struct FakeAttachments {
    inner: Arc<Mutex<AttachmentsInner>>,
}

impl FakeAttachments {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, AttachmentsInner> {
        self.inner
            .lock()
            .expect("the attachment lock isn't poisoned")
    }

    pub(crate) fn get(&self, id: AttachmentId) -> Option<Attachment> {
        self.lock().rows.get(&id).cloned()
    }

    pub(crate) fn count(&self) -> usize {
        self.lock().rows.len()
    }

    /// The tombstone purge deleted this item's row.
    pub(crate) fn item_purged(&self, item: ItemId) {
        self.lock().purged_items.insert(item);
    }

    /// Puts a row in as it is, for tests that need one in a given state.
    pub(crate) fn insert(&self, attachment: Attachment) {
        self.lock().rows.insert(attachment.id, attachment);
    }
}

impl AttachmentRepo for FakeAttachments {
    async fn add(&self, attachment: &Attachment) -> Result<(), StoreError> {
        let mut inner = self.lock();
        if inner.rows.contains_key(&attachment.id) {
            return Err(StoreError::Duplicate);
        }
        inner.rows.insert(attachment.id, attachment.clone());
        Ok(())
    }

    async fn by_id(&self, id: AttachmentId) -> Result<Option<Attachment>, StoreError> {
        Ok(self.get(id))
    }

    async fn mark_ready(&self, id: AttachmentId) -> Result<bool, StoreError> {
        let mut inner = self.lock();
        match inner.rows.get_mut(&id) {
            Some(row) if row.status == AttachmentStatus::Pending => {
                row.status = AttachmentStatus::Ready;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn remove(&self, id: AttachmentId) -> Result<(), StoreError> {
        self.lock().rows.remove(&id);
        Ok(())
    }

    async fn attachment_bytes(&self, owner: Owner) -> Result<u64, StoreError> {
        Ok(self
            .lock()
            .rows
            .values()
            .filter(|a| a.owner == owner)
            .map(|a| a.size)
            .sum())
    }

    async fn orphans(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Attachment>, StoreError> {
        let inner = self.lock();
        let mut found: Vec<Attachment> = inner
            .rows
            .values()
            .filter(|a| a.created_at < before)
            .filter(|a| {
                a.status == AttachmentStatus::Pending || inner.purged_items.contains(&a.item)
            })
            .cloned()
            .collect();
        found.sort_by_key(|a| a.created_at);
        found.truncate(limit as usize);
        Ok(found)
    }
}

// ---------------------------------------------------------------------------------------------
// A request body.

/// A body made of the given pieces, ending with an error when asked to.
pub(crate) struct VecBody {
    pieces: VecDeque<Result<Bytes, BodyError>>,
}

impl VecBody {
    /// `bytes` cut into pieces of `piece` bytes.
    pub(crate) fn new(bytes: &[u8], piece: usize) -> Self {
        VecBody {
            pieces: bytes
                .chunks(piece)
                .map(|p| Ok(Bytes::copy_from_slice(p)))
                .collect(),
        }
    }

    /// The client goes away after the pieces so far.
    pub(crate) fn then_breaks(mut self) -> Self {
        self.pieces.push_back(Err(BodyError));
        self
    }
}

impl BodySource for VecBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, BodyError> {
        self.pieces.pop_front().transpose()
    }
}
