//! Attachments travel with a federated vault, by blob id.
//!
//! A replica lists a peer's attachments of a vault (`Blobs`), adds a row for each it lacks and
//! fetches the file in chunks (`Blob`) when it is at most [`ON_DEMAND_THRESHOLD`] (50 MiB). A
//! larger file gets its row only, and its bytes are fetched the first time someone downloads it:
//! [`OnDemandBlobs`] wraps the server's blob store, and when a read finds the blob missing it asks
//! a [`BlobFetcher`] to bring it from a peer first.
//!
//! The server never reads a file: chunks are bytes of a `KMA1` file as stored, and the blob store
//! checks the header and the length when the file is written, as it does for an upload. A chunk of
//! a file is read by opening the blob and skipping to the offset, so a file of N bytes fetched in
//! 2 MiB chunks reads about N²/4 MiB from the store; that is why the first-use limit is high only
//! for files nobody fetches in bulk.

use crate::error::{FedError, Result};
use crate::message::{MAX_BLOB_ENTRIES, MAX_CHUNK, Request, Response};
use crate::replicate::{Channel, FedStore, Replica};
use bytes::Bytes;
use kemlock_app::federation_view::BoxFut;
use kemlock_app::files::{BlobError, BlobRead, BlobStore, BlobUpload, PresignedUrl};
use kemlock_app::sends::SendBlobs;
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, BlobId, Owner, ServerId};
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;

/// Files larger than this are fetched the first time they are used, not with their item.
pub const ON_DEMAND_THRESHOLD: u64 = 50 * 1024 * 1024;
/// The largest file a replica fetches into memory in one go.
pub const MAX_FETCH: u64 = 512 * 1024 * 1024;

/// How this server's blob storage is read and written by federation.
pub trait BlobFiles: Send + Sync {
    /// The size of `blob` and `len` bytes of it from `offset` (fewer at the end).
    fn read_chunk(
        &self,
        blob: BlobId,
        offset: u64,
        len: u32,
    ) -> BoxFut<'_, std::result::Result<(u64, Vec<u8>), BlobError>>;

    /// Whether the blob is stored.
    fn has(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<bool, BlobError>>;

    /// Stores a whole file. The blob store checks it is a `KMA1` file.
    fn store(&self, blob: BlobId, data: Vec<u8>) -> BoxFut<'_, std::result::Result<(), BlobError>>;

    /// Stores a whole file of a format storage can't check, a Bitwarden app's Send file: only its
    /// size is checked. The default checks it as a `KMA1` file.
    fn store_raw(
        &self,
        blob: BlobId,
        data: Vec<u8>,
    ) -> BoxFut<'_, std::result::Result<(), BlobError>> {
        self.store(blob, data)
    }

    /// Deletes a file, for a vault its home erased. One that is already gone is not an error. The
    /// default keeps nothing to delete.
    fn delete(&self, _blob: BlobId) -> BoxFut<'_, std::result::Result<(), BlobError>> {
        Box::pin(async { Ok(()) })
    }
}

/// [`BlobFiles`] over a [`BlobStore`].
#[derive(Clone, Debug)]
pub struct StoreFiles<B>(pub B);

async fn read_range(
    read: BlobRead,
    offset: u64,
    len: u32,
) -> std::result::Result<(u64, Vec<u8>), BlobError> {
    let size = read.size;
    // Nothing is there past the end: say so without streaming the whole file to find out.
    if offset >= size {
        return Ok((size, Vec::new()));
    }
    let mut body = read.body;
    let want = len as usize;
    let mut skipped = 0u64;
    let mut out: Vec<u8> = Vec::with_capacity(want.min(1 << 20));
    while out.len() < want {
        let Some(next) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await else {
            break;
        };
        let chunk = next?;
        let mut part: &[u8] = &chunk;
        if skipped < offset {
            let skip = (offset - skipped).min(part.len() as u64) as usize;
            skipped += skip as u64;
            part = &part[skip..];
        }
        let take = part.len().min(want - out.len());
        out.extend_from_slice(&part[..take]);
    }
    Ok((size, out))
}

impl<B: SendBlobs + 'static> BlobFiles for StoreFiles<B> {
    fn read_chunk(
        &self,
        blob: BlobId,
        offset: u64,
        len: u32,
    ) -> BoxFut<'_, std::result::Result<(u64, Vec<u8>), BlobError>> {
        Box::pin(async move {
            let read = self.0.open(blob).await?;
            read_range(read, offset, len).await
        })
    }

    fn has(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<bool, BlobError>> {
        Box::pin(async move {
            match self.0.open(blob).await {
                Ok(_) => Ok(true),
                Err(BlobError::NotFound) => Ok(false),
                Err(e) => Err(e),
            }
        })
    }

    fn store(&self, blob: BlobId, data: Vec<u8>) -> BoxFut<'_, std::result::Result<(), BlobError>> {
        Box::pin(async move {
            let mut upload = self.0.begin(blob, data.len() as u64).await?;
            if let Err(e) = upload.write(Bytes::from(data)).await {
                upload.abort().await;
                return Err(e);
            }
            upload.finish().await.map(|_| ())
        })
    }

    fn store_raw(
        &self,
        blob: BlobId,
        data: Vec<u8>,
    ) -> BoxFut<'_, std::result::Result<(), BlobError>> {
        Box::pin(async move {
            let mut upload = self.0.begin_raw(blob, data.len() as u64).await?;
            if let Err(e) = upload.write(Bytes::from(data)).await {
                upload.abort().await;
                return Err(e);
            }
            upload.finish().await.map(|_| ())
        })
    }

    fn delete(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<(), BlobError>> {
        Box::pin(async move {
            match self.0.delete(blob).await {
                Ok(()) | Err(BlobError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

/// Brings a file this server holds a row for but not the bytes of from a peer.
pub trait BlobFetcher: Send + Sync {
    fn fetch(&self, blob: BlobId) -> BoxFut<'_, std::result::Result<(), BlobError>>;
}

/// A blob store that fetches a missing file from a peer the first time it is read.
#[derive(Clone)]
pub struct OnDemandBlobs<B> {
    inner: B,
    fetcher: Arc<dyn BlobFetcher>,
}

impl<B> std::fmt::Debug for OnDemandBlobs<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandBlobs").finish_non_exhaustive()
    }
}

impl<B: BlobStore> OnDemandBlobs<B> {
    pub fn new(inner: B, fetcher: Arc<dyn BlobFetcher>) -> OnDemandBlobs<B> {
        OnDemandBlobs { inner, fetcher }
    }
}

impl<B: BlobStore> BlobStore for OnDemandBlobs<B> {
    type Upload = B::Upload;

    async fn begin(
        &self,
        blob: BlobId,
        max_size: u64,
    ) -> std::result::Result<B::Upload, BlobError> {
        self.inner.begin(blob, max_size).await
    }

    async fn open(&self, blob: BlobId) -> std::result::Result<BlobRead, BlobError> {
        match self.inner.open(blob).await {
            Err(BlobError::NotFound) => {
                self.fetcher.fetch(blob).await?;
                self.inner.open(blob).await
            }
            other => other,
        }
    }

    async fn verify(&self, blob: BlobId, expected: u64) -> std::result::Result<(), BlobError> {
        self.inner.verify(blob, expected).await
    }

    async fn delete(&self, blob: BlobId) -> std::result::Result<(), BlobError> {
        self.inner.delete(blob).await
    }

    async fn presigned_upload(
        &self,
        blob: BlobId,
    ) -> std::result::Result<Option<PresignedUrl>, BlobError> {
        self.inner.presigned_upload(blob).await
    }

    /// A direct bucket URL only for a file that is already here: a missing one is fetched by the
    /// streamed download, which goes through [`open`](Self::open).
    async fn presigned_download(
        &self,
        blob: BlobId,
    ) -> std::result::Result<Option<PresignedUrl>, BlobError> {
        match self.inner.open(blob).await {
            Ok(_) => self.inner.presigned_download(blob).await,
            Err(BlobError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// What [`Replica::sync_blobs`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobReport {
    /// Rows added for attachments we hadn't heard of.
    pub rows: usize,
    /// Files fetched.
    pub fetched: usize,
    /// Files left for their first use, because they are over the threshold.
    pub deferred: usize,
    /// Entries left out: an item this vault doesn't hold, or a file another row already holds.
    pub skipped: usize,
    /// The listing stopped (its pages or its time ran out) before the end: the rest comes at the
    /// next visit, from where it stopped.
    pub unfinished: bool,
}

fn blob_error(e: &BlobError) -> FedError {
    tracing::warn!(error = %e, "blob storage failed during replication");
    FedError::Store("blob storage failed".to_owned())
}

impl<S: FedStore> Replica<S> {
    /// Serves a page of the attachments of `vault` to `peer`.
    pub(crate) async fn serve_blob_list(
        &self,
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    ) -> Result<Response> {
        let rows = self
            .store
            .attachments_after(
                vault,
                AttachmentId(uuid::Uuid::from_bytes(after)),
                limit.min(MAX_BLOB_ENTRIES as u32).saturating_add(1),
            )
            .await?;
        let page = limit.min(MAX_BLOB_ENTRIES as u32) as usize;
        let more = rows.len() > page;
        let entries = rows
            .into_iter()
            .take(page)
            .map(|a| crate::message::BlobEntry {
                attachment: a.id,
                item: a.item,
                blob: a.blob,
                size: a.size,
            })
            .collect();
        Ok(Response::Blobs {
            vault,
            entries,
            more,
        })
    }

    /// Serves a chunk of one file of `vault`.
    ///
    /// The store has no ranged read, so a chunk at `offset` makes it read `offset` plus the chunk
    /// from the start of the file: what a peer asks for is counted at that cost
    /// ([`WorkLimits`](crate::quota::WorkLimits)), and an offset no file this server fetches
    /// reaches is refused.
    pub(crate) async fn serve_blob_chunk(
        &self,
        peer: ServerId,
        vault: Owner,
        blob: BlobId,
        offset: u64,
        len: u32,
        now: u64,
    ) -> Result<Response> {
        let files = self
            .files
            .as_ref()
            .ok_or(FedError::Refused("this server doesn't serve files"))?;
        if offset >= MAX_FETCH {
            return Err(FedError::Refused("an offset past any file this server serves"));
        }
        let cost = offset.saturating_add(u64::from(len.min(MAX_CHUNK)));
        if !self
            .work
            .allow_blob_read(&self.work_limits, peer, cost, now)
        {
            return Err(FedError::Refused("too much of this server's storage was read for this peer: try later"));
        }
        let held = match self
            .store
            .attachment_of_blob(blob)
            .await?
            .filter(|a| a.owner == vault && a.is_ready())
        {
            Some(attachment) => attachment.blob,
            // The file of a Send of the vault's owner, whose bytes have arrived.
            None => self
                .store
                .send_of_blob(blob)
                .await?
                .filter(|s| Owner::User(s.owner) == vault)
                .and_then(|s| s.file)
                .filter(|f| f.ready)
                .map(|f| f.blob)
                .ok_or(FedError::Refused("no such file"))?,
        };
        let (size, data) = files
            .read_chunk(held, offset, len.min(MAX_CHUNK))
            .await
            .map_err(|e| blob_error(&e))?;
        Ok(Response::BlobChunk {
            vault,
            blob,
            size,
            offset,
            data,
        })
    }

    /// Fetches one file of `vault` from the peer on the other end of `channel` and stores it.
    pub async fn fetch_blob<C: Channel>(
        &self,
        channel: &mut C,
        vault: Owner,
        blob: BlobId,
        size: u64,
    ) -> Result<()> {
        self.fetch_file(channel, vault, blob, size, false).await
    }

    /// [`fetch_blob`](Self::fetch_blob) that gives up when `until` has passed, between two chunks.
    /// False when it did: nothing was stored, and the file is fetched when someone first opens it.
    pub async fn fetch_blob_until<C: Channel>(
        &self,
        channel: &mut C,
        vault: Owner,
        blob: BlobId,
        size: u64,
        until: Instant,
    ) -> Result<bool> {
        self.fetch_file_until(channel, vault, blob, size, false, Some(until))
            .await
    }

    /// As [`fetch_blob`](Self::fetch_blob); `raw` is the file of a Send in a format storage can't
    /// check (a Bitwarden app's), held to its size alone.
    pub(crate) async fn fetch_file<C: Channel>(
        &self,
        channel: &mut C,
        vault: Owner,
        blob: BlobId,
        size: u64,
        raw: bool,
    ) -> Result<()> {
        self.fetch_file_until(channel, vault, blob, size, raw, None)
            .await
            .map(|_| ())
    }

    /// As [`fetch_file`](Self::fetch_file), giving up when `until` (if any) has passed, between
    /// two chunks: false then, with nothing stored.
    pub(crate) async fn fetch_file_until<C: Channel>(
        &self,
        channel: &mut C,
        vault: Owner,
        blob: BlobId,
        size: u64,
        raw: bool,
        until: Option<Instant>,
    ) -> Result<bool> {
        let files = self
            .files
            .as_ref()
            .ok_or(FedError::Refused("this server has no file storage"))?;
        if size == 0 || size > MAX_FETCH {
            return Err(FedError::Refused("the file is too large to fetch"));
        }
        let mut data: Vec<u8> = Vec::with_capacity(size.min(64 * 1024 * 1024) as usize);
        while (data.len() as u64) < size {
            if until.is_some_and(|until| Instant::now() >= until) {
                return Ok(false);
            }
            let offset = data.len() as u64;
            let len = (size - offset).min(u64::from(MAX_CHUNK)) as u32;
            let response = channel
                .call(&Request::Blob {
                    vault,
                    blob,
                    offset,
                    len,
                })
                .await?;
            match response {
                Response::BlobChunk {
                    vault: v,
                    blob: b,
                    size: total,
                    offset: at,
                    data: chunk,
                } if v == vault && b == blob && total == size && at == offset => {
                    if chunk.is_empty() || chunk.len() > len as usize {
                        return Err(FedError::Malformed("a chunk has the wrong length"));
                    }
                    data.extend_from_slice(&chunk);
                }
                Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
                _ => return Err(FedError::Malformed("an unexpected response to a chunk")),
            }
        }
        let stored = if raw {
            files.store_raw(blob, data).await
        } else {
            files.store(blob, data).await
        };
        stored.map_err(|e| blob_error(&e))?;
        Ok(true)
    }

    /// Whether a row of this server, an attachment or a Send, already holds the file `blob`.
    pub(crate) async fn blob_in_use(&self, blob: BlobId) -> Result<bool> {
        Ok(self.store.attachment_of_blob(blob).await?.is_some()
            || self.store.send_of_blob(blob).await?.is_some())
    }

    /// Copies the attachments of `vault` that `peer` holds: a row for each one we lack, and the
    /// file too when it is small enough and we don't have it.
    pub async fn sync_blobs<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<BlobReport> {
        let far = Instant::now() + std::time::Duration::from_secs(60 * 60 * 24);
        self.sync_blobs_until(channel, peer, vault, far).await
    }

    /// [`sync_blobs`](Self::sync_blobs) that stops at `until` (between two files), and keeps where
    /// the listing is, per peer and vault, so the next visit goes on from there: a vault with more
    /// attachments than one visit lists is listed in full over several. A file that couldn't be
    /// fetched before `until` is left for its first use, like a large one.
    pub async fn sync_blobs_until<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
        until: Instant,
    ) -> Result<BlobReport> {
        self.authorize(peer, vault).await?;
        let mut report = BlobReport::default();
        let mut after = self.store.blob_cursor(peer, vault).await?;
        for _ in 0..crate::message::MAX_PAGES_PER_VISIT {
            if Instant::now() >= until {
                report.unfinished = true;
                return Ok(report);
            }
            let response = channel
                .call(&Request::Blobs {
                    vault,
                    after,
                    limit: MAX_BLOB_ENTRIES as u32,
                })
                .await?;
            let (entries, more) = match response {
                Response::Blobs {
                    vault: v,
                    entries,
                    more,
                } if v == vault => (entries, more),
                Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
                _ => return Err(FedError::Malformed("an unexpected response to a file list")),
            };
            let Some(last) = entries.last() else {
                // The end: the next visit lists from the beginning again.
                self.store.set_blob_cursor(peer, vault, [0; 16]).await?;
                return Ok(report);
            };
            // A page that doesn't move past the last one is a peer that says there is more and
            // sends the same again.
            if *last.attachment.0.as_bytes() <= after {
                return Err(FedError::Invalid("the file list does not move forward"));
            }
            after = *last.attachment.0.as_bytes();
            for entry in &entries {
                if let Some(row) = self.store.attachment(entry.attachment).await? {
                    // A row this server already holds says which file it is: what the peer names
                    // is checked against it, never taken. Otherwise a peer that knows an
                    // attachment id could name the file of another row (one still being
                    // uploaded, say) and fill it with bytes of its own.
                    if row.owner != vault
                        || row.item != entry.item
                        || row.blob != entry.blob
                        || row.size != entry.size
                        || !row.is_ready()
                    {
                        tracing::info!(%peer, attachment = ?entry.attachment, "an attachment of a peer didn't match the row this server holds: left out");
                        report.skipped += 1;
                        continue;
                    }
                } else {
                    // The peer says which item the file belongs to and which file it is, and
                    // neither is checked by its signature: the item must be one of this vault's,
                    // and the file one no other row (an attachment, or a Send's) holds, or the
                    // peer could hang a file on an item it doesn't own or make this server
                    // serve, and later delete, a file that belongs to another row.
                    if self
                        .store
                        .export_items(vault, &[entry.item])
                        .await?
                        .is_empty()
                        || self.blob_in_use(entry.blob).await?
                    {
                        tracing::info!(%peer, attachment = ?entry.attachment, "an attachment of a peer was left out: its item isn't this vault's, or its file is another row's");
                        report.skipped += 1;
                        continue;
                    }
                    let added = self
                        .store
                        .add_replicated_attachment(&Attachment {
                            id: entry.attachment,
                            item: entry.item,
                            owner: vault,
                            blob: entry.blob,
                            size: entry.size,
                            status: AttachmentStatus::Ready,
                            created_at: OffsetDateTime::now_utc(),
                        })
                        .await?;
                    if added {
                        report.rows += 1;
                    }
                }
                let present = match &self.files {
                    Some(files) => files.has(entry.blob).await.map_err(|e| blob_error(&e))?,
                    None => true,
                };
                if present {
                    continue;
                }
                if entry.size > ON_DEMAND_THRESHOLD {
                    report.deferred += 1;
                } else if self
                    .fetch_blob_until(channel, vault, entry.blob, entry.size, until)
                    .await?
                {
                    report.fetched += 1;
                } else {
                    // Out of time for it: it is fetched when someone first opens it.
                    report.deferred += 1;
                    report.unfinished = true;
                }
            }
            // The page is done: the next visit goes on after it.
            self.store.set_blob_cursor(peer, vault, after).await?;
            if !more {
                self.store.set_blob_cursor(peer, vault, [0; 16]).await?;
                return Ok(report);
            }
        }
        // The page limit of a visit: the rest comes at the next.
        report.unfinished = true;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_core::Stream;
    use std::pin::Pin;

    fn read_of(chunks: Vec<Vec<u8>>) -> BlobRead {
        struct Chunks(std::vec::IntoIter<Vec<u8>>);
        impl Stream for Chunks {
            type Item = std::result::Result<Bytes, BlobError>;
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Ready(self.0.next().map(|c| Ok(Bytes::from(c))))
            }
        }
        let size = chunks.iter().map(Vec::len).sum::<usize>() as u64;
        BlobRead {
            size,
            body: Box::pin(Chunks(chunks.into_iter())),
        }
    }

    #[tokio::test]
    async fn a_range_is_cut_across_chunk_boundaries() {
        let read = read_of(vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9]]);
        let (size, data) = read_range(read, 3, 5).await.expect("a range");
        assert_eq!(size, 10);
        assert_eq!(data, vec![3, 4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn a_peers_chunk_reads_are_counted_by_what_they_cost_the_store() {
        use crate::memory::MemoryStore;
        use crate::quota::WorkLimits;
        use crate::suite::Suite;
        use crate::testing::{draft, identity};
        use kemlock_domain::{ItemId, UserId};

        /// A store of one 3 MiB file that reads nothing.
        struct OneFile;
        impl BlobFiles for OneFile {
            fn read_chunk(
                &self,
                _blob: BlobId,
                offset: u64,
                len: u32,
            ) -> BoxFut<'_, std::result::Result<(u64, Vec<u8>), BlobError>> {
                let size = 3 * 1024 * 1024u64;
                let end = (offset + u64::from(len)).min(size);
                let data = vec![0u8; usize::try_from(end.saturating_sub(offset)).unwrap_or(0)];
                Box::pin(async move { Ok((size, data)) })
            }
            fn has(&self, _blob: BlobId) -> BoxFut<'_, std::result::Result<bool, BlobError>> {
                Box::pin(async { Ok(true) })
            }
            fn store(
                &self,
                _blob: BlobId,
                _data: Vec<u8>,
            ) -> BoxFut<'_, std::result::Result<(), BlobError>> {
                Box::pin(async { Ok(()) })
            }
        }

        const NOW: u64 = 1_800_000_000;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let peer = ia.server;
        let me = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()))
            .with_blob_files(Arc::new(OneFile))
            .with_work_limits(WorkLimits {
                // Room for the chunks at offsets 0 and 2 MiB (they cost 2 MiB and 4 MiB) and no more.
                blob_bytes_per_window: 6 * 1024 * 1024,
                scans_per_window: 30,
            });
        me.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        me.accept_vault(vault, peer, vec![ib.server])
            .await
            .expect("accept");
        let item = ItemId::random();
        me.store
            .put(draft(item, vault, None, 1, 1_000))
            .expect("an item");
        let blob = BlobId::random();
        me.store.put_attachment(Attachment {
            id: AttachmentId(uuid::Uuid::new_v4()),
            item,
            owner: vault,
            blob,
            size: 3 * 1024 * 1024,
            status: AttachmentStatus::Ready,
            created_at: OffsetDateTime::now_utc(),
        });

        let chunk = |offset: u64| me.serve_blob_chunk(peer, vault, blob, offset, MAX_CHUNK, NOW);
        assert!(chunk(0).await.is_ok());
        assert!(chunk(2 * 1024 * 1024).await.is_ok());
        // The window is used up: the next read, from far into the file, is refused, and so is an
        // offset no file reaches, however much is left.
        assert!(matches!(chunk(2 * 1024 * 1024).await, Err(FedError::Refused(_))));
        assert!(matches!(chunk(MAX_FETCH).await, Err(FedError::Refused(_))));
    }

    #[tokio::test]
    async fn a_range_past_the_end_is_short_or_empty() {
        let read = read_of(vec![vec![1, 2, 3]]);
        let (_, data) = read_range(read, 2, 10).await.expect("a range");
        assert_eq!(data, vec![3]);
        let read = read_of(vec![vec![1, 2, 3]]);
        let (_, data) = read_range(read, 9, 10).await.expect("a range");
        assert!(data.is_empty());
    }
    /// A channel that answers each request with the next canned response.
    struct Canned(Vec<Response>);

    impl Channel for Canned {
        async fn call(&mut self, _request: &Request) -> Result<Response> {
            Ok(self.0.remove(0))
        }
    }

    #[tokio::test]
    async fn a_peers_attachment_must_name_an_item_of_the_vault_and_a_file_no_other_row_holds() {
        use crate::memory::MemoryStore;
        use crate::message::BlobEntry;
        use crate::suite::Suite;
        use crate::testing::{draft, identity};
        use kemlock_domain::{ItemId, UserId};

        const NOW: u64 = 1_800_000_000;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let home = ia.server;
        let me = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        me.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        me.accept_vault(vault, home, vec![ib.server])
            .await
            .expect("accept");
        let item = ItemId::random();
        me.store
            .put(draft(item, vault, None, 1, 1_000))
            .expect("an item");
        // A file another attachment already holds.
        let held_blob = BlobId::random();
        me.store.put_attachment(Attachment {
            id: AttachmentId(uuid::Uuid::new_v4()),
            item,
            owner: vault,
            blob: held_blob,
            size: 10,
            status: AttachmentStatus::Ready,
            created_at: OffsetDateTime::now_utc(),
        });
        let entry = |item: ItemId, blob: BlobId| BlobEntry {
            attachment: AttachmentId(uuid::Uuid::new_v4()),
            item,
            blob,
            size: 10,
        };
        let good = entry(item, BlobId::random());
        let unknown_item = entry(ItemId::random(), BlobId::random());
        let stolen_file = entry(item, held_blob);
        let mut channel = Canned(vec![Response::Blobs {
            vault,
            entries: vec![unknown_item.clone(), stolen_file.clone(), good.clone()],
            more: false,
        }]);

        let report = me
            .sync_blobs(&mut channel, home, vault)
            .await
            .expect("sync");
        assert_eq!((report.rows, report.skipped), (1, 2));
        let held: Vec<AttachmentId> = me.store.attachments().iter().map(|a| a.id).collect();
        assert!(held.contains(&good.attachment));
        assert!(!held.contains(&unknown_item.attachment));
        assert!(!held.contains(&stolen_file.attachment));
    }

    #[tokio::test]
    async fn a_peer_cannot_name_another_file_for_an_attachment_this_server_already_holds() {
        use crate::memory::MemoryStore;
        use crate::message::BlobEntry;
        use crate::suite::Suite;
        use crate::testing::{draft, identity};
        use kemlock_domain::{ItemId, UserId};

        const NOW: u64 = 1_800_000_000;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let home = ia.server;
        let me = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        me.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        me.accept_vault(vault, home, vec![ib.server])
            .await
            .expect("accept");
        let item = ItemId::random();
        me.store
            .put(draft(item, vault, None, 1, 1_000))
            .expect("an item");
        // An upload this server's own user has started: the row is pending and its file not here.
        let pending = Attachment {
            id: AttachmentId(uuid::Uuid::new_v4()),
            item,
            owner: vault,
            blob: BlobId::random(),
            size: 10,
            status: AttachmentStatus::Pending,
            created_at: OffsetDateTime::now_utc(),
        };
        me.store.put_attachment(pending.clone());
        // The peer lists that attachment id (it knows it) with a file it names itself, and again
        // with the row's own file, which is not ready here.
        let other_file = BlobEntry {
            attachment: pending.id,
            item,
            blob: BlobId::random(),
            size: 10,
        };
        let own_file = BlobEntry {
            blob: pending.blob,
            ..other_file.clone()
        };
        let mut channel = Canned(vec![Response::Blobs {
            vault,
            entries: vec![other_file, own_file],
            more: false,
        }]);
        let report = me
            .sync_blobs(&mut channel, home, vault)
            .await
            .expect("sync");
        assert_eq!((report.rows, report.fetched, report.skipped), (0, 0, 2));
    }

    #[tokio::test]
    async fn the_file_list_is_bounded_and_must_move_forward() {
        use crate::extra::BlobSync as _;
        use crate::memory::MemoryStore;
        use crate::message::BlobEntry;
        use crate::suite::Suite;
        use crate::testing::identity;
        use kemlock_domain::{ItemId, UserId};

        const NOW: u64 = 1_800_000_000;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let home = ia.server;
        let me = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        me.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        me.accept_vault(vault, home, vec![ib.server])
            .await
            .expect("accept");
        let entry = |n: u128| BlobEntry {
            attachment: AttachmentId(uuid::Uuid::from_u128(n)),
            item: ItemId::random(),
            blob: BlobId::random(),
            size: 10,
        };

        // A peer that always has one more entry: asked for a bounded number of pages, and the
        // listing says it didn't finish.
        struct Endless {
            calls: u128,
            vault: Owner,
        }
        impl Channel for Endless {
            async fn call(&mut self, _request: &Request) -> Result<Response> {
                self.calls += 1;
                Ok(Response::Blobs {
                    vault: self.vault,
                    entries: vec![BlobEntry {
                        attachment: AttachmentId(uuid::Uuid::from_u128(self.calls)),
                        item: ItemId::random(),
                        blob: BlobId::random(),
                        size: 10,
                    }],
                    more: true,
                })
            }
        }
        let mut endless = Endless { calls: 0, vault };
        let report = me
            .sync_blobs(&mut endless, home, vault)
            .await
            .expect("a bounded listing");
        assert!(report.unfinished);
        assert_eq!(endless.calls, crate::message::MAX_PAGES_PER_VISIT as u128);
        // Where it stopped is kept, so the next visit goes on from there.
        assert_eq!(
            me.store.blob_cursor(home, vault).await,
            Ok(*uuid::Uuid::from_u128(endless.calls).as_bytes())
        );

        // A second page that is not past the first is a peer saying there is more and repeating.
        let same = entry(10_000);
        let mut repeating = Canned(vec![
            Response::Blobs {
                vault,
                entries: vec![same.clone()],
                more: true,
            },
            Response::Blobs {
                vault,
                entries: vec![same],
                more: true,
            },
        ]);
        assert!(matches!(
            me.sync_blobs(&mut repeating, home, vault).await,
            Err(FedError::Invalid(_))
        ));
    }
}
