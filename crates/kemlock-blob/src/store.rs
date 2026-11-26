//! The `BlobStore` port over the `object_store` crate: a local folder or an S3-compatible bucket.
//!
//! Blobs are named by their random id and nothing else: `ab/abcdef0123…` (the first two hex digits
//! make a folder, so a big install doesn't put millions of files in one). Uploads stream: bytes are
//! gathered into parts of 1 MiB (5 MiB on a bucket, the smallest part S3 takes except for the
//! last) and each part is written before the next is gathered, so a transfer holds one part plus
//! the chunk in hand. A file that fits in one part is written with one plain put. Downloads stream
//! too, in chunks of 256 KiB from a local file.
//!
//! The upload also enforces what the server is able to know about `KMA1` without the key: the
//! size cap, the magic as soon as the first four bytes arrive, and at the end a length that
//! whole chunks make (see [`crate::kma1`]).

use crate::config::{Backend, BlobConfig, S3Config};
use crate::kma1::{self, Kma1Error, StreamCheck};
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use kemlock_app::files::{BlobError, BlobRead, BlobStore, BlobUpload, ByteStream, PresignedUrl};
use kemlock_app::sends::SendBlobs;
use kemlock_domain::BlobId;
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::signer::{Method, Signer};
use object_store::{
    GetOptions, GetResultPayload, MultipartUpload, ObjectStore, PutMultipartOptions, PutOptions,
    PutPayload, PutPayloadMut,
};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// A part of an upload to a local folder.
const LOCAL_PART_SIZE: usize = 1024 * 1024;
/// A part of an upload to a bucket: S3's smallest part other than the last.
const BUCKET_PART_SIZE: usize = 5 * 1024 * 1024;
/// How much of a local file one read takes.
const READ_CHUNK: usize = 256 * 1024;

/// File storage over `object_store`. Cloning is cheap: clones share the store.
#[derive(Clone, Debug)]
pub struct ObjectBlobStore {
    store: Arc<dyn ObjectStore>,
    /// Makes pre-signed URLs; only a bucket has one.
    signer: Option<Arc<dyn Signer>>,
    /// How long pre-signed URLs live, when they are turned on.
    presign_ttl: Option<Duration>,
    part_size: usize,
}

fn backend(e: object_store::Error) -> BlobError {
    match e {
        object_store::Error::NotFound { .. } => BlobError::NotFound,
        other => BlobError::Backend(other.to_string()),
    }
}

fn not_kma1(e: Kma1Error) -> BlobError {
    BlobError::NotKma1(match e {
        Kma1Error::TooShort => "shorter than a KMA1 header and one tag",
        Kma1Error::BadMagic => "doesn't start with KMA1",
        Kma1Error::BadLength => "the length is not that of any sequence of KMA1 chunks",
    })
}

/// Where a blob is kept: `ab/abcdef…`.
fn path_of(blob: BlobId) -> Path {
    let name = blob.to_string();
    Path::from(format!("{}/{name}", &name[..2]))
}

/// Where a pre-signed upload lands: `staging/<blob id>`, never the blob's own path. The signed URL
/// names this and nothing the server serves, so a `PUT` to it after the upload was checked (the URL
/// stays valid for its whole lifetime) can't change the file. `BlobStore::verify` checks
/// what is here and moves it to the blob's own path.
fn staging_path_of(blob: BlobId) -> Path {
    Path::from(format!("staging/{blob}"))
}

/// Where a raw file is kept: its key, a few `/`-separated parts of `[A-Za-z0-9_-]`, such as
/// Vaultwarden's `<cipher id>/<attachment id>`. A key that could leave the folder (`..`, an absolute
/// path, a dot or backslash) is refused. A first part of two hex digits is a folder of blob ids, so
/// it isn't a raw file's.
fn raw_path(key: &str) -> Result<Path, BlobError> {
    let bad = || BlobError::Backend(format!("{key:?} is not a valid file key"));
    let parts: Vec<&str> = key.split('/').collect();
    let clean = |part: &&str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if parts.len() > 4 || !parts.iter().all(clean) {
        return Err(bad());
    }
    if parts[0].len() == 2 && parts[0].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    Ok(Path::from(key))
}

impl ObjectBlobStore {
    /// An upload to `blob` of at most `max_size` bytes, held to the `KMA1` rules when `check` is
    /// given and to the size cap alone otherwise.
    fn upload(&self, blob: BlobId, max_size: u64, check: Option<StreamCheck>) -> ObjectUpload {
        ObjectUpload {
            store: self.store.clone(),
            path: path_of(blob),
            part_size: self.part_size,
            max_size,
            check,
            written: 0,
            buffer: PutPayloadMut::new(),
            multipart: None,
        }
    }

    fn new(store: Arc<dyn ObjectStore>, part_size: usize) -> Self {
        ObjectBlobStore {
            store,
            signer: None,
            presign_ttl: None,
            part_size,
        }
    }

    /// Files in `folder`, which is made when it isn't there.
    pub fn local(folder: &std::path::Path) -> Result<Self, BlobError> {
        std::fs::create_dir_all(folder)
            .map_err(|e| BlobError::Backend(format!("can't make {}: {e}", folder.display())))?;
        let fs = LocalFileSystem::new_with_prefix(folder).map_err(backend)?;
        Ok(Self::new(Arc::new(fs), LOCAL_PART_SIZE))
    }

    /// Files in a bucket. `presign_ttl` turns pre-signed URLs on for that long.
    pub fn s3(config: &S3Config, presign_ttl: Option<Duration>) -> Result<Self, BlobError> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(config.bucket.as_str())
            .with_region(config.region.as_str())
            .with_access_key_id(config.access_key_id.as_str())
            .with_secret_access_key(config.secret_access_key.as_str())
            .with_virtual_hosted_style_request(!config.path_style);
        if let Some(endpoint) = &config.endpoint {
            builder = builder
                .with_endpoint(endpoint.as_str())
                .with_allow_http(endpoint.starts_with("http://"));
        }
        let s3 = Arc::new(builder.build().map_err(backend)?);
        Ok(ObjectBlobStore {
            store: s3.clone(),
            signer: Some(s3),
            presign_ttl,
            part_size: BUCKET_PART_SIZE,
        })
    }

    /// Files in memory, for tests.
    pub fn memory() -> Self {
        Self::new(Arc::new(InMemory::new()), LOCAL_PART_SIZE)
    }

    /// The store the settings describe.
    pub fn from_config(config: &BlobConfig) -> Result<Self, BlobError> {
        match &config.backend {
            Backend::Local { folder } => Self::local(folder),
            Backend::S3(s3) => Self::s3(s3, config.presign.then_some(config.presign_ttl)),
        }
    }

    /// Stores `bytes` under `key`, replacing what was there. For files that aren't `KMA1`: the
    /// Bitwarden API keeps its attachments, which are Bitwarden's own format, beside the Kemlock
    /// ones, in the same folder or bucket, under `<cipher id>/<attachment id>`. Nothing is checked
    /// about the bytes, and the whole file is held in memory.
    pub async fn put_raw(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        self.put_path(&raw_path(key)?, bytes).await
    }

    /// The bytes under `key`, or `None` when there are none.
    pub async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, BlobError> {
        self.get_path(&raw_path(key)?).await
    }

    /// Removes `key`; removing what isn't there is fine.
    pub async fn delete_raw(&self, key: &str) -> Result<(), BlobError> {
        self.delete_path(raw_path(key)?).await
    }

    /// Stores `bytes` as the blob `blob`, in a single put and unchecked, where [`BlobStore::delete`]
    /// (and so the Send purge and an account's erasure) find and remove it. For a Send's file in a
    /// Bitwarden app's own format, which arrives whole.
    pub async fn put_blob_raw(&self, blob: BlobId, bytes: Vec<u8>) -> Result<(), BlobError> {
        self.put_path(&path_of(blob), bytes).await
    }

    /// The bytes of the blob `blob`, or `None` when there are none.
    pub async fn get_blob_raw(&self, blob: BlobId) -> Result<Option<Vec<u8>>, BlobError> {
        self.get_path(&path_of(blob)).await
    }

    async fn put_path(&self, path: &Path, bytes: Vec<u8>) -> Result<(), BlobError> {
        self.store
            .put_opts(path, PutPayload::from(bytes), PutOptions::default())
            .await
            .map(|_| ())
            .map_err(backend)
    }

    async fn get_path(&self, path: &Path) -> Result<Option<Vec<u8>>, BlobError> {
        match self.store.get_opts(path, GetOptions::new()).await {
            Ok(found) => found
                .bytes()
                .await
                .map(|bytes| Some(bytes.to_vec()))
                .map_err(backend),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }

    /// Deletes the object at `path`; one that is already gone is what the caller wanted.
    async fn delete_path(&self, path: Path) -> Result<(), BlobError> {
        let locations =
            futures_util::stream::once(async move { Ok::<Path, object_store::Error>(path) })
                .boxed();
        match self.store.delete_stream(locations).try_next().await {
            Ok(_) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(backend(e)),
        }
    }

    /// The same store with parts of `part_size` bytes, so tests can make several of them from a
    /// small file.
    #[must_use]
    pub fn with_part_size(mut self, part_size: usize) -> Self {
        self.part_size = part_size.max(1);
        self
    }

    /// Moves what a pre-signed upload put under `blob`'s staging name to the blob's own path, when
    /// there is something there. The signed URL can't be made to name a length or to stop working
    /// once the upload is settled, so the server doesn't trust what is under it: the object must
    /// be `expected` bytes, and its bytes are read and written again under the blob's own name
    /// through the same `KMA1` checks and size cap as an upload through the server. The staging
    /// object goes afterwards. A later `PUT` to the URL makes a new staging object and nothing
    /// else.
    ///
    /// `Ok` also when there is nothing staged (a local folder, or an upload settled already).
    /// `WrongSize` and `NotKma1` leave the staging object for the caller's `delete`.
    async fn adopt_staged(&self, blob: BlobId, expected: u64) -> Result<(), BlobError> {
        let staging = staging_path_of(blob);
        let found = match self.store.get_opts(&staging, GetOptions::new()).await {
            Ok(found) => found,
            Err(object_store::Error::NotFound { .. }) => return Ok(()),
            Err(e) => return Err(backend(e)),
        };
        let size = found.meta.size;
        if size != expected {
            return Err(BlobError::WrongSize);
        }
        let mut body = match found.payload {
            GetResultPayload::File(file, _) => file_stream(file, size),
            GetResultPayload::Stream(stream) => stream.map_err(backend).boxed(),
        };
        let mut upload = self.upload(blob, expected, Some(StreamCheck::new()));
        while let Some(chunk) = body.try_next().await? {
            if let Err(e) = upload.write(chunk).await {
                upload.abort().await;
                return Err(e);
            }
        }
        if upload.finish().await? != expected {
            // Fewer bytes arrived than the object's size said: it changed under the read.
            self.delete_path(path_of(blob)).await?;
            return Err(BlobError::WrongSize);
        }
        self.delete_path(staging).await
    }

    /// A pre-signed URL for `method` on `path`, when the store signs and the setting is on.
    async fn presigned(
        &self,
        method: Method,
        path: &Path,
    ) -> Result<Option<PresignedUrl>, BlobError> {
        let (Some(signer), Some(expires_in)) = (&self.signer, self.presign_ttl) else {
            return Ok(None);
        };
        let url = signer
            .signed_url(method, path, expires_in)
            .await
            .map_err(backend)?;
        Ok(Some(PresignedUrl {
            url: url.to_string(),
            expires_in,
        }))
    }
}

/// One upload to an [`ObjectBlobStore`].
pub struct ObjectUpload {
    store: Arc<dyn ObjectStore>,
    path: Path,
    part_size: usize,
    max_size: u64,
    /// The `KMA1` rules, for an upload that must be a `KMA1` file; `None` for one of any format.
    check: Option<StreamCheck>,
    written: u64,
    /// Bytes gathered for the next part.
    buffer: PutPayloadMut,
    /// Started when the first part is full; a file that fits in one part never starts one.
    multipart: Option<Box<dyn MultipartUpload>>,
}

impl std::fmt::Debug for ObjectUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectUpload")
            .field("path", &self.path)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl ObjectUpload {
    /// Writes the gathered bytes as the next part.
    async fn flush_part(&mut self) -> Result<(), BlobError> {
        if self.multipart.is_none() {
            let started = self
                .store
                .put_multipart_opts(&self.path, PutMultipartOptions::default())
                .await
                .map_err(backend)?;
            self.multipart = Some(started);
        }
        let part = std::mem::take(&mut self.buffer).freeze();
        match self.multipart.as_mut() {
            Some(upload) => upload.put_part(part).await.map_err(backend),
            None => Err(BlobError::Backend("a multipart upload vanished".to_owned())),
        }
    }

    /// Gives up the parts already stored, if any. The error of a failed abort is no use to anyone.
    async fn discard(&mut self) {
        if let Some(mut upload) = self.multipart.take()
            && let Err(e) = upload.abort().await
        {
            tracing::warn!(error = %e, "couldn't abort a multipart upload");
        }
    }
}

impl BlobUpload for ObjectUpload {
    async fn write(&mut self, chunk: Bytes) -> Result<(), BlobError> {
        let len = chunk.len() as u64;
        if self.written.saturating_add(len) > self.max_size {
            return Err(BlobError::TooLarge);
        }
        if let Some(check) = self.check.as_mut() {
            check.push(&chunk).map_err(not_kma1)?;
        }
        self.written += len;
        self.buffer.push(chunk);
        if self.buffer.content_length() >= self.part_size {
            self.flush_part().await?;
        }
        Ok(())
    }

    async fn finish(mut self) -> Result<u64, BlobError> {
        let total = match self.check.take() {
            Some(check) => match check.finish() {
                Ok((_, total)) => total,
                Err(e) => {
                    self.discard().await;
                    return Err(not_kma1(e));
                }
            },
            None => self.written,
        };
        let stored = if self.multipart.is_none() {
            let payload = std::mem::take(&mut self.buffer).freeze();
            self.store
                .put_opts(&self.path, payload, PutOptions::default())
                .await
                .map(|_| ())
                .map_err(backend)
        } else {
            self.complete().await
        };
        if let Err(e) = stored {
            self.discard().await;
            return Err(e);
        }
        Ok(total)
    }

    async fn abort(mut self) {
        self.discard().await;
    }
}

impl ObjectUpload {
    /// Writes the last part and completes the multipart upload.
    async fn complete(&mut self) -> Result<(), BlobError> {
        if !self.buffer.is_empty() {
            self.flush_part().await?;
        }
        match self.multipart.as_mut() {
            Some(upload) => upload.complete().await.map(|_| ()).map_err(backend),
            None => Err(BlobError::Backend("a multipart upload vanished".to_owned())),
        }
    }
}

/// The file still to read and how many bytes of it are left.
type FileState = (Option<std::fs::File>, u64);

/// Reads the next chunk of a local file on the blocking pool; `None` once `left` is used up.
async fn next_file_chunk((file, left): FileState) -> Result<Option<(Bytes, FileState)>, BlobError> {
    let Some(mut file) = file.filter(|_| left > 0) else {
        return Ok(None);
    };
    let want = usize::try_from(left).map_or(READ_CHUNK, |n| n.min(READ_CHUNK));
    let read = tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; want];
        file.read_exact(&mut buf).map(|()| (file, Bytes::from(buf)))
    })
    .await;
    match read {
        Ok(Ok((file, chunk))) => Ok(Some((chunk, (Some(file), left - want as u64)))),
        Ok(Err(e)) => Err(BlobError::Backend(format!("reading a file: {e}"))),
        Err(e) => Err(BlobError::Backend(format!("reading a file: {e}"))),
    }
}

/// Reads a local file in chunks of at most [`READ_CHUNK`] bytes, on the blocking pool.
fn file_stream(file: std::fs::File, size: u64) -> ByteStream {
    futures_util::stream::try_unfold((Some(file), size), next_file_chunk).boxed()
}

impl BlobStore for ObjectBlobStore {
    type Upload = ObjectUpload;

    async fn begin(&self, blob: BlobId, max_size: u64) -> Result<ObjectUpload, BlobError> {
        Ok(self.upload(blob, max_size, Some(StreamCheck::new())))
    }

    async fn open(&self, blob: BlobId) -> Result<BlobRead, BlobError> {
        let found = self
            .store
            .get_opts(&path_of(blob), GetOptions::new())
            .await
            .map_err(backend)?;
        let size = found.meta.size;
        let body = match found.payload {
            GetResultPayload::File(file, _) => file_stream(file, size),
            GetResultPayload::Stream(stream) => stream.map_err(backend).boxed(),
        };
        Ok(BlobRead { size, body })
    }

    async fn verify(&self, blob: BlobId, expected: u64) -> Result<(), BlobError> {
        // A pre-signed upload arrives under the staging name. Move it to the blob's own, checked
        // as it goes, before looking at the blob: from here on the signed URL can't reach it.
        self.adopt_staged(blob, expected).await?;
        let path = path_of(blob);
        let meta = self
            .store
            .get_opts(&path, GetOptions::new().with_head(true))
            .await
            .map_err(backend)?
            .meta;
        if meta.size != expected {
            return Err(BlobError::WrongSize);
        }
        kma1::check_length(meta.size).map_err(not_kma1)?;
        let head = self
            .store
            .get_opts(
                &path,
                GetOptions::new().with_range(Some(0..kma1::HEADER_LEN as u64)),
            )
            .await
            .map_err(backend)?
            .bytes()
            .await
            .map_err(backend)?;
        kma1::Header::parse(&head).map(|_| ()).map_err(not_kma1)
    }

    /// Deletes the blob and whatever a pre-signed upload left under its staging name.
    async fn delete(&self, blob: BlobId) -> Result<(), BlobError> {
        self.delete_path(path_of(blob)).await?;
        self.delete_path(staging_path_of(blob)).await
    }

    /// The URL names the staging path, not the blob's own: the signature can't limit the length of
    /// what is sent or end when the upload is settled, so what arrives there is checked and moved
    /// by `verify`, and a later `PUT` to the URL only makes a new staging object.
    async fn presigned_upload(&self, blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        self.presigned(Method::PUT, &staging_path_of(blob)).await
    }

    async fn presigned_download(&self, blob: BlobId) -> Result<Option<PresignedUrl>, BlobError> {
        self.presigned(Method::GET, &path_of(blob)).await
    }
}

impl SendBlobs for ObjectBlobStore {
    /// A Send's file in a format the server can't check (a Bitwarden app's own), stored under the
    /// same random blob ids as any file, held to the size cap alone.
    async fn begin_raw(&self, blob: BlobId, max_size: u64) -> Result<ObjectUpload, BlobError> {
        Ok(self.upload(blob, max_size, None))
    }
}
