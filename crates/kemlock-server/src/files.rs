//! Attachments: builds the blob store from its settings (see `kemlock_blob::config`), the file
//! routes over it, and the job that removes files no item names any more.
//!
//! The routes are returned apart from the API router, because an upload takes as long as the
//! connection does and so runs under a longer timeout than the JSON routes.

use crate::adapters::ServerCrypto;
use crate::app::RunError;
use axum::Router;
use axum::http::StatusCode;
use kemlock_api_bw::{BlobError as BwBlobError, BlobStore as BwBlobStore, BoxFuture};
use kemlock_api_kem::{Api, JwsTokenSigner, files_router};
use kemlock_app::files::{
    BlobError as FileBlobError, BlobStore as FileBlobStore, FileError, FilesConfig, PurgeOrphans,
};
use kemlock_blob::{BlobConfig, ObjectBlobStore};
use kemlock_domain::{AttachmentLimits, BlobId};
use kemlock_federation::blobs::{BlobFetcher, OnDemandBlobs};
use kemlock_store_sql::{ImportFiles, ImportFilesFuture, SqlStore};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

/// How long one file request may take. A 100 MiB file on a slow link takes minutes.
const FILE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

type Purge = PurgeOrphans<SqlStore, ObjectBlobStore, ServerCrypto>;

/// What the server keeps to run the attachment job.
pub struct Files {
    purge: Purge,
    /// The store every file lives in, for the Bitwarden API's attachments too.
    blobs: ObjectBlobStore,
}

impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files").finish_non_exhaustive()
    }
}

/// Reads the file-storage settings and opens the blob store, making the folder if needed.
pub fn open_blobs(data_folder: &Path) -> Result<(ObjectBlobStore, BlobConfig), RunError> {
    let settings =
        BlobConfig::from_env(data_folder).map_err(|e| RunError::Config(e.to_string()))?;
    let blobs = ObjectBlobStore::from_config(&settings)
        .map_err(|e| RunError::Config(format!("file storage: {e}")))?;
    Ok((blobs, settings))
}

/// Builds the file routes over the blob store. A file a federated vault holds a row for but not
/// the bytes of (one over 50 MB, copied on first use) is fetched from a peer by `fetcher` when it
/// is first read.
pub fn wire(
    api: &Api<SqlStore, ServerCrypto, JwsTokenSigner>,
    store: &SqlStore,
    blobs: ObjectBlobStore,
    settings: &BlobConfig,
    fetcher: Arc<dyn BlobFetcher>,
) -> Result<(Router, Files), RunError> {
    let config = FilesConfig {
        limits: AttachmentLimits {
            max_size: settings.max_size,
        },
        ..FilesConfig::default()
    };
    let served = OnDemandBlobs::new(blobs.clone(), fetcher);
    let router = files_router(api.clone(), served, store.clone(), config).layer(
        TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, FILE_TIMEOUT),
    );
    let purge = PurgeOrphans {
        attachments: store.clone(),
        blobs: blobs.clone(),
        clock: api.crypto.clone(),
        config,
    };
    Ok((router, Files { purge, blobs }))
}

impl Files {
    /// The Bitwarden API's attachment storage: the same local folder or bucket as the Kemlock
    /// API's files, so one setting says where every attachment goes.
    pub fn bitwarden_blobs(&self) -> Arc<dyn BwBlobStore> {
        Arc::new(BitwardenBlobs(self.blobs.clone()))
    }

    /// Deletes the files of purged items and the uploads that never finished, and says how many
    /// went. `jobs::purge_files_once` runs it hourly, under a lease.
    pub async fn purge_once(&self) -> Result<u64, FileError> {
        self.purge.execute().await
    }
}

/// The Bitwarden API's [`BwBlobStore`] over the server's file storage. Its attachments are
/// Bitwarden's own encrypted bytes, not `KMA1`, so they go in as raw files under
/// `<cipher id>/<attachment id>`, the layout Vaultwarden uses, in the same folder or bucket.
#[derive(Clone, Debug)]
pub struct BitwardenBlobs(ObjectBlobStore);

impl BitwardenBlobs {
    pub fn new(blobs: ObjectBlobStore) -> Self {
        BitwardenBlobs(blobs)
    }
}

/// The move from Vaultwarden puts its files where the Bitwarden API reads them: through this store,
/// so they land in the configured folder or bucket, and a Send's file where the Send purge looks.
impl ImportFiles for BitwardenBlobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> ImportFilesFuture<'a> {
        Box::pin(async move {
            BwBlobStore::put(self, key, bytes)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> ImportFilesFuture<'a> {
        Box::pin(async move {
            BwBlobStore::delete(self, key)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

fn failure(e: FileBlobError) -> BwBlobError {
    BwBlobError(e.to_string())
}

/// The blob a Bitwarden Send's file is kept at: its key is `sends/<send id>/<file id>`, and the
/// bytes go to the blob named by the Send's id, which is where the Send purge and an account's
/// erasure look when they delete the Send's file.
fn send_blob(key: &str) -> Option<BlobId> {
    let rest = key.strip_prefix("sends/")?;
    let (send, file) = rest.split_once('/')?;
    let clean = !file.is_empty()
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !clean {
        return None;
    }
    uuid::Uuid::parse_str(send).ok().map(BlobId::from_uuid)
}

impl BwBlobStore for BitwardenBlobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BwBlobError>> {
        Box::pin(async move {
            let stored = match send_blob(key) {
                Some(blob) => self.0.put_blob_raw(blob, bytes).await,
                None => self.0.put_raw(key, bytes).await,
            };
            stored.map_err(failure)
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BwBlobError>> {
        Box::pin(async move {
            let found = match send_blob(key) {
                Some(blob) => self.0.get_blob_raw(blob).await,
                None => self.0.get_raw(key).await,
            };
            found.map_err(failure)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BwBlobError>> {
        Box::pin(async move {
            let gone = match send_blob(key) {
                Some(blob) => FileBlobStore::delete(&self.0, blob).await,
                None => self.0.delete_raw(key).await,
            };
            gone.map_err(failure)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bitwarden_attachments_use_the_configured_folder_in_vaultwardens_layout() {
        let dir = tempfile_dir();
        let blobs =
            BitwardenBlobs::new(ObjectBlobStore::local(&dir.join("attachments")).expect("a store"));
        let key = "7f3c4b1e-0000-4000-8000-000000000000/att1";
        assert_eq!(BwBlobStore::get(&blobs, key).await, Ok(None));
        BwBlobStore::put(&blobs, key, b"encrypted by bitwarden".to_vec())
            .await
            .expect("put");
        assert_eq!(
            BwBlobStore::get(&blobs, key).await,
            Ok(Some(b"encrypted by bitwarden".to_vec()))
        );
        assert_eq!(
            std::fs::read(dir.join("attachments/7f3c4b1e-0000-4000-8000-000000000000/att1"))
                .expect("a file where Vaultwarden keeps it"),
            b"encrypted by bitwarden"
        );
        BwBlobStore::delete(&blobs, key).await.expect("delete");
        BwBlobStore::delete(&blobs, key)
            .await
            .expect("deleting twice is fine");
        assert_eq!(BwBlobStore::get(&blobs, key).await, Ok(None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_bitwarden_send_file_lands_where_the_send_purge_deletes_it() {
        let store = ObjectBlobStore::memory();
        let blobs = BitwardenBlobs::new(store.clone());
        let send = uuid::Uuid::new_v4();
        let key = format!("sends/{send}/0123abcd");
        BwBlobStore::put(&blobs, &key, vec![1, 2, 3])
            .await
            .expect("put");
        assert_eq!(
            BwBlobStore::get(&blobs, &key).await,
            Ok(Some(vec![1, 2, 3]))
        );
        assert_eq!(
            store.get_blob_raw(BlobId::from_uuid(send)).await,
            Ok(Some(vec![1, 2, 3]))
        );
        // What PurgeSends and EraseSends call for a Send's file.
        FileBlobStore::delete(&store, BlobId::from_uuid(send))
            .await
            .expect("deleted");
        assert_eq!(BwBlobStore::get(&blobs, &key).await, Ok(None));
    }

    #[test]
    fn only_send_keys_with_a_uuid_and_a_clean_file_id_are_a_sends_blob() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(
            send_blob(&format!("sends/{id}/ab_C-1")),
            Some(BlobId::from_uuid(id))
        );
        assert_eq!(send_blob(&format!("sends/{id}/")), None);
        assert_eq!(send_blob(&format!("sends/{id}/../x")), None);
        assert_eq!(send_blob("sends/not-a-uuid/ab"), None);
        assert_eq!(send_blob(&format!("{id}/ab")), None);
    }

    #[tokio::test]
    async fn a_key_that_could_leave_the_folder_is_refused() {
        let blobs = BitwardenBlobs::new(ObjectBlobStore::memory());
        assert!(
            BwBlobStore::put(&blobs, "../escape", vec![1])
                .await
                .is_err()
        );
        assert!(BwBlobStore::get(&blobs, "a/../b").await.is_err());
    }

    #[tokio::test]
    async fn the_server_hands_the_store_it_built_to_the_bitwarden_api() {
        let blobs = BitwardenBlobs::new(ObjectBlobStore::memory());
        let shared: Arc<dyn BwBlobStore> = Arc::new(blobs.clone());
        // A Bitwarden key: the cipher's uuid, then the attachment's id.
        const KEY: &str = "7f3c4b1e-0000-4000-8000-000000000000/a1";
        shared.put(KEY, vec![4, 5]).await.expect("put");
        // The clone the server keeps for the Kemlock routes sees the same files.
        assert_eq!(blobs.get(KEY).await, Ok(Some(vec![4, 5])));
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "kemlock-server-bw-blobs-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a temp dir");
        path
    }
}
