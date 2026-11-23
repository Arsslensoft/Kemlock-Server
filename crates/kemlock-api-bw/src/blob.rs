//! Where attachment bytes go.
//!
//! A small trait of this crate's own, so the Bitwarden routes needn't know the storage. The server
//! wires it to `kemlock-blob`, so Bitwarden attachments use the same local folder or bucket as
//! every other file. Keys are `<cipher id>/<attachment id>`, as Vaultwarden names its files.
//! Futures are boxed so the trait can be held as `dyn BlobStore`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A storage failure; the message is for logs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("blob store failure: {0}")]
pub struct BlobError(pub String);

pub trait BlobStore: Send + Sync + 'static {
    /// Stores `bytes` under `key`, replacing what was there.
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>>;
    /// The bytes under `key`, or `None` when there are none.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>>;
    /// Removes `key`; removing what isn't there is fine.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>>;
}

/// Bytes in memory: for tests and for a server that keeps nothing on disk.
#[derive(Debug, Default)]
pub struct MemoryBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many blobs are held.
    pub fn len(&self) -> usize {
        self.blobs.lock().map_or(0, |m| m.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BlobStore for MemoryBlobStore {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            self.blobs
                .lock()
                .map_err(|_| BlobError("poisoned".to_owned()))?
                .insert(key.to_owned(), bytes);
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>> {
        Box::pin(async move {
            Ok(self
                .blobs
                .lock()
                .map_err(|_| BlobError("poisoned".to_owned()))?
                .get(key)
                .cloned())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            self.blobs
                .lock()
                .map_err(|_| BlobError("poisoned".to_owned()))?
                .remove(key);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(store: &dyn BlobStore) {
        assert_eq!(store.get("c1/a1").await, Ok(None));
        store.put("c1/a1", vec![1, 2, 3]).await.expect("put");
        assert_eq!(store.get("c1/a1").await, Ok(Some(vec![1, 2, 3])));
        store.put("c1/a1", vec![9]).await.expect("replace");
        assert_eq!(store.get("c1/a1").await, Ok(Some(vec![9])));
        store.delete("c1/a1").await.expect("delete");
        store.delete("c1/a1").await.expect("deleting twice is fine");
        assert_eq!(store.get("c1/a1").await, Ok(None));
    }

    #[tokio::test]
    async fn memory_blobs_round_trip() {
        let store = MemoryBlobStore::new();
        round_trip(&store).await;
        assert!(store.is_empty());
    }
}
