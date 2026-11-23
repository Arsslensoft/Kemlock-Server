//! File Sends on the object store: `begin_raw` keeps bytes of any format, held to the size cap
//! alone, while `begin` still insists on `KMA1`.

use bytes::Bytes;
use futures_util::StreamExt;
use kemlock_app::files::{BlobError, BlobStore, BlobUpload};
use kemlock_app::sends::SendBlobs;
use kemlock_blob::ObjectBlobStore;
use kemlock_domain::BlobId;

async fn read_all(store: &ObjectBlobStore, blob: BlobId) -> Vec<u8> {
    let opened = store.open(blob).await.expect("the blob opens");
    let mut body = opened.body;
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("a chunk"));
    }
    assert_eq!(out.len() as u64, opened.size);
    out
}

/// Bytes that are not a `KMA1` file: a Bitwarden app's encrypted buffer starts with a type byte.
fn bitwarden_like(len: usize) -> Vec<u8> {
    let mut bytes = vec![2u8];
    bytes.extend((0..len - 1).map(|i| (i % 249) as u8));
    bytes
}

#[tokio::test]
async fn a_raw_upload_keeps_any_bytes_and_streams_them_back() {
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    let bytes = bitwarden_like(5000);

    let mut upload = store.begin_raw(blob, 10_000).await.expect("begins");
    for piece in bytes.chunks(777) {
        upload
            .write(Bytes::copy_from_slice(piece))
            .await
            .expect("writes");
    }
    assert_eq!(upload.finish().await, Ok(5000));
    assert_eq!(read_all(&store, blob).await, bytes);
}

#[tokio::test]
async fn a_raw_upload_larger_than_one_part_is_kept_whole() {
    // Parts of 100 bytes, so a 1,050-byte file is several of them.
    let store = ObjectBlobStore::memory().with_part_size(100);
    let blob = BlobId::random();
    let bytes = bitwarden_like(1050);
    let mut upload = store.begin_raw(blob, 5000).await.expect("begins");
    for piece in bytes.chunks(333) {
        upload
            .write(Bytes::copy_from_slice(piece))
            .await
            .expect("writes");
    }
    assert_eq!(upload.finish().await, Ok(1050));
    assert_eq!(read_all(&store, blob).await, bytes);
}

#[tokio::test]
async fn a_raw_upload_is_held_to_the_size_cap() {
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    let mut upload = store.begin_raw(blob, 100).await.expect("begins");
    upload
        .write(Bytes::from(vec![1u8; 100]))
        .await
        .expect("up to the cap");
    assert_eq!(
        upload.write(Bytes::from(vec![1u8; 1])).await,
        Err(BlobError::TooLarge)
    );
    upload.abort().await;
    assert_eq!(store.open(blob).await.err(), Some(BlobError::NotFound));
}

#[tokio::test]
async fn an_aborted_raw_upload_leaves_nothing() {
    let store = ObjectBlobStore::memory().with_part_size(50);
    let blob = BlobId::random();
    let mut upload = store.begin_raw(blob, 1000).await.expect("begins");
    upload
        .write(Bytes::from(vec![9u8; 200]))
        .await
        .expect("writes");
    upload.abort().await;
    assert_eq!(store.open(blob).await.err(), Some(BlobError::NotFound));
}

#[tokio::test]
async fn the_checked_upload_still_refuses_what_is_not_kma1() {
    let store = ObjectBlobStore::memory();
    let mut upload = store.begin(BlobId::random(), 1000).await.expect("begins");
    let refused = upload.write(Bytes::from(bitwarden_like(100))).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))));
    upload.abort().await;
}

#[tokio::test]
async fn deleting_a_raw_blob_goes_through_the_same_store() {
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    let mut upload = store.begin_raw(blob, 1000).await.expect("begins");
    upload
        .write(Bytes::from(bitwarden_like(10)))
        .await
        .expect("writes");
    upload.finish().await.expect("finishes");
    store.delete(blob).await.expect("deleted");
    assert_eq!(store.open(blob).await.err(), Some(BlobError::NotFound));
    // Deleting again is fine.
    store.delete(blob).await.expect("already gone");
}
