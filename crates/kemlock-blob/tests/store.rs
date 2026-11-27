//! The object store adapter over a temporary folder and over memory: round trips, the size cap,
//! the `KMA1` checks, multipart uploads, cleanup and pre-signed URLs.

use bytes::Bytes;
use futures_util::StreamExt;
use kemlock_app::files::{BlobError, BlobStore, BlobUpload};
use kemlock_blob::{Backend, BlobConfig, ObjectBlobStore, S3Config, kma1};
use kemlock_domain::BlobId;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A `KMA1`-shaped file whose plaintext is `plain` bytes long: the right header and a length
/// whole chunks make (the server never opens a chunk, so the rest is filler).
fn kma1_file(plain: usize) -> Vec<u8> {
    let len = usize::try_from(kma1::sealed_length(plain as u64)).expect("fits");
    let mut bytes = b"KMA1".to_vec();
    bytes.extend((0..len - 4).map(|i| (i % 253) as u8));
    bytes
}

/// Uploads `bytes` in pieces of `piece` bytes and returns what the upload says it stored.
async fn put(
    store: &ObjectBlobStore,
    blob: BlobId,
    bytes: &[u8],
    piece: usize,
) -> Result<u64, BlobError> {
    let mut upload = store.begin(blob, u64::MAX).await?;
    for chunk in bytes.chunks(piece) {
        if let Err(e) = upload.write(Bytes::copy_from_slice(chunk)).await {
            upload.abort().await;
            return Err(e);
        }
    }
    upload.finish().await
}

/// Reads a blob to the end, returning its bytes and the size of its largest chunk.
async fn read(store: &ObjectBlobStore, blob: BlobId) -> Result<(Vec<u8>, usize), BlobError> {
    let opened = store.open(blob).await?;
    let size = opened.size;
    let mut body = opened.body;
    let mut out = Vec::new();
    let mut largest = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        largest = largest.max(chunk.len());
        out.extend_from_slice(&chunk);
    }
    assert_eq!(out.len() as u64, size, "the size says how many bytes come");
    Ok((out, largest))
}

/// Every file under `dir`, however deep.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("a readable folder") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

fn local() -> (ObjectBlobStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let store = ObjectBlobStore::local(&dir.path().join("attachments")).expect("a local store");
    (store, dir)
}

#[tokio::test]
async fn a_file_round_trips_through_a_local_folder() {
    let (store, dir) = local();
    let blob = BlobId::random();
    let bytes = kma1_file(5000);

    let stored = put(&store, blob, &bytes, 700).await.expect("stored");
    assert_eq!(stored, bytes.len() as u64);

    let (back, _) = read(&store, blob).await.expect("read");
    assert_eq!(back, bytes);

    // On disk it is named by its blob id and nothing else.
    let files = files_under(&dir.path().join("attachments"));
    assert_eq!(files.len(), 1);
    let hex = blob.to_string();
    assert!(
        files[0].ends_with(Path::new(&hex[..2]).join(&hex)),
        "{files:?}"
    );
    assert_eq!(std::fs::read(&files[0]).expect("a file"), bytes);
}

#[tokio::test]
async fn the_apps_two_chunk_fixture_round_trips_byte_for_byte() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("two-chunks.kma1");
    let bytes = std::fs::read(fixture).expect("the fixture");
    let (store, _dir) = local();
    let blob = BlobId::random();
    // Cut at awkward places, including the 12-byte header boundary.
    for piece in [5, 12, 4096, 65_552] {
        put(&store, blob, &bytes, piece).await.expect("stored");
        assert_eq!(read(&store, blob).await.expect("read").0, bytes, "{piece}");
    }
}

#[tokio::test]
async fn a_memory_store_works_the_same() {
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    let bytes = kma1_file(300);
    put(&store, blob, &bytes, 50).await.expect("stored");
    assert_eq!(read(&store, blob).await.expect("read").0, bytes);
}

#[tokio::test]
async fn big_files_are_written_in_parts_and_read_in_small_chunks() {
    let (store, _dir) = local();
    let store = store.with_part_size(100_000);
    let blob = BlobId::random();
    // 3 MiB and a bit: 30 parts, a short last one.
    let bytes = kma1_file(3 * 1024 * 1024 + 12_345);
    put(&store, blob, &bytes, 16 * 1024).await.expect("stored");
    let (back, largest) = read(&store, blob).await.expect("read");
    assert!(back == bytes, "the bytes changed on the way");
    assert!(largest <= 256 * 1024, "a chunk of {largest} bytes");
}

#[tokio::test]
async fn parts_work_in_memory_too() {
    let store = ObjectBlobStore::memory().with_part_size(1000);
    let blob = BlobId::random();
    let bytes = kma1_file(10_000);
    put(&store, blob, &bytes, 333).await.expect("stored");
    assert_eq!(read(&store, blob).await.expect("read").0, bytes);
}

#[tokio::test]
async fn a_write_past_the_cap_is_refused_and_nothing_is_stored() {
    let (store, dir) = local();
    let store = store.with_part_size(64);
    let blob = BlobId::random();
    let bytes = kma1_file(200);
    let cap = bytes.len() as u64;

    let mut upload = store.begin(blob, cap).await.expect("begins");
    for chunk in bytes.chunks(50) {
        upload
            .write(Bytes::copy_from_slice(chunk))
            .await
            .expect("within the cap");
    }
    // One byte more than the cap.
    assert_eq!(
        upload.write(Bytes::from_static(b"x")).await,
        Err(BlobError::TooLarge)
    );
    upload.abort().await;

    assert_eq!(store.open(blob).await.map(|_| ()), Err(BlobError::NotFound));
    assert!(files_under(&dir.path().join("attachments")).is_empty());
}

#[tokio::test]
async fn a_file_of_exactly_the_cap_is_accepted() {
    let (store, _dir) = local();
    let blob = BlobId::random();
    let bytes = kma1_file(1000);
    let mut upload = store.begin(blob, bytes.len() as u64).await.expect("begins");
    for chunk in bytes.chunks(128) {
        upload
            .write(Bytes::copy_from_slice(chunk))
            .await
            .expect("within the cap");
    }
    assert_eq!(upload.finish().await, Ok(bytes.len() as u64));
}

#[tokio::test]
async fn the_magic_is_checked_from_the_first_bytes() {
    let (store, dir) = local();
    let blob = BlobId::random();
    let mut upload = store.begin(blob, 1000).await.expect("begins");
    upload
        .write(Bytes::from_static(b"KM"))
        .await
        .expect("so far fine");
    let refused = upload.write(Bytes::from_static(b"Z1")).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))), "{refused:?}");
    upload.abort().await;
    assert!(files_under(&dir.path().join("attachments")).is_empty());

    // A ZIP, the file type most likely to be sent by mistake.
    let mut zip = kma1_file(100);
    zip[..4].copy_from_slice(b"PK\x03\x04");
    let refused = put(&store, blob, &zip, 64).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))), "{refused:?}");
    assert_eq!(store.open(blob).await.map(|_| ()), Err(BlobError::NotFound));
}

#[tokio::test]
async fn a_length_no_chunks_make_is_refused_at_the_end() {
    let (store, dir) = local();
    for len in [4, 11, 12, 27, 12 + 65_552 + 5] {
        let blob = BlobId::random();
        let mut bytes = kma1_file(0);
        bytes.resize(len.max(4), 7);
        bytes.truncate(len);
        bytes[..len.min(4)].copy_from_slice(&b"KMA1"[..len.min(4)]);
        let refused = put(&store, blob, &bytes, 1000).await;
        assert!(
            matches!(refused, Err(BlobError::NotKma1(_))),
            "{len}: {refused:?}"
        );
        assert_eq!(
            store.open(blob).await.map(|_| ()),
            Err(BlobError::NotFound),
            "{len}"
        );
    }
    assert!(files_under(&dir.path().join("attachments")).is_empty());
}

#[tokio::test]
async fn a_cut_off_multipart_upload_leaves_nothing() {
    let (store, dir) = local();
    let store = store.with_part_size(100);
    let blob = BlobId::random();
    let bytes = kma1_file(1000);

    // Aborted: the staging file goes.
    let mut upload = store.begin(blob, u64::MAX).await.expect("begins");
    for chunk in bytes[..500].chunks(100) {
        upload
            .write(Bytes::copy_from_slice(chunk))
            .await
            .expect("written");
    }
    upload.abort().await;
    assert!(
        files_under(&dir.path().join("attachments")).is_empty(),
        "after abort"
    );

    // Dropped, as when the client's connection goes: the same.
    let mut upload = store.begin(blob, u64::MAX).await.expect("begins");
    for chunk in bytes[..500].chunks(100) {
        upload
            .write(Bytes::copy_from_slice(chunk))
            .await
            .expect("written");
    }
    drop(upload);
    // The staging file is removed on the blocking pool, so give it a moment.
    let attachments = dir.path().join("attachments");
    for _ in 0..100 {
        if files_under(&attachments).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(files_under(&attachments).is_empty(), "after drop");
    assert_eq!(store.open(blob).await.map(|_| ()), Err(BlobError::NotFound));
}

#[tokio::test]
async fn a_blob_is_not_visible_until_its_upload_finishes() {
    let (store, _dir) = local();
    let store = store.with_part_size(100);
    let blob = BlobId::random();
    let bytes = kma1_file(1000);
    let mut upload = store.begin(blob, u64::MAX).await.expect("begins");
    for chunk in bytes.chunks(100) {
        upload
            .write(Bytes::copy_from_slice(chunk))
            .await
            .expect("written");
    }
    assert_eq!(store.open(blob).await.map(|_| ()), Err(BlobError::NotFound));
    upload.finish().await.expect("finished");
    assert_eq!(read(&store, blob).await.expect("read").0, bytes);
}

#[tokio::test]
async fn uploading_again_replaces_the_blob() {
    let (store, _dir) = local();
    let blob = BlobId::random();
    let first = kma1_file(100);
    let second = kma1_file(200);
    put(&store, blob, &first, 50).await.expect("first");
    put(&store, blob, &second, 50).await.expect("second");
    assert_eq!(read(&store, blob).await.expect("read").0, second);
}

#[tokio::test]
async fn deleting_removes_the_blob_and_is_idempotent() {
    let (store, _dir) = local();
    let blob = BlobId::random();
    put(&store, blob, &kma1_file(100), 50)
        .await
        .expect("stored");
    assert_eq!(store.delete(blob).await, Ok(()));
    assert_eq!(store.open(blob).await.map(|_| ()), Err(BlobError::NotFound));
    assert_eq!(store.delete(blob).await, Ok(()), "already gone");
    assert_eq!(store.delete(BlobId::random()).await, Ok(()), "never there");
}

#[tokio::test]
async fn opening_a_missing_blob_is_not_found() {
    let (store, _dir) = local();
    assert_eq!(
        store.open(BlobId::random()).await.map(|_| ()),
        Err(BlobError::NotFound)
    );
}

#[tokio::test]
async fn verify_checks_a_blob_written_some_other_way() {
    let (store, dir) = local();
    let place = |blob: BlobId, bytes: &[u8]| {
        let hex = blob.to_string();
        let folder = dir.path().join("attachments").join(&hex[..2]);
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::write(folder.join(&hex), bytes).expect("a file");
    };

    let good = BlobId::random();
    let bytes = kma1_file(500);
    place(good, &bytes);
    assert_eq!(store.verify(good, bytes.len() as u64).await, Ok(()));
    assert_eq!(
        store.verify(good, bytes.len() as u64 + 1).await,
        Err(BlobError::WrongSize)
    );

    let zip = BlobId::random();
    let mut other = bytes.clone();
    other[..4].copy_from_slice(b"PK\x03\x04");
    place(zip, &other);
    let refused = store.verify(zip, other.len() as u64).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))), "{refused:?}");

    let odd = BlobId::random();
    // A full last chunk and then five stray bytes: no whole chunks make that length.
    let mut odd_bytes = kma1_file(65_536);
    odd_bytes.extend([0; 5]);
    place(odd, &odd_bytes);
    let refused = store.verify(odd, odd_bytes.len() as u64).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))), "{refused:?}");

    assert_eq!(
        store.verify(BlobId::random(), 10).await,
        Err(BlobError::NotFound)
    );
}

/// Where a pre-signed upload lands in a local folder's layout, which a test writes to by hand: the
/// bucket's signed URL names this path.
fn stage(dir: &Path, blob: BlobId, bytes: &[u8]) -> PathBuf {
    let folder = dir.join("attachments").join("staging");
    std::fs::create_dir_all(&folder).expect("a folder");
    let path = folder.join(blob.to_string());
    std::fs::write(&path, bytes).expect("a file");
    path
}

#[tokio::test]
async fn a_pre_signed_upload_is_checked_and_moved_so_a_later_put_cannot_change_the_file() {
    let (store, dir) = local();
    let blob = BlobId::random();
    let bytes = kma1_file(500);
    let staged = stage(dir.path(), blob, &bytes);

    assert_eq!(store.verify(blob, bytes.len() as u64).await, Ok(()));
    assert!(
        !staged.exists(),
        "the staging object went once it was moved"
    );
    assert_eq!(read(&store, blob).await.expect("reads").0, bytes);

    // The signed URL still works for its lifetime: a bigger body goes to the staging name again.
    let huge = kma1_file(70_000);
    let again = stage(dir.path(), blob, &huge);
    assert_eq!(
        read(&store, blob).await.expect("reads").0,
        bytes,
        "what clients download didn't change"
    );
    // A finish retried before the attachment was marked ready sees the staging object again, and
    // a body other than the announced one is refused.
    assert_eq!(
        store.verify(blob, bytes.len() as u64).await,
        Err(BlobError::WrongSize),
    );
    store.delete(blob).await.expect("deleted");
    assert!(
        !again.exists(),
        "deleting the blob takes its staging object too"
    );
    assert!(store.open(blob).await.is_err(), "and the blob itself");
}

#[tokio::test]
async fn a_pre_signed_upload_of_the_wrong_size_or_kind_is_refused() {
    let (store, dir) = local();
    let bytes = kma1_file(500);

    // Announced tiny, sent big.
    let big = BlobId::random();
    stage(dir.path(), big, &kma1_file(70_000));
    assert_eq!(
        store.verify(big, bytes.len() as u64).await,
        Err(BlobError::WrongSize)
    );
    assert!(
        store.open(big).await.is_err(),
        "nothing was stored under the blob's own name"
    );

    // The right size but not a KMA1 file.
    let zip = BlobId::random();
    let mut other = bytes.clone();
    other[..4].copy_from_slice(b"PK\x03\x04");
    stage(dir.path(), zip, &other);
    let refused = store.verify(zip, other.len() as u64).await;
    assert!(matches!(refused, Err(BlobError::NotKma1(_))), "{refused:?}");
    assert!(store.open(zip).await.is_err());

    // The caller deletes what was refused, staging included.
    for blob in [big, zip] {
        store.delete(blob).await.expect("deleted");
    }
    assert!(
        files_under(&dir.path().join("attachments")).is_empty(),
        "{:?}",
        files_under(&dir.path().join("attachments"))
    );
}

fn bucket() -> S3Config {
    S3Config {
        endpoint: Some("http://localhost:9000".to_owned()),
        bucket: "kemlock".to_owned(),
        region: "us-east-1".to_owned(),
        access_key_id: "AKIDEXAMPLE".to_owned(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        path_style: true,
    }
}

#[tokio::test]
async fn a_local_folder_has_no_presigned_urls() {
    let (store, _dir) = local();
    let blob = BlobId::random();
    assert_eq!(store.presigned_upload(blob).await, Ok(None));
    assert_eq!(store.presigned_download(blob).await, Ok(None));
}

#[tokio::test]
async fn a_bucket_signs_urls_only_when_the_setting_is_on() {
    let blob = BlobId::random();

    let off = ObjectBlobStore::s3(&bucket(), None).expect("a bucket store");
    assert_eq!(off.presigned_upload(blob).await, Ok(None));

    let on =
        ObjectBlobStore::s3(&bucket(), Some(Duration::from_secs(300))).expect("a bucket store");
    // An upload URL is signed for one length: the unsized form gives none.
    assert_eq!(on.presigned_upload(blob).await, Ok(None));
    for url in [
        on.presigned_upload_sized(blob, 4096)
            .await
            .expect("signs")
            .expect("a URL"),
        on.presigned_download(blob)
            .await
            .expect("signs")
            .expect("a URL"),
    ] {
        assert_eq!(url.expires_in, Duration::from_secs(300));
        assert!(
            url.url.starts_with("http://localhost:9000/kemlock/"),
            "{}",
            url.url
        );
        assert!(url.url.contains(&blob.to_string()), "{}", url.url);
        assert!(url.url.contains("X-Amz-Signature="), "{}", url.url);
    }
}

#[tokio::test]
async fn an_upload_url_signs_the_files_exact_length() {
    let on =
        ObjectBlobStore::s3(&bucket(), Some(Duration::from_secs(300))).expect("a bucket store");
    let blob = BlobId::random();
    let url = on
        .presigned_upload_sized(blob, 4096)
        .await
        .expect("signs")
        .expect("a URL")
        .url;
    // It names the staging object, and the length is one of the headers the signature binds.
    assert!(url.contains(&format!("/staging/{blob}")), "{url}");
    let signed = url
        .split("X-Amz-SignedHeaders=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(signed.contains("content-length"), "{url}");
}

#[tokio::test]
async fn the_purge_removes_only_the_staging_objects_past_the_grace_period() {
    let store = ObjectBlobStore::memory();
    let (a, b) = (BlobId::random(), BlobId::random());
    store
        .put_raw(&format!("staging/{a}"), b"left behind".to_vec())
        .await
        .expect("put");
    store
        .put_raw(&format!("staging/{b}"), b"left behind too".to_vec())
        .await
        .expect("put");
    store
        .put_blob_raw(a, b"a finished blob".to_vec())
        .await
        .expect("put");

    // Nothing is old enough yet.
    assert_eq!(store.purge_staging(Duration::from_secs(3600)).await, Ok(0));
    assert!(
        store
            .get_raw(&format!("staging/{a}"))
            .await
            .expect("read")
            .is_some()
    );
    // Past the grace period they go, and a finished blob is not under `staging/`.
    assert_eq!(store.purge_staging(Duration::ZERO).await, Ok(2));
    for blob in [a, b] {
        assert_eq!(
            store.get_raw(&format!("staging/{blob}")).await,
            Ok(None)
        );
    }
    assert!(store.get_blob_raw(a).await.expect("read").is_some());
}

#[tokio::test]
async fn the_settings_build_the_store_they_describe() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let folder = dir.path().join("made").join("on").join("demand");
    let config = BlobConfig {
        backend: Backend::Local {
            folder: folder.clone(),
        },
        max_size: 1000,
        presign: true,
        staging_expiry_confirmed: true,
        presign_ttl: Duration::from_secs(60),
    };
    let store = ObjectBlobStore::from_config(&config).expect("a local store");
    assert!(folder.is_dir(), "the folder is made");
    assert_eq!(store.presigned_upload(BlobId::random()).await, Ok(None));

    let config = BlobConfig {
        backend: Backend::S3(bucket()),
        max_size: 1000,
        presign: true,
        staging_expiry_confirmed: true,
        presign_ttl: Duration::from_secs(60),
    };
    let store = ObjectBlobStore::from_config(&config).expect("a bucket store");
    assert!(
        store
            .presigned_upload(BlobId::random())
            .await
            .expect("signs")
            .is_some()
    );
}

// ---- raw files: the Bitwarden API's attachments, beside the Kemlock ones ----

#[tokio::test]
async fn a_raw_file_round_trips_in_the_layout_vaultwarden_uses() {
    let (store, dir) = local();
    let key = "7f3c4b1e-0000-4000-8000-000000000000/abc_DEF-123";
    assert_eq!(store.get_raw(key).await, Ok(None));
    // The bytes needn't be KMA1: they are Bitwarden's own encrypted attachment.
    store
        .put_raw(key, b"not a kma1 file".to_vec())
        .await
        .expect("stored");
    assert_eq!(
        store.get_raw(key).await,
        Ok(Some(b"not a kma1 file".to_vec()))
    );
    assert_eq!(
        std::fs::read(
            dir.path()
                .join("attachments")
                .join("7f3c4b1e-0000-4000-8000-000000000000")
                .join("abc_DEF-123")
        )
        .expect("the file is where Vaultwarden keeps it"),
        b"not a kma1 file"
    );

    store.put_raw(key, vec![9]).await.expect("replaced");
    assert_eq!(store.get_raw(key).await, Ok(Some(vec![9])));
    store.delete_raw(key).await.expect("deleted");
    store.delete_raw(key).await.expect("deleting twice is fine");
    assert_eq!(store.get_raw(key).await, Ok(None));
}

#[tokio::test]
async fn raw_files_work_in_memory_and_beside_kma1_blobs() {
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    put(&store, blob, &kma1_file(100), 64)
        .await
        .expect("a blob");
    store
        .put_raw("cipher-1/att-1", vec![1, 2, 3])
        .await
        .expect("a raw file");
    assert_eq!(
        store.get_raw("cipher-1/att-1").await,
        Ok(Some(vec![1, 2, 3]))
    );
    // Neither touches the other.
    let (bytes, _) = read(&store, blob).await.expect("the blob reads");
    assert_eq!(bytes, kma1_file(100));
    store.delete(blob).await.expect("the blob goes");
    assert_eq!(
        store.get_raw("cipher-1/att-1").await,
        Ok(Some(vec![1, 2, 3]))
    );
}

#[tokio::test]
async fn a_raw_key_cannot_leave_the_folder_or_name_a_blob_folder() {
    let (store, dir) = local();
    for bad in [
        "",
        "..",
        "../x",
        "a/../b",
        "/etc/passwd",
        "a//b",
        "a/b.c",
        "a\\b",
        "a/b/c/d/e",
        // The folders of blob ids are two hex digits.
        "ab/0f3c4b1e",
    ] {
        assert!(store.put_raw(bad, vec![1]).await.is_err(), "{bad:?}");
        assert!(store.get_raw(bad).await.is_err(), "{bad:?}");
        assert!(store.delete_raw(bad).await.is_err(), "{bad:?}");
    }
    assert!(
        files_under(&dir.path().join("attachments")).is_empty(),
        "nothing was written"
    );
}

#[tokio::test]
async fn a_blob_stored_whole_and_unchecked_is_removed_by_the_blob_delete() {
    // A Send's file in a Bitwarden app's own format: not KMA1, but where the purge looks.
    let store = ObjectBlobStore::memory();
    let blob = BlobId::random();
    assert_eq!(store.get_blob_raw(blob).await, Ok(None));
    store
        .put_blob_raw(blob, b"bitwarden's own bytes".to_vec())
        .await
        .expect("stored");
    assert_eq!(
        store.get_blob_raw(blob).await,
        Ok(Some(b"bitwarden's own bytes".to_vec()))
    );
    store.delete(blob).await.expect("the blob delete finds it");
    assert_eq!(store.get_blob_raw(blob).await, Ok(None));
}
