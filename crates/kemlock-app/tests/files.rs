//! The attachment use cases over in-memory fakes: starting an upload, streaming its bytes,
//! finishing a pre-signed one, downloading, deleting and purging orphans.

mod fakes;
mod file_fakes;

use fakes::{FakeEnv, FakeStore, World, actor, delete, write};
use file_fakes::{FakeAttachments, FakeBlobs, VecBody, kma1_bytes};
use futures_util::StreamExt;
use kemlock_app::Actor;
use kemlock_app::files::{
    DeleteFile, Download, FileError, FilesConfig, FinishUpload, PurgeOrphans, StartUpload,
    UploadBytes,
};
use kemlock_app::ports::Clock;
use kemlock_app::quota::QuotaRefusal;
use kemlock_domain::{
    Attachment, AttachmentId, AttachmentLimits, AttachmentStatus, BlobId, ItemId, Owner, UserId,
};
use time::Duration;

/// The use cases over one set of fakes.
struct Files {
    world: World,
    blobs: FakeBlobs,
    attachments: FakeAttachments,
    config: FilesConfig,
}

impl Files {
    fn new() -> Self {
        Files::with_blobs(FakeBlobs::new())
    }

    fn with_blobs(blobs: FakeBlobs) -> Self {
        Files {
            world: World::new(),
            blobs,
            attachments: FakeAttachments::new(),
            config: FilesConfig::default(),
        }
    }

    fn with_limit(mut self, max_size: u64) -> Self {
        self.config.limits = AttachmentLimits { max_size };
        self
    }

    fn start(&self) -> StartUpload<FakeStore, FakeAttachments, FakeBlobs, FakeEnv> {
        StartUpload {
            items: self.world.store.clone(),
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
            clock: self.world.env.clone(),
            config: self.config,
        }
    }

    fn upload(&self) -> UploadBytes<FakeAttachments, FakeBlobs, FakeStore, FakeEnv> {
        UploadBytes {
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
            config: self.config,
        }
    }

    fn finish(&self) -> FinishUpload<FakeAttachments, FakeBlobs, FakeStore, FakeEnv> {
        FinishUpload {
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn download(&self) -> Download<FakeStore, FakeAttachments, FakeBlobs> {
        Download {
            items: self.world.store.clone(),
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
        }
    }

    fn delete(&self) -> DeleteFile<FakeAttachments, FakeBlobs, FakeStore, FakeEnv> {
        DeleteFile {
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn purge(&self) -> PurgeOrphans<FakeAttachments, FakeBlobs, FakeEnv> {
        PurgeOrphans {
            attachments: self.attachments.clone(),
            blobs: self.blobs.clone(),
            clock: self.world.env.clone(),
            config: self.config,
        }
    }

    /// An item of `who`, stored at revision 1. The account is made first when it isn't there: a write
    /// to a personal vault is checked against its account.
    async fn item_of(&self, who: &Actor) -> ItemId {
        self.account(who.user).await;
        let id = ItemId::random();
        self.world
            .put_item()
            .execute(who, write(who.user, id, None, 1))
            .await
            .expect("the item is stored");
        id
    }

    /// Makes the account `user` in the store, unless it is there already.
    async fn account(&self, user: UserId) {
        use kemlock_app::ports::UserRepo;
        use kemlock_domain::{AccountMode, Email, KdfParams, Role, User};
        if UserRepo::by_id(&self.world.store, user)
            .await
            .expect("a read")
            .is_some()
        {
            return;
        }
        let now = time::OffsetDateTime::now_utc();
        let account = User {
            id: user,
            email: Email::parse(&format!("{}@example.org", user.0)).expect("an email"),
            name: None,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account([1; 16]),
            opaque_record: None,
            wrapped_root_key: vec![1; 80],
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: 0,
            security_stamp: uuid::Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        };
        UserRepo::insert(&self.world.store, &account)
            .await
            .expect("the account");
    }

    /// Starts an upload of `size` bytes and returns the attachment.
    async fn started(&self, who: &Actor, item: ItemId, size: u64) -> Attachment {
        self.start()
            .execute(who, item, size)
            .await
            .expect("the upload starts")
            .attachment
    }

    /// Starts and completes an upload of `bytes`.
    async fn stored(&self, who: &Actor, item: ItemId, bytes: &[u8]) -> Attachment {
        let attachment = self.started(who, item, bytes.len() as u64).await;
        self.upload()
            .execute(
                who,
                item,
                attachment.id,
                bytes.len() as u64,
                &mut VecBody::new(bytes, 10),
            )
            .await
            .expect("the upload completes")
    }
}

fn someone() -> Actor {
    actor(UserId::random())
}

// ---------------------------------------------------------------------------------------------
// Start upload.

#[tokio::test]
async fn starting_records_a_pending_attachment_of_the_announced_size() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;

    let started = files
        .start()
        .execute(&me, item, 1234)
        .await
        .expect("starts");

    let a = &started.attachment;
    assert_eq!(a.item, item);
    assert_eq!(a.owner, Owner::User(me.user));
    assert_eq!(a.size, 1234);
    assert_eq!(a.status, AttachmentStatus::Pending);
    assert_eq!(a.created_at, files.world.env.now());
    assert_eq!(files.attachments.get(a.id), Some(a.clone()));
    assert_eq!(started.upload, None, "a local folder has no pre-signed URL");
    assert_eq!(files.blobs.count(), 0, "no bytes yet");
}

#[tokio::test]
async fn every_attachment_gets_its_own_random_blob() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    let b = files.started(&me, item, 100).await;
    assert_ne!(a.id, b.id);
    assert_ne!(a.blob, b.blob);
}

#[tokio::test]
async fn an_item_that_is_not_stored_yet_may_get_files() {
    // The client uploads first and writes the item after.
    let files = Files::new();
    let me = someone();
    let started = files.start().execute(&me, ItemId::random(), 100).await;
    assert!(started.is_ok());
}

#[tokio::test]
async fn another_accounts_item_is_forbidden() {
    let files = Files::new();
    let owner = someone();
    let item = files.item_of(&owner).await;
    let stranger = someone();
    assert_eq!(
        files.start().execute(&stranger, item, 100).await,
        Err(FileError::Forbidden)
    );
    assert_eq!(files.attachments.count(), 0);
}

#[tokio::test]
async fn a_deleted_item_has_no_files() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    files
        .world
        .put_item()
        .execute(&me, delete(me.user, item, 1, 2))
        .await
        .expect("the delete works");
    assert_eq!(
        files.start().execute(&me, item, 100).await,
        Err(FileError::NotFound)
    );
}

#[tokio::test]
async fn the_size_limit_is_enforced_and_empty_files_refused() {
    let files = Files::new().with_limit(1000);
    let me = someone();
    let item = files.item_of(&me).await;
    assert!(files.start().execute(&me, item, 1000).await.is_ok());
    assert_eq!(
        files.start().execute(&me, item, 1001).await,
        Err(FileError::TooLarge)
    );
    assert_eq!(
        files.start().execute(&me, item, 0).await,
        Err(FileError::Invalid("the file is empty"))
    );
}

#[tokio::test]
async fn the_default_limit_is_100_mib() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    assert!(
        files
            .start()
            .execute(&me, item, 100 * 1024 * 1024)
            .await
            .is_ok()
    );
    assert_eq!(
        files
            .start()
            .execute(&me, item, 100 * 1024 * 1024 + 1)
            .await,
        Err(FileError::TooLarge)
    );
}

#[tokio::test]
async fn a_presigning_store_adds_the_bucket_url() {
    let files = Files::with_blobs(FakeBlobs::presigning());
    let me = someone();
    let item = files.item_of(&me).await;
    let started = files.start().execute(&me, item, 100).await.expect("starts");
    let url = started.upload.expect("a pre-signed URL");
    assert!(url.url.contains(&started.attachment.blob.to_string()));
}

// ---------------------------------------------------------------------------------------------
// Upload bytes.

#[tokio::test]
async fn the_bytes_stream_into_storage_and_the_attachment_is_ready() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let bytes = kma1_bytes(5000);

    let a = files.stored(&me, item, &bytes).await;

    assert_eq!(a.status, AttachmentStatus::Ready);
    assert_eq!(files.blobs.get(a.blob), Some(bytes));
    assert_eq!(
        files.attachments.get(a.id).map(|r| r.status),
        Some(AttachmentStatus::Ready)
    );
    let event = files
        .world
        .store
        .events()
        .into_iter()
        .find(|e| e.action == "attachment.upload")
        .expect("an event");
    assert_eq!(event.actor, Some(me.user));
    assert_eq!(event.target, Some(a.id.to_string()));
}

#[tokio::test]
async fn a_file_is_uploaded_once() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let bytes = kma1_bytes(100);
    let a = files.stored(&me, item, &bytes).await;
    assert_eq!(
        files
            .upload()
            .execute(&me, item, a.id, 100, &mut VecBody::new(&bytes, 50))
            .await,
        Err(FileError::AlreadyUploaded)
    );
}

#[tokio::test]
async fn the_content_length_must_be_the_announced_size() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    let bytes = kma1_bytes(99);
    assert_eq!(
        files
            .upload()
            .execute(&me, item, a.id, 99, &mut VecBody::new(&bytes, 50))
            .await,
        Err(FileError::LengthMismatch)
    );
    assert_eq!(files.blobs.count(), 0);
}

#[tokio::test]
async fn a_body_longer_or_shorter_than_announced_is_refused_and_leaves_nothing() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    for actual in [60, 140] {
        let bytes = kma1_bytes(actual);
        assert_eq!(
            files
                .upload()
                .execute(&me, item, a.id, 100, &mut VecBody::new(&bytes, 25))
                .await,
            Err(FileError::LengthMismatch),
            "a body of {actual} bytes"
        );
    }
    assert_eq!(files.blobs.count(), 0);
    assert_eq!(
        files.attachments.get(a.id).map(|r| r.status),
        Some(AttachmentStatus::Pending),
        "the client may send it again"
    );
    // And a right one still works.
    files.stored_again(&me, item, &a, &kma1_bytes(100)).await;
}

impl Files {
    /// Uploads `bytes` to an attachment that is already started.
    async fn stored_again(&self, who: &Actor, item: ItemId, a: &Attachment, bytes: &[u8]) {
        self.upload()
            .execute(who, item, a.id, a.size, &mut VecBody::new(bytes, 33))
            .await
            .expect("the upload completes");
    }
}

#[tokio::test]
async fn bytes_that_are_not_kma1_are_refused() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    let mut zip = kma1_bytes(100);
    zip[..4].copy_from_slice(b"PK\x03\x04");
    let refused = files
        .upload()
        .execute(&me, item, a.id, 100, &mut VecBody::new(&zip, 100))
        .await;
    assert!(matches!(refused, Err(FileError::NotKma1(_))), "{refused:?}");
    assert_eq!(files.blobs.count(), 0);
    assert_eq!(
        files.attachments.get(a.id).map(|r| r.status),
        Some(AttachmentStatus::Pending)
    );
}

#[tokio::test]
async fn a_body_that_breaks_off_is_interrupted_and_leaves_nothing() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    let bytes = kma1_bytes(60);
    assert_eq!(
        files
            .upload()
            .execute(
                &me,
                item,
                a.id,
                100,
                &mut VecBody::new(&bytes, 20).then_breaks()
            )
            .await,
        Err(FileError::Interrupted)
    );
    assert_eq!(files.blobs.count(), 0);
}

#[tokio::test]
async fn a_limit_lowered_since_the_start_still_applies() {
    let mut files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 500).await;
    files.config.limits.max_size = 100;
    assert_eq!(
        files
            .upload()
            .execute(
                &me,
                item,
                a.id,
                500,
                &mut VecBody::new(&kma1_bytes(500), 100)
            )
            .await,
        Err(FileError::TooLarge)
    );
}

#[tokio::test]
async fn nobody_else_may_upload_to_a_file() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    let bytes = kma1_bytes(100);
    let stranger = someone();
    assert_eq!(
        files
            .upload()
            .execute(&stranger, item, a.id, 100, &mut VecBody::new(&bytes, 100))
            .await,
        Err(FileError::NotFound)
    );
    // Nor through another item's path.
    assert_eq!(
        files
            .upload()
            .execute(
                &me,
                ItemId::random(),
                a.id,
                100,
                &mut VecBody::new(&bytes, 100)
            )
            .await,
        Err(FileError::NotFound)
    );
}

// ---------------------------------------------------------------------------------------------
// Finish upload (pre-signed).

#[tokio::test]
async fn a_direct_upload_is_settled_by_finishing_it() {
    let files = Files::with_blobs(FakeBlobs::presigning());
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 200).await;
    files.blobs.put_directly(a.blob, kma1_bytes(200));

    let done = files
        .finish()
        .execute(&me, item, a.id)
        .await
        .expect("finishes");
    assert_eq!(done.status, AttachmentStatus::Ready);
    assert_eq!(
        files.attachments.get(a.id).map(|r| r.status),
        Some(AttachmentStatus::Ready)
    );
    // Finishing again, or finishing a file the server received itself, changes nothing.
    assert!(files.finish().execute(&me, item, a.id).await.is_ok());
}

#[tokio::test]
async fn finishing_before_the_bytes_arrive_is_refused() {
    let files = Files::with_blobs(FakeBlobs::presigning());
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 200).await;
    assert_eq!(
        files.finish().execute(&me, item, a.id).await,
        Err(FileError::Invalid("the file hasn't been uploaded"))
    );
}

#[tokio::test]
async fn a_direct_upload_of_the_wrong_size_or_kind_is_deleted() {
    let files = Files::with_blobs(FakeBlobs::presigning());
    let me = someone();
    let item = files.item_of(&me).await;

    let wrong_size = files.started(&me, item, 200).await;
    files.blobs.put_directly(wrong_size.blob, kma1_bytes(300));
    assert_eq!(
        files.finish().execute(&me, item, wrong_size.id).await,
        Err(FileError::LengthMismatch)
    );
    assert_eq!(files.blobs.get(wrong_size.blob), None);

    let not_kma1 = files.started(&me, item, 200).await;
    let mut other = kma1_bytes(200);
    other[0] = b'X';
    files.blobs.put_directly(not_kma1.blob, other);
    let refused = files.finish().execute(&me, item, not_kma1.id).await;
    assert!(matches!(refused, Err(FileError::NotKma1(_))), "{refused:?}");
    assert_eq!(files.blobs.get(not_kma1.blob), None);
    assert_eq!(
        files.attachments.get(not_kma1.id).map(|r| r.status),
        Some(AttachmentStatus::Pending)
    );
}

// ---------------------------------------------------------------------------------------------
// Download.

async fn read_all(downloaded: kemlock_app::files::Downloaded) -> Vec<u8> {
    let mut body = downloaded.read.body;
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("a chunk"));
    }
    assert_eq!(out.len() as u64, downloaded.read.size);
    out
}

#[tokio::test]
async fn a_ready_file_downloads_as_it_was_uploaded() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let bytes = kma1_bytes(777);
    let a = files.stored(&me, item, &bytes).await;

    let downloaded = files.download().open(&me, item, a.id).await.expect("opens");
    assert_eq!(downloaded.attachment.id, a.id);
    assert_eq!(read_all(downloaded).await, bytes);
}

#[tokio::test]
async fn a_pending_file_cannot_be_downloaded() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    assert!(matches!(
        files.download().open(&me, item, a.id).await,
        Err(FileError::NotFound)
    ));
}

#[tokio::test]
async fn nobody_else_can_download_a_file() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;
    assert!(matches!(
        files.download().open(&someone(), item, a.id).await,
        Err(FileError::NotFound)
    ));
    assert!(matches!(
        files.download().open(&me, ItemId::random(), a.id).await,
        Err(FileError::NotFound)
    ));
}

#[tokio::test]
async fn a_deleted_items_files_are_gone() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;
    files
        .world
        .put_item()
        .execute(&me, delete(me.user, item, 1, 2))
        .await
        .expect("the delete works");
    assert!(matches!(
        files.download().open(&me, item, a.id).await,
        Err(FileError::NotFound)
    ));
}

#[tokio::test]
async fn a_missing_blob_is_not_found() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;
    // The bytes are lost from storage.
    kemlock_app::files::BlobStore::delete(&files.blobs, a.blob)
        .await
        .expect("deleted");
    assert!(matches!(
        files.download().open(&me, item, a.id).await,
        Err(FileError::NotFound)
    ));
}

#[tokio::test]
async fn a_link_exists_only_with_presigning() {
    let local = Files::new();
    let me = someone();
    let item = local.item_of(&me).await;
    let a = local.stored(&me, item, &kma1_bytes(100)).await;
    assert_eq!(local.download().link(&me, item, a.id).await, Ok(None));

    let bucket = Files::with_blobs(FakeBlobs::presigning());
    let item = bucket.item_of(&me).await;
    let a = bucket.stored(&me, item, &kma1_bytes(100)).await;
    let link = bucket
        .download()
        .link(&me, item, a.id)
        .await
        .expect("a link")
        .expect("a pre-signed URL");
    assert!(link.url.ends_with("?get"));
}

// ---------------------------------------------------------------------------------------------
// Delete.

#[tokio::test]
async fn deleting_removes_the_bytes_and_the_row() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;

    files
        .delete()
        .execute(&me, item, a.id)
        .await
        .expect("deleted");

    assert_eq!(files.blobs.count(), 0);
    assert_eq!(files.attachments.get(a.id), None);
    assert!(
        files
            .world
            .store
            .events()
            .iter()
            .any(|e| e.action == "attachment.delete" && e.target == Some(a.id.to_string()))
    );
    assert_eq!(
        files.delete().execute(&me, item, a.id).await,
        Err(FileError::NotFound)
    );
}

#[tokio::test]
async fn nobody_else_can_delete_a_file() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;
    assert_eq!(
        files.delete().execute(&someone(), item, a.id).await,
        Err(FileError::NotFound)
    );
    assert_eq!(files.blobs.count(), 1);
}

#[tokio::test]
async fn a_blob_that_cannot_be_deleted_keeps_its_row() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.stored(&me, item, &kma1_bytes(100)).await;
    files.blobs.fail_deletes();
    assert!(matches!(
        files.delete().execute(&me, item, a.id).await,
        Err(FileError::Blob(_))
    ));
    assert!(
        files.attachments.get(a.id).is_some(),
        "a second delete can finish it"
    );
}

#[tokio::test]
async fn a_pending_file_can_be_deleted_too() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    files
        .delete()
        .execute(&me, item, a.id)
        .await
        .expect("deleted");
    assert_eq!(files.attachments.count(), 0);
}

// ---------------------------------------------------------------------------------------------
// Purge.

#[tokio::test]
async fn abandoned_uploads_and_files_of_purged_items_go_after_the_grace_period() {
    let files = Files::new();
    let me = someone();

    let live_item = files.item_of(&me).await;
    let kept = files.stored(&me, live_item, &kma1_bytes(100)).await;
    let abandoned = files.started(&me, live_item, 100).await;

    let purged_item = files.item_of(&me).await;
    let orphaned = files.stored(&me, purged_item, &kma1_bytes(100)).await;
    files.attachments.item_purged(purged_item);

    // Nothing is old enough yet.
    assert_eq!(files.purge().execute().await, Ok(0));

    files.world.env.clock.advance(Duration::hours(25));
    assert_eq!(files.purge().execute().await, Ok(2));

    assert!(files.attachments.get(kept.id).is_some());
    assert!(files.blobs.get(kept.blob).is_some());
    assert_eq!(files.attachments.get(abandoned.id), None);
    assert_eq!(files.attachments.get(orphaned.id), None);
    assert_eq!(files.blobs.get(orphaned.blob), None);
    assert_eq!(
        files.purge().execute().await,
        Ok(0),
        "nothing is left to purge"
    );
}

#[tokio::test]
async fn a_long_backlog_is_purged_in_rounds() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    for _ in 0..250 {
        files.attachments.insert(Attachment {
            id: AttachmentId::random(),
            item,
            owner: Owner::User(me.user),
            blob: BlobId::random(),
            size: 100,
            status: AttachmentStatus::Pending,
            created_at: files.world.env.now() - Duration::days(3),
        });
    }
    assert_eq!(files.purge().execute().await, Ok(250));
    assert_eq!(files.attachments.count(), 0);
}

#[tokio::test]
async fn a_blob_that_cannot_be_deleted_stops_the_purge_and_keeps_its_row() {
    let files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    let a = files.started(&me, item, 100).await;
    files.world.env.clock.advance(Duration::days(2));
    files.blobs.fail_deletes();
    assert!(matches!(
        files.purge().execute().await,
        Err(FileError::Blob(_))
    ));
    assert!(files.attachments.get(a.id).is_some());
}

#[tokio::test]
async fn the_users_quota_counts_what_they_store_and_a_quota_of_zero_is_off() {
    let mut files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;

    // No quota set: any size goes.
    assert!(files.start().execute(&me, item, 5_000).await.is_ok());

    // A quota of 10 KB with 5 KB used: 5 KB fits, one byte more does not.
    files.config.user_quota = Some(10_000);
    assert!(files.start().execute(&me, item, 5_000).await.is_ok());
    assert_eq!(
        files.start().execute(&me, item, 1).await,
        Err(FileError::Quota(QuotaRefusal::Reached))
    );
    files.config.user_quota = Some(12_000);
    assert_eq!(
        files.start().execute(&me, item, 2_001).await,
        Err(FileError::Quota(QuotaRefusal::Exceeded))
    );
    assert!(files.start().execute(&me, item, 2_000).await.is_ok());

    // Zero switches attachments off, whatever is stored.
    files.config.user_quota = Some(0);
    assert_eq!(
        files.start().execute(&me, item, 1).await,
        Err(FileError::Quota(QuotaRefusal::Disabled))
    );
    // Another account's use doesn't count against this one.
    let you = someone();
    let their_item = files.item_of(&you).await;
    files.config.user_quota = Some(5_000);
    assert!(files.start().execute(&you, their_item, 5_000).await.is_ok());
}

#[tokio::test]
async fn a_quota_lowered_after_the_announce_is_held_to_when_the_bytes_arrive() {
    let mut files = Files::new();
    let me = someone();
    let item = files.item_of(&me).await;
    files.config.user_quota = Some(10_000);
    let a = files.started(&me, item, 5_000).await;

    // The quota drops below the file: the bytes are refused and nothing is kept.
    files.config.user_quota = Some(4_000);
    let bytes = kma1_bytes(5_000);
    let refused = files
        .upload()
        .execute(&me, item, a.id, 5_000, &mut VecBody::new(&bytes, 100))
        .await;
    assert_eq!(refused, Err(FileError::Quota(QuotaRefusal::Exceeded)));
    assert_eq!(files.blobs.count(), 0);

    // Switched off, it refuses too; at a limit the file fits, it goes through.
    files.config.user_quota = Some(0);
    let refused = files
        .upload()
        .execute(&me, item, a.id, 5_000, &mut VecBody::new(&bytes, 100))
        .await;
    assert_eq!(refused, Err(FileError::Quota(QuotaRefusal::Disabled)));
    files.config.user_quota = Some(5_000);
    files.stored_again(&me, item, &a, &bytes).await;
}
