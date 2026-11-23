//! `AttachmentRepo`: rows, the pending-to-ready step and the orphan query, which reads the items
//! table.
//!
//! Each scenario runs on every backend that is available (see `accounts.rs`) and uses owners, items
//! and attachments of its own, looking only at its own rows, so a database kept between runs does
//! not disturb it.

mod common;

use common::{MADE_AT, draft, external, file, memory, put, tombstone, user_owner};
use kemlock_app::files::AttachmentRepo;
use kemlock_app::ports::{ItemStore, StoreError};
use kemlock_app::quota::QuotaRefusal;
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, BlobId, ItemId, Owner};
use kemlock_store_sql::SqlStore;
use time::Duration;
use time::macros::datetime;

const CREATED: time::OffsetDateTime = datetime!(2026-03-01 10:00:00 UTC);

fn attachment(item: ItemId, owner: Owner, status: AttachmentStatus) -> Attachment {
    Attachment {
        id: AttachmentId::random(),
        item,
        owner,
        blob: BlobId::random(),
        size: 65_680,
        status,
        created_at: CREATED,
    }
}

async fn add(store: &SqlStore, a: &Attachment) {
    AttachmentRepo::add(store, a).await.expect("added");
}

async fn by_id(store: &SqlStore, id: AttachmentId) -> Option<Attachment> {
    AttachmentRepo::by_id(store, id).await.expect("by_id")
}

async fn orphans(store: &SqlStore, before: time::OffsetDateTime) -> Vec<AttachmentId> {
    AttachmentRepo::orphans(store, before, 1000)
        .await
        .expect("orphans")
        .into_iter()
        .map(|a| a.id)
        .collect()
}

async fn rows_round_trip(store: &SqlStore) {
    let owner = user_owner();
    let a = attachment(ItemId::random(), owner, AttachmentStatus::Pending);
    assert_eq!(by_id(store, a.id).await, None);

    add(store, &a).await;
    assert_eq!(by_id(store, a.id).await, Some(a.clone()));

    // An id is taken once, and so is a blob.
    assert_eq!(
        AttachmentRepo::add(store, &a).await,
        Err(StoreError::Duplicate)
    );
    let same_blob = Attachment {
        id: AttachmentId::random(),
        ..a.clone()
    };
    assert_eq!(
        AttachmentRepo::add(store, &same_blob).await,
        Err(StoreError::Duplicate)
    );

    // A space's attachment keeps its owner kind.
    let space = Owner::Space(kemlock_domain::SpaceId::random());
    let s = attachment(ItemId::random(), space, AttachmentStatus::Ready);
    add(store, &s).await;
    assert_eq!(by_id(store, s.id).await, Some(s));
}

async fn pending_becomes_ready_once(store: &SqlStore) {
    let a = attachment(ItemId::random(), user_owner(), AttachmentStatus::Pending);
    add(store, &a).await;

    assert_eq!(AttachmentRepo::mark_ready(store, a.id).await, Ok(true));
    assert_eq!(
        by_id(store, a.id).await.map(|r| r.status),
        Some(AttachmentStatus::Ready)
    );
    assert_eq!(
        AttachmentRepo::mark_ready(store, a.id).await,
        Ok(false),
        "the second finisher is told it came second"
    );
    assert_eq!(
        AttachmentRepo::mark_ready(store, AttachmentId::random()).await,
        Ok(false),
        "an unknown id"
    );
}

async fn remove_is_idempotent(store: &SqlStore) {
    let a = attachment(ItemId::random(), user_owner(), AttachmentStatus::Ready);
    add(store, &a).await;
    AttachmentRepo::remove(store, a.id).await.expect("removed");
    assert_eq!(by_id(store, a.id).await, None);
    AttachmentRepo::remove(store, a.id)
        .await
        .expect("removing a gone row is fine");
    AttachmentRepo::remove(store, AttachmentId::random())
        .await
        .expect("and so is an unknown id");
}

async fn orphans_are_old_pending_rows_and_rows_without_an_item(store: &SqlStore) {
    let owner = user_owner();
    let before = CREATED + Duration::days(1);

    // An item that exists, with an abandoned upload, a finished file and a young upload.
    let live = ItemId::random();
    put(store, draft(live, owner, None, 1)).await;
    let abandoned = attachment(live, owner, AttachmentStatus::Pending);
    let kept = attachment(live, owner, AttachmentStatus::Ready);
    let young = Attachment {
        created_at: before + Duration::hours(1),
        ..attachment(live, owner, AttachmentStatus::Pending)
    };

    // A file whose item was never written, and a young one.
    let never = attachment(ItemId::random(), owner, AttachmentStatus::Ready);
    let young_never = Attachment {
        created_at: before + Duration::hours(1),
        ..attachment(ItemId::random(), owner, AttachmentStatus::Ready)
    };

    // A file of a deleted item: not an orphan while the tombstone is there, one once it is purged.
    let gone = ItemId::random();
    put(store, draft(gone, owner, None, 1)).await;
    put(store, tombstone(gone, owner, Some(1), 2, MADE_AT)).await;
    let of_tombstone = attachment(gone, owner, AttachmentStatus::Ready);

    for a in [
        &abandoned,
        &kept,
        &young,
        &never,
        &young_never,
        &of_tombstone,
    ] {
        add(store, a).await;
    }

    let found = orphans(store, before).await;
    assert!(found.contains(&abandoned.id), "an abandoned upload");
    assert!(found.contains(&never.id), "a file whose item never came");
    for (id, why) in [
        (kept.id, "a finished file of a live item"),
        (young.id, "an upload still within the grace period"),
        (young_never.id, "a young file whose item may still come"),
        (of_tombstone.id, "a file of a tombstone not yet purged"),
    ] {
        assert!(!found.contains(&id), "{why}");
    }

    ItemStore::purge_tombstones(store, MADE_AT + Duration::hours(1))
        .await
        .expect("purged");
    let found = orphans(store, before).await;
    assert!(
        found.contains(&of_tombstone.id),
        "once the tombstone is purged its files are orphans"
    );
    assert!(!found.contains(&kept.id));

    // Oldest first, and the limit is honoured.
    let one = AttachmentRepo::orphans(store, before, 1)
        .await
        .expect("limited");
    assert_eq!(one.len(), 1);
    let none = AttachmentRepo::orphans(store, CREATED - Duration::days(365), 1000)
        .await
        .expect("nothing is that old");
    assert!(
        none.iter()
            .all(|a| a.created_at < CREATED - Duration::days(365))
    );
}

async fn an_owners_bytes_add_up_pending_rows_included(store: &SqlStore) {
    let owner = user_owner();
    let other = user_owner();
    assert_eq!(AttachmentRepo::attachment_bytes(store, owner).await, Ok(0));
    let mut ready = attachment(ItemId::random(), owner, AttachmentStatus::Ready);
    ready.size = 1_000;
    let mut pending = attachment(ItemId::random(), owner, AttachmentStatus::Pending);
    pending.size = 250;
    let mut theirs = attachment(ItemId::random(), other, AttachmentStatus::Ready);
    theirs.size = 7_000;
    for a in [&ready, &pending, &theirs] {
        add(store, a).await;
    }
    assert_eq!(
        AttachmentRepo::attachment_bytes(store, owner).await,
        Ok(1_250)
    );
    assert_eq!(
        AttachmentRepo::attachment_bytes(store, other).await,
        Ok(7_000)
    );
}

/// Announces that arrive together are held to the quota: only as many as fit are stored.
async fn racing_announces_cannot_exceed_the_quota(store: &SqlStore) {
    let owner = user_owner();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let mut a = attachment(ItemId::random(), owner, AttachmentStatus::Pending);
        a.size = 400;
        tasks.spawn(async move { AttachmentRepo::add_within_quota(&store, &a, Some(1_000)).await });
    }
    let mut stored = 0;
    while let Some(done) = tasks.join_next().await {
        match done.expect("the task ran").expect("the store answered") {
            Ok(()) => stored += 1,
            Err(refusal) => assert!(matches!(
                refusal,
                QuotaRefusal::Reached | QuotaRefusal::Exceeded
            )),
        }
    }
    assert_eq!(stored, 2, "1000 bytes hold two files of 400");
    assert_eq!(
        AttachmentRepo::attachment_bytes(store, owner).await,
        Ok(800)
    );

    // No limit stores whatever comes; a limit of zero refuses everything.
    let mut free = attachment(ItemId::random(), owner, AttachmentStatus::Pending);
    free.size = 5_000;
    assert_eq!(
        AttachmentRepo::add_within_quota(store, &free, None).await,
        Ok(Ok(()))
    );
    let off = attachment(ItemId::random(), owner, AttachmentStatus::Pending);
    assert_eq!(
        AttachmentRepo::add_within_quota(store, &off, Some(0)).await,
        Ok(Err(QuotaRefusal::Disabled))
    );
    assert_eq!(by_id(store, off.id).await, None);
}

async fn run_all(store: &SqlStore) {
    rows_round_trip(store).await;
    pending_becomes_ready_once(store).await;
    remove_is_idempotent(store).await;
    orphans_are_old_pending_rows_and_rows_without_an_item(store).await;
    an_owners_bytes_add_up_pending_rows_included(store).await;
    racing_announces_cannot_exceed_the_quota(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}
