//! `SendRepo` on a real `SqlStore`: rows round-trip, the view count is held to its limit under
//! contention, and the job's query finds what is due.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, and PostgreSQL and
//! MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, memory, unique_email, user};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::quota::QuotaRefusal;
use kemlock_app::sends::SendRepo;
use kemlock_domain::sends::{SendFile, SendFileFormat, SendId, SendKind, SendPassword, SendRecord};
use kemlock_domain::{BlobId, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const MADE: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

async fn owner(store: &SqlStore) -> UserId {
    let account = user(&unique_email("send-owner"));
    UserRepo::insert(store, &account)
        .await
        .expect("the account is stored");
    account.id
}

fn note(owner: UserId) -> SendRecord {
    SendRecord {
        id: SendId::random(),
        owner,
        kind: SendKind::Text,
        meta: vec![1; 40],
        sealed_key: vec![2; 100],
        payload: vec![3; 60],
        file: None,
        password: None,
        max_access: None,
        access_count: 0,
        hide_email: false,
        disabled: false,
        expires_at: None,
        deletion_at: MADE + Duration::days(7),
        created_at: MADE,
        revised_at: MADE,
    }
}

fn file_send(owner: UserId, ready: bool) -> SendRecord {
    SendRecord {
        kind: SendKind::File,
        file: Some(SendFile {
            blob: BlobId::random(),
            size: 65_680,
            format: SendFileFormat::Kma1,
            ready,
        }),
        ..note(owner)
    }
}

async fn round_trip(store: &SqlStore) {
    let owner = owner(store).await;
    let mut with_password = note(owner);
    with_password.password = Some(SendPassword {
        salt: vec![4; 32],
        hash: vec![5; 32],
    });
    with_password.max_access = Some(3);
    with_password.hide_email = true;
    with_password.expires_at = Some(MADE + Duration::days(2));
    let file = file_send(owner, false);
    // A payload well over a 64 KiB `BLOB` still fits.
    let mut big = note(owner);
    big.payload = vec![7; 200 * 1024];

    for send in [with_password, file, big] {
        SendRepo::add_send(store, &send).await.expect("stored");
        assert_eq!(
            SendRepo::send_by_id(store, send.id).await,
            Ok(Some(send.clone()))
        );
    }
    assert_eq!(
        SendRepo::send_by_id(store, SendId::random()).await,
        Ok(None)
    );
}

async fn ids_and_owners_are_checked(store: &SqlStore) {
    let owner = owner(store).await;
    let send = note(owner);
    SendRepo::add_send(store, &send).await.expect("stored");
    assert_eq!(
        SendRepo::add_send(store, &send).await,
        Err(StoreError::Duplicate)
    );
    // A Send of an account that doesn't exist has nowhere to belong.
    let orphan = note(UserId::random());
    assert_eq!(
        SendRepo::add_send(store, &orphan).await,
        Err(StoreError::NotFound)
    );
}

async fn lists_are_the_owners_newest_first(store: &SqlStore) {
    let sam = owner(store).await;
    let ann = owner(store).await;
    let first = SendRecord {
        created_at: MADE,
        ..note(sam)
    };
    let second = SendRecord {
        created_at: MADE + Duration::hours(1),
        ..note(sam)
    };
    let theirs = note(ann);
    for send in [&first, &second, &theirs] {
        SendRepo::add_send(store, send).await.expect("stored");
    }
    let listed = SendRepo::sends_of(store, sam).await.expect("listed");
    let ids: Vec<SendId> = listed.iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![second.id, first.id]);
    assert_eq!(
        SendRepo::sends_of(store, UserId::random()).await,
        Ok(Vec::new())
    );
}

async fn an_update_writes_what_an_owner_may_change_and_nothing_else(store: &SqlStore) {
    let owner = owner(store).await;
    let mut send = note(owner);
    send.access_count = 4;
    SendRepo::add_send(store, &send).await.expect("stored");

    let mut changed = send.clone();
    changed.meta = vec![9; 20];
    changed.payload = vec![8; 33];
    changed.password = Some(SendPassword {
        salt: vec![1; 32],
        hash: vec![2; 32],
    });
    changed.max_access = Some(10);
    changed.hide_email = true;
    changed.disabled = true;
    changed.expires_at = Some(MADE + Duration::days(1));
    changed.deletion_at = MADE + Duration::days(3);
    changed.revised_at = MADE + Duration::minutes(5);
    // These are not the owner's to change here.
    changed.sealed_key = vec![0; 5];
    changed.access_count = 99;
    changed.created_at = MADE - Duration::days(9);

    SendRepo::update_send(store, &changed)
        .await
        .expect("updated");
    let stored = SendRepo::send_by_id(store, send.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.meta, vec![9; 20]);
    assert_eq!(stored.payload, vec![8; 33]);
    assert_eq!(stored.password, changed.password);
    assert_eq!(stored.max_access, Some(10));
    assert!(stored.hide_email && stored.disabled);
    assert_eq!(stored.expires_at, changed.expires_at);
    assert_eq!(stored.deletion_at, changed.deletion_at);
    assert_eq!(stored.revised_at, changed.revised_at);
    assert_eq!(stored.sealed_key, send.sealed_key);
    assert_eq!(stored.access_count, 4);
    assert_eq!(stored.created_at, MADE);

    // Taking the password away clears both columns.
    changed.password = None;
    SendRepo::update_send(store, &changed)
        .await
        .expect("updated");
    let stored = SendRepo::send_by_id(store, send.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.password, None);

    let gone = note(owner);
    assert_eq!(
        SendRepo::update_send(store, &gone).await,
        Err(StoreError::NotFound)
    );
}

async fn a_file_becomes_ready_once(store: &SqlStore) {
    let owner = owner(store).await;
    let send = file_send(owner, false);
    SendRepo::add_send(store, &send).await.expect("stored");
    assert_eq!(
        SendRepo::mark_send_file_ready(store, send.id).await,
        Ok(true)
    );
    assert_eq!(
        SendRepo::mark_send_file_ready(store, send.id).await,
        Ok(false)
    );
    let stored = SendRepo::send_by_id(store, send.id)
        .await
        .expect("read")
        .expect("there");
    assert!(stored.file.expect("a file").ready);

    // A note has no file to ready, and an unknown Send is not there.
    let text = note(owner);
    SendRepo::add_send(store, &text).await.expect("stored");
    assert_eq!(
        SendRepo::mark_send_file_ready(store, text.id).await,
        Ok(false)
    );
    assert_eq!(
        SendRepo::mark_send_file_ready(store, SendId::random()).await,
        Ok(false)
    );
}

async fn views_stop_at_the_limit(store: &SqlStore) {
    let owner = owner(store).await;
    let limited = SendRecord {
        max_access: Some(2),
        ..note(owner)
    };
    let unlimited = note(owner);
    SendRepo::add_send(store, &limited).await.expect("stored");
    SendRepo::add_send(store, &unlimited).await.expect("stored");
    let at = MADE + Duration::minutes(3);

    assert_eq!(
        SendRepo::count_send_view(store, limited.id, at).await,
        Ok(true)
    );
    assert_eq!(
        SendRepo::count_send_view(store, limited.id, at).await,
        Ok(true)
    );
    assert_eq!(
        SendRepo::count_send_view(store, limited.id, at).await,
        Ok(false)
    );
    let stored = SendRepo::send_by_id(store, limited.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.access_count, 2);
    assert_eq!(stored.revised_at, at);

    for _ in 0..5 {
        assert_eq!(
            SendRepo::count_send_view(store, unlimited.id, at).await,
            Ok(true)
        );
    }
    assert_eq!(
        SendRepo::send_by_id(store, unlimited.id)
            .await
            .expect("read")
            .expect("there")
            .access_count,
        5
    );
    assert_eq!(
        SendRepo::count_send_view(store, SendId::random(), at).await,
        Ok(false)
    );
}

async fn racing_openers_cannot_exceed_the_limit(store: &SqlStore) {
    let owner = owner(store).await;
    let send = SendRecord {
        max_access: Some(3),
        ..note(owner)
    };
    SendRepo::add_send(store, &send).await.expect("stored");

    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        let id = send.id;
        tasks.push(tokio::spawn(async move {
            SendRepo::count_send_view(&store, id, MADE).await
        }));
    }
    let mut counted = 0;
    for task in tasks {
        if task.await.expect("the task ran").expect("no store error") {
            counted += 1;
        }
    }
    assert_eq!(
        counted, 3,
        "exactly the limit's worth of openers got a view"
    );
    let stored = SendRepo::send_by_id(store, send.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.access_count, 3);
}

async fn the_job_finds_what_is_due(store: &SqlStore) {
    let owner = owner(store).await;
    // A time before every other scenario's Sends, so only the rows made here are due.
    let now = MADE - Duration::days(30);
    let abandoned_before = now - Duration::hours(24);

    let due_note = SendRecord {
        deletion_at: now - Duration::minutes(1),
        ..note(owner)
    };
    let due_at_the_second = SendRecord {
        deletion_at: now,
        ..note(owner)
    };
    let later = SendRecord {
        deletion_at: now + Duration::days(1),
        ..note(owner)
    };
    // Waiting for its bytes since long ago: abandoned. Since a moment ago: still waiting.
    let abandoned = SendRecord {
        created_at: abandoned_before - Duration::hours(1),
        deletion_at: now + Duration::days(5),
        ..file_send(owner, false)
    };
    let waiting = SendRecord {
        created_at: now - Duration::hours(1),
        deletion_at: now + Duration::days(5),
        ..file_send(owner, false)
    };
    let uploaded = SendRecord {
        created_at: abandoned_before - Duration::hours(1),
        deletion_at: now + Duration::days(5),
        ..file_send(owner, true)
    };
    for send in [
        &due_note,
        &due_at_the_second,
        &later,
        &abandoned,
        &waiting,
        &uploaded,
    ] {
        SendRepo::add_send(store, send).await.expect("stored");
    }

    let due = SendRepo::sends_to_delete(store, now, abandoned_before, 100)
        .await
        .expect("the query runs");
    let mut found: Vec<SendId> = due.iter().map(|s| s.id).collect();
    found.sort();
    let mut expected = vec![due_note.id, due_at_the_second.id, abandoned.id];
    expected.sort();
    assert_eq!(found, expected);

    // The limit holds, and removing makes a row not due any more; removing twice is fine.
    let one = SendRepo::sends_to_delete(store, now, abandoned_before, 1)
        .await
        .expect("limited");
    assert_eq!(one.len(), 1);
    for send in &due {
        SendRepo::remove_send(store, send.id)
            .await
            .expect("removed");
    }
    SendRepo::remove_send(store, due_note.id)
        .await
        .expect("a second remove is fine");
    assert_eq!(
        SendRepo::sends_to_delete(store, now, abandoned_before, 100).await,
        Ok(Vec::new())
    );
    assert!(
        SendRepo::send_by_id(store, later.id)
            .await
            .expect("read")
            .is_some()
    );
}

async fn an_overwrite_changes_the_key_but_not_the_count_or_the_owner(store: &SqlStore) {
    let owner = owner(store).await;
    let mut send = note(owner);
    send.access_count = 4;
    SendRepo::add_send(store, &send).await.expect("stored");

    let mut changed = send.clone();
    changed.sealed_key = vec![6; 77];
    changed.payload = vec![8; 33];
    changed.max_access = Some(9);
    changed.access_count = 0;
    changed.owner = UserId::random();
    changed.revised_at = MADE + Duration::hours(3);
    store.overwrite_send(&changed).await.expect("written");

    let stored = SendRepo::send_by_id(store, send.id)
        .await
        .expect("read")
        .expect("there");
    assert_eq!(stored.sealed_key, vec![6; 77]);
    assert_eq!(stored.payload, vec![8; 33]);
    assert_eq!(stored.max_access, Some(9));
    assert_eq!(stored.revised_at, MADE + Duration::hours(3));
    assert_eq!(stored.access_count, 4, "the count is kept");
    assert_eq!(stored.owner, owner);

    assert_eq!(
        store.overwrite_send(&note(owner)).await,
        Err(StoreError::NotFound)
    );
}

/// File Sends made together are held to the quota: only as many as fit are stored.
async fn racing_file_sends_cannot_exceed_the_quota(store: &SqlStore) {
    let owner = owner(store).await;
    // Room for two files of 65 680 bytes, and a third byte over.
    let quota = Some(2 * 65_680 + 10);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let send = file_send(owner, false);
        tasks.spawn(async move { SendRepo::add_send_within_quota(&store, &send, quota).await });
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
    assert_eq!(stored, 2);
    assert_eq!(
        SendRepo::sends_of(store, owner).await.expect("list").len(),
        2
    );

    // A note takes no space, whatever the quota.
    assert_eq!(
        SendRepo::add_send_within_quota(store, &note(owner), Some(1)).await,
        Ok(Ok(()))
    );
}

async fn run_all(store: &SqlStore) {
    round_trip(store).await;
    ids_and_owners_are_checked(store).await;
    lists_are_the_owners_newest_first(store).await;
    an_update_writes_what_an_owner_may_change_and_nothing_else(store).await;
    an_overwrite_changes_the_key_but_not_the_count_or_the_owner(store).await;
    a_file_becomes_ready_once(store).await;
    views_stop_at_the_limit(store).await;
    racing_openers_cannot_exceed_the_limit(store).await;
    the_job_finds_what_is_due(store).await;
    racing_file_sends_cannot_exceed_the_quota(store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}
