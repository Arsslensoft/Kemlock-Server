//! `SendSync` on a real `SqlStore`: the Sends federation lists and copies, the rows a replica adds
//! and updates, and the marker that tells a copy from a Send made on the server.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, and PostgreSQL and
//! MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, memory, unique_email, user};
use kemlock_app::ports::UserRepo;
use kemlock_app::sends::SendRepo;
use kemlock_domain::sends::{SendFile, SendFileFormat, SendId, SendKind, SendRecord};
use kemlock_domain::{BlobId, Owner, ServerId, UserId};
use kemlock_federation::sendsync::{SendApply, SendSync};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const MADE: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

async fn owner(store: &SqlStore) -> UserId {
    let account = user(&unique_email("send-copy"));
    UserRepo::insert(store, &account).await.expect("account");
    account.id
}

fn note(owner: UserId) -> SendRecord {
    SendRecord {
        id: SendId::random(),
        owner,
        kind: SendKind::Text,
        meta: vec![1; 40],
        sealed_key: vec![2; 64],
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

async fn only_what_is_open_to_a_peer_is_listed_in_id_order(store: &SqlStore) {
    let user = owner(store).await;
    let other = owner(store).await;
    let first = note(user);
    let ready = file_send(user, true);
    let waiting = file_send(user, false);
    let theirs = note(other);
    for send in [&first, &ready, &waiting, &theirs] {
        SendRepo::add_send(store, send).await.expect("add");
    }
    let listed = store
        .sends_after(Owner::User(user), SendId(uuid::Uuid::nil()), 10, ServerId::random())
        .await
        .expect("list");
    let mut want = vec![first.id, ready.id];
    want.sort();
    let got: Vec<SendId> = listed.iter().map(|s| s.id).collect();
    assert_eq!(got, want, "the file whose bytes haven't arrived is not listed");

    // A page after the first id has the other one only.
    let page = store
        .sends_after(Owner::User(user), want[0], 10, ServerId::random())
        .await
        .expect("page");
    assert_eq!(page.iter().map(|s| s.id).collect::<Vec<_>>(), vec![want[1]]);
    let one = store
        .sends_after(Owner::User(user), SendId(uuid::Uuid::nil()), 1, ServerId::random())
        .await
        .expect("limited");
    assert_eq!(one.len(), 1);

    // A space has none, and a file Send is found by its blob.
    assert!(
        store
            .sends_after(
                Owner::Space(kemlock_domain::SpaceId::random()),
                SendId(uuid::Uuid::nil()),
                10,
                ServerId::random()
            )
            .await
            .expect("space")
            .is_empty()
    );
    let blob = ready.file.expect("file").blob;
    assert_eq!(store.send_of_blob(blob).await, Ok(Some(ready)));
    assert_eq!(store.send_of_blob(BlobId::random()).await, Ok(None));
}

async fn a_copy_is_not_handed_back_to_the_server_it_came_from(store: &SqlStore) {
    let user = owner(store).await;
    let (home, third) = (ServerId::random(), ServerId::random());
    let copied = note(user);
    let own = note(user);
    SendRepo::add_send(store, &own).await.expect("own");
    assert_eq!(
        store.apply_replicated_send(home, &copied).await,
        Ok(SendApply::Added)
    );
    let nil = SendId(uuid::Uuid::nil());
    let ids = |sends: Vec<SendRecord>| {
        let mut ids: Vec<SendId> = sends.iter().map(|s| s.id).collect();
        ids.sort();
        ids
    };
    // The home gets only what was made here; any other server gets both.
    let to_home = store
        .sends_after(Owner::User(user), nil, 10, home)
        .await
        .expect("to home");
    assert_eq!(ids(to_home), vec![own.id]);
    let to_third = store
        .sends_after(Owner::User(user), nil, 10, third)
        .await
        .expect("to third");
    let mut both = vec![own.id, copied.id];
    both.sort();
    assert_eq!(ids(to_third), both);
}

async fn a_copy_is_added_updated_and_dropped_but_a_local_send_is_not(store: &SqlStore) {
    let user = owner(store).await;
    let vault = Owner::User(user);
    let home = ServerId::random();

    let copied = file_send(user, true);
    assert_eq!(
        store.apply_replicated_send(home, &copied).await,
        Ok(SendApply::Added)
    );
    assert_eq!(store.send_row(copied.id).await, Ok(Some(copied.clone())));
    assert_eq!(
        store.apply_replicated_send(home, &copied).await,
        Ok(SendApply::Unchanged)
    );

    // A newer revision takes the options, and a higher view count.
    let mut at_home = copied.clone();
    at_home.revised_at = MADE + Duration::hours(2);
    at_home.disabled = true;
    at_home.max_access = Some(3);
    at_home.access_count = 1;
    assert_eq!(
        store.apply_replicated_send(home, &at_home).await,
        Ok(SendApply::Updated)
    );
    let held = store.send_row(copied.id).await.expect("row").expect("held");
    assert!(held.disabled);
    assert_eq!(held.max_access, Some(3));
    assert_eq!(held.revised_at, MADE + Duration::hours(2));
    assert_eq!(held.file, copied.file, "the file never changes");

    // The same id under another owner is refused.
    let other = owner(store).await;
    let hijack = SendRecord {
        owner: other,
        ..copied.clone()
    };
    assert_eq!(
        store.apply_replicated_send(home, &hijack).await,
        Ok(SendApply::Unchanged)
    );

    // A Send made here is not a copy: it is neither listed as one nor dropped.
    let local = note(user);
    SendRepo::add_send(store, &local).await.expect("local send");
    assert_eq!(
        store.replicated_send_ids(vault, home).await,
        Ok(vec![copied.id])
    );
    assert_eq!(store.replicated_send_ids(vault, ServerId::random()).await, Ok(vec![]));
    assert_eq!(store.drop_replicated_send(local.id).await, Ok(None));
    assert!(store.send_row(local.id).await.expect("row").is_some());

    // Dropping a copy deletes the row and says which file went with it.
    assert_eq!(
        store.drop_replicated_send(copied.id).await,
        Ok(copied.file.map(|f| f.blob))
    );
    assert_eq!(store.send_row(copied.id).await, Ok(None));
    assert_eq!(store.replicated_send_ids(vault, home).await, Ok(vec![]));
}

async fn run_all(store: &SqlStore) {
    only_what_is_open_to_a_peer_is_listed_in_id_order(store).await;
    a_copy_is_not_handed_back_to_the_server_it_came_from(store).await;
    a_copy_is_added_updated_and_dropped_but_a_local_send_is_not(store).await;
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
