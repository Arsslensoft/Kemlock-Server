//! Connecting, migrating, reopening: the server id, the migration lock and the SQLite setup.

mod common;

use common::{draft, external, file_url, memory, put, user_owner};
use kemlock_app::ports::{ItemStore, ServerInfo, StoreError};
use kemlock_domain::ItemId;
use kemlock_store_sql::{SqlStore, SqliteSync, StoreOptions};

#[tokio::test]
async fn the_server_id_is_made_once_and_kept_across_reopens() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("kemlock.db"));

    let store = SqlStore::connect(&url).await.expect("first connect");
    let id = ServerInfo::server_id(&store);
    assert_eq!(id.0.get_version_num(), 4);

    let owner = user_owner();
    let item = ItemId::random();
    let written = put(&store, draft(item, owner, None, 1)).await;
    assert_eq!(written.change.origin, id);
    store.close().await.expect("close");

    let reopened = SqlStore::connect(&url).await.expect("second connect");
    assert_eq!(ServerInfo::server_id(&reopened), id, "the id never changes");
    assert_eq!(
        ItemStore::get(&reopened, item).await.expect("get"),
        Some(written.clone())
    );
    // The sequence counter was kept too.
    let next = put(&reopened, draft(item, owner, Some(1), 2)).await;
    assert_eq!(next.change.seq, written.change.seq + 1);
    assert_eq!(next.change.origin, id);

    // Two handles at once see the same server, and each other's writes.
    let second = SqlStore::connect(&url).await.expect("third connect");
    assert_eq!(ServerInfo::server_id(&second), id);
    assert_eq!(
        ItemStore::get(&second, item).await.expect("get"),
        Some(next)
    );
}

#[tokio::test]
async fn separate_databases_have_separate_ids() {
    let a = memory().await;
    let b = memory().await;
    assert_ne!(ServerInfo::server_id(&a), ServerInfo::server_id(&b));
}

#[tokio::test]
async fn migrating_again_changes_nothing() {
    let store = memory().await;
    let item = ItemId::random();
    let written = put(&store, draft(item, user_owner(), None, 1)).await;

    store.migrate().await.expect("a second migrate");
    store.migrate().await.expect("a third migrate");

    assert_eq!(
        ItemStore::get(&store, item).await.expect("get"),
        Some(written)
    );
    store.ping().await.expect("ping");
}

#[tokio::test]
async fn migrations_are_safe_on_a_database_kept_between_runs() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("kemlock.db"));
    for _ in 0..3 {
        let store = SqlStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        store.close().await.expect("close");
    }
}

#[tokio::test]
async fn sqlite_options_are_accepted() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("kemlock.db"));
    let store = SqlStore::connect_with(
        &url,
        StoreOptions {
            sqlite_sync: SqliteSync::Normal,
            sqlite_readers: 1,
            ..StoreOptions::default()
        },
    )
    .await
    .expect("connect");
    let item = ItemId::random();
    let written = put(&store, draft(item, user_owner(), None, 1)).await;
    assert_eq!(
        ItemStore::get(&store, item).await.expect("get"),
        Some(written)
    );
}

#[tokio::test]
async fn reads_proceed_while_the_writer_is_busy() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = file_url(&dir.path().join("kemlock.db"));
    let store = SqlStore::connect(&url).await.expect("connect");
    let owner = user_owner();
    let item = ItemId::random();
    let written = put(&store, draft(item, owner, None, 1)).await;

    // Writers and readers at once: every read sees a whole write or none, never an error.
    let mut tasks = Vec::new();
    for n in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            if n % 2 == 0 {
                put(&store, draft(ItemId::random(), owner, None, 1)).await;
            } else {
                let found = ItemStore::get(&store, item).await.expect("a read");
                assert_eq!(found.map(|i| i.id), Some(item));
            }
        }));
    }
    for task in tasks {
        task.await.expect("the task finishes");
    }
    assert_eq!(
        ItemStore::get(&store, item).await.expect("get"),
        Some(written)
    );
}

#[tokio::test]
async fn an_unsupported_url_is_refused() {
    let err = SqlStore::connect("ftp://example.org/db")
        .await
        .expect_err("not a database");
    assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
}

#[tokio::test]
async fn postgres_when_configured_migrates_and_pings() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        store.migrate().await.expect("migrate");
        store.ping().await.expect("ping");
    }
}

#[tokio::test]
async fn mysql_when_configured_migrates_and_pings() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        store.migrate().await.expect("migrate");
        store.ping().await.expect("ping");
    }
}

#[tokio::test]
async fn a_lease_is_held_by_one_holder_until_it_is_released_or_lapses() {
    let store = memory().await;
    let hour = time::Duration::hours(1);
    let name = format!("job-{}", uuid::Uuid::new_v4().simple());

    assert_eq!(store.try_lease(&name, "a", hour).await, Ok(true));
    assert_eq!(store.try_lease(&name, "b", hour).await, Ok(false));
    // Releasing what someone else holds changes nothing.
    store.release_lease(&name, "b").await.expect("release");
    assert_eq!(store.try_lease(&name, "b", hour).await, Ok(false));
    // The holder gives it back and the next one gets it.
    store.release_lease(&name, "a").await.expect("release");
    assert_eq!(store.try_lease(&name, "b", hour).await, Ok(true));

    // A holder that crashed is no obstacle once its lease has lapsed.
    let lapsing = format!("lapsing-{}", uuid::Uuid::new_v4().simple());
    assert_eq!(
        store
            .try_lease(&lapsing, "gone", time::Duration::seconds(-1))
            .await,
        Ok(true)
    );
    assert_eq!(store.try_lease(&lapsing, "next", hour).await, Ok(true));
}
