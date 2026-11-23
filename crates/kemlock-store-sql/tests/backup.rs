//! Snapshots and restores: every table goes out as plain rows and comes back, between databases
//! of any kind, and a table the backup doesn't know about stops a snapshot instead of going
//! missing from it.

mod common;

use common::{MADE_AT, device, draft, external, file, file_url, memory, put, unique_email, user};
use kemlock_app::ports::{DeviceRepo, ItemStore, StoreError, UserRepo};
use kemlock_app::privacy::{NewSignIn, PrivacyLog, PrivacySettings};
use kemlock_domain::privacy::{Retention, SignInOutcome};
use kemlock_domain::{ItemId, Owner};
use kemlock_store_sql::{Snapshot, SqlStore};
use std::net::IpAddr;

/// Gives a store some of everything the tests look for.
async fn populate(store: &SqlStore) -> (kemlock_domain::User, ItemId) {
    let account = user(&unique_email("backup"));
    UserRepo::insert(store, &account).await.expect("account");
    DeviceRepo::upsert(store, &device(account.id, "Pixel", MADE_AT))
        .await
        .expect("device");
    let id = ItemId::random();
    put(store, draft(id, Owner::User(account.id), None, 1)).await;
    put(
        store,
        draft(ItemId::random(), Owner::User(account.id), None, 1),
    )
    .await;
    PrivacySettings::save_retention(
        store,
        &Retention {
            trash_days: 45,
            ..Retention::default()
        },
    )
    .await
    .expect("settings");
    let from: IpAddr = "203.0.113.5".parse().expect("ip");
    PrivacyLog::record_sign_in(
        store,
        NewSignIn {
            user: Some(account.id),
            device: None,
            method: "password",
            outcome: SignInOutcome::Success,
            at: MADE_AT,
            ip: Some(from),
        },
    )
    .await
    .expect("sign-in");
    (account, id)
}

fn rows_of(snapshot: &Snapshot, table: &str) -> u64 {
    snapshot
        .tables
        .iter()
        .find(|t| t.name == table)
        .unwrap_or_else(|| panic!("the snapshot has {table}"))
        .rows
}

#[tokio::test]
async fn a_snapshot_counts_its_rows_and_restores_into_another_database() {
    let source = memory().await;
    let (account, item) = populate(&source).await;
    let dir = tempfile::tempdir().expect("a temp dir");

    let snapshot = source.snapshot_to(dir.path()).await.expect("the snapshot");

    assert_eq!(snapshot.database, "sqlite");
    assert_eq!(rows_of(&snapshot, "users"), 1);
    assert_eq!(rows_of(&snapshot, "devices"), 1);
    assert_eq!(rows_of(&snapshot, "items"), 2);
    assert_eq!(rows_of(&snapshot, "sign_in_log"), 1);
    assert_eq!(rows_of(&snapshot, "settings"), 1);
    assert!(
        snapshot.migrations.iter().any(|m| m.ends_with("_privacy")),
        "{:?}",
        snapshot.migrations
    );
    assert!(dir.path().join("users.jsonl").exists());
    // The counts are the database's own.
    let counts = source.row_counts().await.expect("counts");
    for table in &snapshot.tables {
        let live = counts
            .iter()
            .find(|(name, _)| *name == table.name)
            .map(|(_, n)| *n);
        assert_eq!(live, Some(table.rows), "{}", table.name);
    }

    // Into a database that already holds rows of its own: they are replaced.
    let target = memory().await;
    let stranger = user(&unique_email("stranger"));
    UserRepo::insert(&target, &stranger)
        .await
        .expect("a stranger");
    target
        .restore_from(dir.path(), &snapshot.tables)
        .await
        .expect("the restore works");

    assert_eq!(
        UserRepo::by_id(&target, account.id).await.expect("a read"),
        Some(account.clone()),
        "the account comes back as it was, blobs and times included"
    );
    assert_eq!(
        UserRepo::by_id(&target, stranger.id).await,
        Ok(None),
        "what was there is replaced"
    );
    let restored = ItemStore::get(&target, item)
        .await
        .expect("a read")
        .expect("the item");
    let original = ItemStore::get(&source, item)
        .await
        .expect("a read")
        .expect("the item");
    assert_eq!(restored, original);
    assert_eq!(
        DeviceRepo::list(&target, account.id)
            .await
            .expect("devices")
            .len(),
        1
    );
    assert_eq!(
        PrivacySettings::retention(&target)
            .await
            .map(|r| r.trash_days),
        Ok(45)
    );
    assert_eq!(
        target.row_counts().await.expect("counts"),
        source.row_counts().await.expect("counts")
    );

    // Restoring again changes nothing.
    target
        .restore_from(dir.path(), &snapshot.tables)
        .await
        .expect("a second restore");
    assert_eq!(
        target.row_counts().await.expect("counts"),
        source.row_counts().await.expect("counts")
    );
}

#[tokio::test]
async fn a_restore_that_finds_the_files_wrong_changes_nothing() {
    let source = memory().await;
    populate(&source).await;
    let dir = tempfile::tempdir().expect("a temp dir");
    let snapshot = source.snapshot_to(dir.path()).await.expect("the snapshot");

    let target = memory().await;
    let (kept, _) = populate(&target).await;

    // A row goes missing from the items file: the manifest's count no longer matches.
    let path = dir.path().join("items.jsonl");
    let text = std::fs::read_to_string(&path).expect("the file");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.pop();
    std::fs::write(&path, lines.join("\n") + "\n").expect("rewritten");

    let refused = target.restore_from(dir.path(), &snapshot.tables).await;
    assert!(
        matches!(refused, Err(StoreError::Backend(_))),
        "{refused:?}"
    );
    assert!(
        UserRepo::by_id(&target, kept.id)
            .await
            .expect("a read")
            .is_some(),
        "the transaction rolled back: the target is as it was"
    );
}

#[tokio::test]
async fn a_table_the_backup_does_not_know_stops_the_snapshot() {
    let (store, dir) = file().await;
    let url = file_url(&dir.path().join("kemlock.db"));
    let raw = sea_orm::Database::connect(&url)
        .await
        .expect("a raw connection");
    sea_orm::ConnectionTrait::execute_unprepared(&raw, "CREATE TABLE mystery (x INTEGER)")
        .await
        .expect("a table");
    raw.close().await.expect("closed");

    let out = tempfile::tempdir().expect("a temp dir");
    let refused = store.snapshot_to(out.path()).await;
    match refused {
        Err(StoreError::Backend(message)) => {
            assert!(message.contains("mystery"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_snapshot_of_a_file_database_works_while_it_is_open_for_writing() {
    let (store, dir) = file().await;
    populate(&store).await;
    let out = tempfile::tempdir().expect("a temp dir");
    let snapshot = store.snapshot_to(out.path()).await.expect("the snapshot");
    assert_eq!(rows_of(&snapshot, "users"), 1);
    // The database keeps taking writes after.
    populate(&store).await;
    assert_eq!(
        rows_of(
            &store.snapshot_to(out.path()).await.expect("again"),
            "users"
        ),
        2
    );
    drop(dir);
}

#[tokio::test]
async fn a_postgresql_or_mysql_snapshot_restores_into_sqlite() {
    for var in ["KEMLOCK_TEST_POSTGRES_URL", "KEMLOCK_TEST_MYSQL_URL"] {
        let Some(source) = external(var).await else {
            continue;
        };
        populate(&source).await;
        let dir = tempfile::tempdir().expect("a temp dir");
        let snapshot = source.snapshot_to(dir.path()).await.expect("the snapshot");
        assert_ne!(snapshot.database, "sqlite");
        // Reading is all that is done to the shared database; the rows go into a private one.
        let target = memory().await;
        target
            .restore_from(dir.path(), &snapshot.tables)
            .await
            .expect("the restore works");
        let counts = target.row_counts().await.expect("counts");
        for table in &snapshot.tables {
            let n = counts
                .iter()
                .find(|(name, _)| *name == table.name)
                .map(|(_, n)| *n);
            assert_eq!(n, Some(table.rows), "{var} {}", table.name);
        }
    }
}
