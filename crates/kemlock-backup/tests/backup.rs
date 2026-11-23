//! The backup job end to end over a real in-memory store: an encrypted archive lands at the
//! destination, opens only with the identity, leaves `server.key` out, restores into another
//! database and is pruned as new ones arrive.

use age::x25519::Identity;
use kemlock_app::ports::UserRepo;
use kemlock_backup::{
    BackupSettings, DataLayout, Destination, DestinationConfig, Kind, Schedule, Source,
    create_backup, read_archive, verify_unpacked,
};
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_store_sql::{SnapshotTable, SqlStore};
use std::path::{Path, PathBuf};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn account(email: &str) -> User {
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("a valid email"),
        name: Some("Ada".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 500],
        bundle_signature: vec![4; 340],
        sealed_private_keys: vec![5; 800],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        updated_at: datetime!(2026-01-02 03:04:05 UTC),
    }
}

struct Setup {
    root: tempfile::TempDir,
    data: PathBuf,
    destination: PathBuf,
    identity: Identity,
    settings: BackupSettings,
    layout: DataLayout,
}

fn setup(keep: u32) -> Setup {
    let root = tempfile::tempdir().expect("a temp dir");
    let data = root.path().join("data");
    std::fs::create_dir_all(data.join("attachments").join("ab")).expect("folders");
    std::fs::write(data.join("server.key"), b"THE-SERVER-KEY-BYTES").expect("key");
    std::fs::write(data.join("opaque-setup.sealed"), b"sealed-setup").expect("sealed");
    std::fs::write(data.join("attachments/ab/abcdef"), b"attachment bytes").expect("blob");
    std::fs::write(data.join("db.sqlite3"), b"the live database").expect("db");
    let destination = root.path().join("nas").join("backups");
    let identity = Identity::generate();
    let settings = BackupSettings {
        schedule: Schedule::Nightly,
        keep,
        destination: DestinationConfig::Local {
            folder: destination.clone(),
        },
        recipient: identity.to_public().to_string(),
        zstd_level: 1,
    };
    let layout = DataLayout {
        data_folder: data.clone(),
        attachments_folder: Some(data.join("attachments")),
        config_file: None,
        skip: vec![data.join("db.sqlite3")],
    };
    Setup {
        root,
        data,
        destination,
        identity,
        settings,
        layout,
    }
}

async fn backup(store: &SqlStore, s: &Setup, now: OffsetDateTime) -> kemlock_backup::BackupReport {
    create_backup(
        Source::Store(store),
        &s.settings,
        &s.layout,
        Kind::Backup,
        30,
        now,
    )
    .await
    .expect("the backup works")
}

fn archives(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .expect("the folder")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_backup_lands_encrypted_and_restores_into_another_database() {
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let ada = account("ada@example.org");
    UserRepo::insert(&store, &ada).await.expect("account");
    let s = setup(7);
    let now = datetime!(2026-11-23 03:00 UTC);

    let report = backup(&store, &s, now).await;

    assert_eq!(report.name, "kemlock-backup-20261123T030000Z.tar.zst.age");
    assert_eq!(archives(&s.destination), vec![report.name.clone()]);
    assert!(report.size > 0);
    assert!(report.manifest.total_rows() >= 1);
    assert!(report.pruned.is_empty());
    // The working folder is gone.
    assert!(
        archives(&s.data)
            .iter()
            .all(|n| !n.starts_with(".kemlock-backup-work-")),
        "{:?}",
        archives(&s.data)
    );

    // The archive is ciphertext: neither the key nor the account is readable in it.
    let archive = s.destination.join(&report.name);
    let raw = std::fs::read(&archive).expect("the archive");
    let text = String::from_utf8_lossy(&raw);
    assert!(!text.contains("THE-SERVER-KEY-BYTES"));
    assert!(!text.contains("ada@example.org"));

    // Only its identity opens it.
    let stranger = Identity::generate();
    assert!(read_archive(&archive, &stranger, &s.root.path().join("no")).is_err());
    let unpacked = s.root.path().join("unpacked");
    read_archive(&archive, &s.identity, &unpacked).expect("read");
    let manifest = verify_unpacked(&unpacked).expect("checks out");
    assert_eq!(manifest, report.manifest);

    // server.key and the live database file are not in it; the sealed files and attachments are.
    assert!(!unpacked.join("data/server.key").exists());
    assert!(!unpacked.join("data/db.sqlite3").exists());
    assert_eq!(
        std::fs::read(unpacked.join("data/opaque-setup.sealed")).expect("sealed"),
        b"sealed-setup"
    );
    assert_eq!(
        std::fs::read(unpacked.join("attachments/ab/abcdef")).expect("blob"),
        b"attachment bytes"
    );
    assert!(manifest.files.iter().all(|f| f.path != "data/server.key"));

    // Its rows restore into a database of their own.
    let other = SqlStore::connect("sqlite::memory:")
        .await
        .expect("another store");
    let tables: Vec<SnapshotTable> = manifest
        .tables
        .iter()
        .map(|t| SnapshotTable {
            name: t.name.clone(),
            columns: t.columns.clone(),
            rows: t.rows,
        })
        .collect();
    other
        .restore_from(&unpacked.join("db"), &tables)
        .await
        .expect("the rows go back");
    assert_eq!(
        UserRepo::by_id(&other, ada.id).await.expect("a read"),
        Some(ada)
    );
}

#[tokio::test]
async fn old_archives_are_pruned_as_new_ones_arrive() {
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let s = setup(2);
    let first = datetime!(2026-11-20 03:00 UTC);
    let mut names = Vec::new();
    for day in 0..3 {
        let report = backup(&store, &s, first + Duration::days(day)).await;
        names.push(report.name);
    }
    // After the third, the first is gone.
    assert_eq!(
        archives(&s.destination),
        vec![names[1].clone(), names[2].clone()]
    );

    // The fourth reports what it pruned.
    let fourth = backup(&store, &s, first + Duration::days(3)).await;
    assert_eq!(fourth.pruned, vec![names[1].clone()]);
}

#[tokio::test]
async fn a_bad_recipient_stops_before_anything_is_stored() {
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let mut s = setup(7);
    s.settings.recipient = "not an age key".to_owned();
    let refused = create_backup(
        Source::Store(&store),
        &s.settings,
        &s.layout,
        Kind::Backup,
        30,
        datetime!(2026-11-23 03:00 UTC),
    )
    .await;
    assert!(refused.is_err());
    assert!(!s.destination.exists(), "nothing was made");
}

#[tokio::test]
async fn the_local_and_memory_destinations_agree() {
    let s = setup(7);
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let report = backup(&store, &s, datetime!(2026-11-23 03:00 UTC)).await;
    let dest = Destination::open(&s.settings.destination).expect("opens");
    let listed = dest.list().await.expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, report.name);
    assert_eq!(listed[0].size, report.size);
}
