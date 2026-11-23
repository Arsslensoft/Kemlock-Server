//! Backup, restore drill and restore, end to end: a server's data folder is made for real (keys on
//! disk, a SQLite file), an account is stored, a backup is taken to a folder, and the archive is
//! checked by the drill and restored into another data folder.

use age::secrecy::ExposeSecret;
use kemlock_app::ports::UserRepo;
use kemlock_backup::{AgeIdentity, BackupSettings, DestinationConfig, Schedule};
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_server::backups::{layout, run_backup};
use kemlock_server::restore::{RestoreOptions, restore, restore_check};
use kemlock_server::{Config, build};
use std::path::{Path, PathBuf};
use time::macros::datetime;
use uuid::Uuid;

fn config(data: &Path) -> Config {
    let data = data.to_string_lossy().replace('\\', "/");
    Config::from_sources(
        &|name| match name {
            "DATA_FOLDER" => Some(data.clone()),
            "DOMAIN" => Some("https://kemlock.test".to_owned()),
            _ => None,
        },
        None,
    )
    .expect("a valid configuration")
}

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

struct Fixture {
    root: tempfile::TempDir,
    #[allow(
        dead_code,
        reason = "kept so a failing test can print what it ran against"
    )]
    config: Config,
    archive: PathBuf,
    identity_file: PathBuf,
    key_file: PathBuf,
    ada: User,
}

/// A server with one account and a backup of it.
async fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("a temp dir");
    let data = root.path().join("source");
    let config = config(&data);
    let built = build(&config).await.expect("the server is built");
    let ada = account("ada@example.org");
    UserRepo::insert(&built.store, &ada).await.expect("account");

    let identity = AgeIdentity::generate();
    let identity_file = root.path().join("identity.txt");
    std::fs::write(
        &identity_file,
        format!(
            "# public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        ),
    )
    .expect("identity file");
    let settings = BackupSettings {
        schedule: Schedule::Nightly,
        keep: 7,
        destination: DestinationConfig::Local {
            folder: root.path().join("nas"),
        },
        recipient: identity.to_public().to_string(),
        zstd_level: 1,
    };
    let layout = layout(&config).expect("a layout");
    let report = run_backup(&built.store, &settings, &layout)
        .await
        .expect("the backup works");

    // The outcome is saved for the admin console.
    let status = built
        .store
        .setting("backup.status")
        .await
        .expect("a read")
        .expect("a status");
    assert!(status.contains("\"ok\":true"), "{status}");

    let key_file = root.path().join("server.key.stored-apart");
    std::fs::copy(data.join("server.key"), &key_file).expect("the key, stored apart");
    built.store.close().await.expect("closed");
    Fixture {
        archive: root.path().join("nas").join(&report.name),
        identity_file,
        key_file,
        config,
        ada,
        root,
    }
}

#[tokio::test]
async fn the_drill_restores_into_a_scratch_folder_and_starts_a_read_only_server() {
    let f = fixture().await;
    let work = f.root.path().join("work");

    let report = restore_check(&f.archive, &f.identity_file, &f.key_file, &work)
        .await
        .expect("the drill passes");

    assert!(report.tables > 10, "{report:?}");
    assert!(report.rows >= 1, "{report:?}");
    assert!(report.files >= 2, "the sealed key files: {report:?}");
    assert!(report.server_started);
    assert!(report.writes_refused, "a drill server takes no writes");
    // The scratch folder is gone, and nothing else was touched.
    assert_eq!(
        std::fs::read_dir(&work).expect("the work folder").count(),
        0
    );
}

#[tokio::test]
async fn the_drill_fails_with_the_wrong_server_key_or_the_wrong_identity() {
    let f = fixture().await;
    let work = f.root.path().join("work");

    let wrong_key = f.root.path().join("wrong.key");
    std::fs::write(&wrong_key, [7u8; 32]).expect("a key");
    let error = restore_check(&f.archive, &f.identity_file, &wrong_key, &work)
        .await
        .expect_err("the sealed secrets don't open");
    assert!(error.contains("server"), "{error}");

    let short = f.root.path().join("short.key");
    std::fs::write(&short, [1u8; 5]).expect("a file");
    let error = restore_check(&f.archive, &f.identity_file, &short, &work)
        .await
        .expect_err("not a key");
    assert!(error.contains("32 bytes"), "{error}");

    let stranger = AgeIdentity::generate();
    let stranger_file = f.root.path().join("stranger.txt");
    std::fs::write(&stranger_file, stranger.to_string().expose_secret()).expect("a file");
    let error = restore_check(&f.archive, &stranger_file, &f.key_file, &work)
        .await
        .expect_err("not the archive's identity");
    assert!(error.contains("age"), "{error}");
}

#[tokio::test]
async fn a_restore_puts_the_account_and_the_key_files_into_a_fresh_data_folder() {
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));

    let report = restore(
        &target,
        &RestoreOptions {
            archive: f.archive.clone(),
            identity: f.identity_file.clone(),
            server_key: Some(f.key_file.clone()),
        },
    )
    .await
    .expect("the restore works");

    assert!(report.server_key_installed);
    assert!(report.rows >= 1);
    assert!(report.files >= 2);
    assert!(target.data_folder.join("opaque-setup.sealed").is_file());
    assert!(target.data_folder.join("server.key").is_file());

    // A server starts over it with the account in place, and the sealed secrets open.
    let built = build(&target).await.expect("the restored server starts");
    assert_eq!(
        UserRepo::by_id(&built.store, f.ada.id)
            .await
            .expect("a read"),
        Some(f.ada.clone())
    );
    built.store.close().await.expect("closed");
}

#[tokio::test]
async fn a_restore_refuses_a_data_folder_with_another_server_key() {
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));
    std::fs::create_dir_all(&target.data_folder).expect("a folder");
    std::fs::write(target.data_folder.join("server.key"), [9u8; 32]).expect("another key");

    let error = restore(
        &target,
        &RestoreOptions {
            archive: f.archive.clone(),
            identity: f.identity_file.clone(),
            server_key: Some(f.key_file.clone()),
        },
    )
    .await
    .expect_err("the keys differ");

    assert!(error.contains("different server.key"), "{error}");
    assert!(
        !target.data_folder.join("db.sqlite3").exists(),
        "nothing was restored"
    );
}

#[tokio::test]
async fn a_restore_without_a_key_says_to_put_it_in_place() {
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));

    let report = restore(
        &target,
        &RestoreOptions {
            archive: f.archive.clone(),
            identity: f.identity_file.clone(),
            server_key: None,
        },
    )
    .await
    .expect("the restore works");

    assert!(!report.server_key_installed);
    assert!(
        report.notes.iter().any(|n| n.contains("server.key")),
        "{:?}",
        report.notes
    );
}
