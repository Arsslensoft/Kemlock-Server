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

/// A server with one account and a backup of it, with its authentication code.
async fn fixture() -> Fixture {
    fixture_with(true).await
}

/// [`fixture`], and with `authenticated` false the archive is written as one made before archives
/// carried a code.
async fn fixture_with(authenticated: bool) -> Fixture {
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
    let mut layout = layout(&config).expect("a layout");
    assert!(
        layout.mac_key.is_some(),
        "the server key is there to make the code with"
    );
    if !authenticated {
        layout.mac_key = None;
    }
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

    let report = restore_check(&f.archive, &f.identity_file, &f.key_file, &work, false)
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
    let error = restore_check(&f.archive, &f.identity_file, &wrong_key, &work, false)
        .await
        .expect_err("the sealed secrets don't open");
    assert!(error.contains("server"), "{error}");

    let short = f.root.path().join("short.key");
    std::fs::write(&short, [1u8; 5]).expect("a file");
    let error = restore_check(&f.archive, &f.identity_file, &short, &work, false)
        .await
        .expect_err("not a key");
    assert!(error.contains("32 bytes"), "{error}");

    let stranger = AgeIdentity::generate();
    let stranger_file = f.root.path().join("stranger.txt");
    std::fs::write(&stranger_file, stranger.to_string().expose_secret()).expect("a file");
    let error = restore_check(&f.archive, &stranger_file, &f.key_file, &work, false)
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
            allow_unauthenticated: false,
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
            allow_unauthenticated: false,
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

/// The key files a restore puts down are readable by their owner only, whatever the umask and
/// whatever mode the archive's copies had.
#[cfg(unix)]
#[tokio::test]
async fn a_restore_leaves_the_key_files_private() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));

    restore(
        &target,
        &RestoreOptions {
            archive: f.archive.clone(),
            identity: f.identity_file.clone(),
            server_key: Some(f.key_file.clone()),
            allow_unauthenticated: false,
        },
    )
    .await
    .expect("the restore works");

    let mut checked = 0;
    for name in [
        "server.key",
        "opaque-setup.sealed",
        "token-signing-key.sealed",
        "rsa_key.pem",
    ] {
        let path = target.data_folder.join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} is {mode:o}");
            checked += 1;
        }
    }
    assert!(checked >= 3, "the key files were restored: {checked}");
}

/// Options for a restore into `target` with the given key file.
fn options(f: &Fixture, server_key: Option<&Path>, allow_unauthenticated: bool) -> RestoreOptions {
    RestoreOptions {
        archive: f.archive.clone(),
        identity: f.identity_file.clone(),
        server_key: server_key.map(Path::to_path_buf),
        allow_unauthenticated,
    }
}

#[tokio::test]
async fn a_restore_without_a_key_is_refused_unless_told_to_take_the_archive_unchecked() {
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));

    // Nothing to check the archive's code with: refused, and nothing is changed.
    let error = restore(&target, &options(&f, None, false))
        .await
        .expect_err("an unchecked archive is refused");
    assert!(error.contains("server.key"), "{error}");
    assert!(error.contains("--allow-unauthenticated"), "{error}");
    assert!(error.contains("Nothing was changed"), "{error}");
    assert!(!target.data_folder.join("db.sqlite3").exists());

    // Told to, it restores, says it didn't check, and says to put the key in place.
    let report = restore(&target, &options(&f, None, true))
        .await
        .expect("the restore works");
    assert!(!report.server_key_installed);
    assert!(
        report.notes.iter().any(|n| n.contains("server.key")),
        "{:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|n| n.contains("NOT authenticated")),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn an_archive_made_with_another_server_key_is_refused() {
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));
    let other_key = f.root.path().join("other.key");
    std::fs::write(&other_key, [9u8; 32]).expect("another key");

    let error = restore(&target, &options(&f, Some(&other_key), false))
        .await
        .expect_err("the code doesn't match this key");
    assert!(error.contains("manifest.mac"), "{error}");
    assert!(error.contains("Nothing was changed"), "{error}");
    // Neither the database nor the key was put in place.
    assert!(!target.data_folder.join("db.sqlite3").exists());
    assert!(!target.data_folder.join("server.key").exists());

    // The drill refuses it as well.
    let work = f.root.path().join("work");
    let error = restore_check(&f.archive, &f.identity_file, &other_key, &work, false)
        .await
        .expect_err("the drill checks the code too");
    assert!(error.contains("manifest.mac"), "{error}");
}

#[tokio::test]
async fn an_archive_with_no_code_is_refused_unless_told_to_take_it_as_it_is() {
    let f = fixture_with(false).await;
    let target = config(&f.root.path().join("target"));

    let error = restore(&target, &options(&f, Some(&f.key_file), false))
        .await
        .expect_err("no code");
    assert!(error.contains("no manifest.mac"), "{error}");
    assert!(!target.data_folder.join("server.key").exists());

    let report = restore(&target, &options(&f, Some(&f.key_file), true))
        .await
        .expect("allowed");
    assert!(report.server_key_installed);
    assert!(
        report.notes.iter().any(|n| n.contains("NOT authenticated")),
        "{:?}",
        report.notes
    );

    let work = f.root.path().join("work");
    let drill = restore_check(&f.archive, &f.identity_file, &f.key_file, &work, true)
        .await
        .expect("the drill with the flag");
    assert!(!drill.authenticated);
}

#[tokio::test]
async fn an_archive_with_its_code_restores_with_the_key_and_the_drill_says_so() {
    let f = fixture().await;
    let work = f.root.path().join("work");
    let drill = restore_check(&f.archive, &f.identity_file, &f.key_file, &work, false)
        .await
        .expect("the drill passes");
    assert!(drill.authenticated);

    let target = config(&f.root.path().join("target"));
    let report = restore(&target, &options(&f, Some(&f.key_file), false))
        .await
        .expect("the restore works");
    assert!(
        report
            .notes
            .iter()
            .all(|n| !n.contains("NOT authenticated")),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn inspecting_an_archive_says_what_it_is_without_changing_anything() {
    use kemlock_server::restore::inspect_archive;
    let f = fixture().await;
    let target = config(&f.root.path().join("target"));

    let info = inspect_archive(&target, &options(&f, Some(&f.key_file), false))
        .await
        .expect("the archive opens");
    assert!(info.created_at.starts_with("20"), "{}", info.created_at);
    assert!(
        info.tables > 10 && info.rows >= 1 && info.files >= 2,
        "{info:?}"
    );
    assert!(info.warnings.is_empty(), "{:?}", info.warnings);
    // Nothing was restored, and the scratch folder is gone.
    assert!(!target.data_folder.join("db.sqlite3").exists());
    assert_eq!(
        std::fs::read_dir(&target.data_folder)
            .expect("the data folder")
            .count(),
        0
    );

    // Without the key it can't be checked, and says so rather than showing an unchecked archive.
    let error = inspect_archive(&target, &options(&f, None, false))
        .await
        .expect_err("no key to check it with");
    assert!(error.contains("server.key"), "{error}");
}
