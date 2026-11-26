//! The move from Vaultwarden as the console starts it: the request returns at once, the import
//! runs in the background under a lease, and the status shows its stage and its result. Over a
//! real store and the Vaultwarden 1.37.5 sample folder `kemlock-vaultwarden`'s tests build.

#[allow(clippy::unwrap_used)]
#[path = "../../kemlock-vaultwarden/tests/common/mod.rs"]
mod vwfix;

use kemlock_app::admin::{
    AdminError, AdminEventRepo, EventFilter, MigrationRecord, MigrationRequest, MigrationRunner,
    MigrationState, MigrationStatus,
};
use kemlock_app::ports::UserRepo;
use kemlock_blob::ObjectBlobStore;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::files::BitwardenBlobs;
use kemlock_server::migration::{
    IMPORT_FOLDER, LEASE_TTL, MIGRATION_LEASE, VaultwardenMove, WRITE_FAILED,
};
use kemlock_store_sql::SqlStore;
use std::time::Duration;
use time::macros::datetime;
use uuid::Uuid;

const KEY: [u8; 32] = [7u8; 32];

struct Rig {
    store: SqlStore,
    crypto: ServerCrypto,
    runner: VaultwardenMove,
    /// The data folder: where the import copies `rsa_key.pem`, and whose `import` folder the
    /// console reads Vaultwarden's data from.
    dest: tempfile::TempDir,
}

async fn rig() -> Rig {
    let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
    let crypto = ServerCrypto::new(ServerSeal::new(&KEY), OpaqueServer::generate());
    let dest = tempfile::tempdir().expect("a temp dir");
    Rig {
        runner: VaultwardenMove::new(
            store.clone(),
            crypto.clone(),
            &KEY,
            dest.path().to_path_buf(),
            std::sync::Arc::new(BitwardenBlobs::new(ObjectBlobStore::memory())),
        ),
        store,
        crypto,
        dest,
    }
}

impl Rig {
    fn record(&self) -> MigrationRecord<SqlStore, ServerCrypto> {
        MigrationRecord {
            repo: self.store.clone(),
            clock: self.crypto.clone(),
        }
    }

    fn request(&self, from: &str) -> MigrationRequest {
        MigrationRequest {
            from: from.to_owned(),
            files: None,
            by: UserId::random(),
        }
    }

    /// The import folder, made when asked for.
    fn vw_folder(&self) -> std::path::PathBuf {
        let folder = self.dest.path().join(IMPORT_FOLDER);
        std::fs::create_dir_all(&folder).expect("an import folder");
        folder
    }

    /// The sample database, named the way the console takes it: relative to the import folder.
    fn vw_path(&self) -> String {
        self.vw_folder();
        "db.sqlite3".to_owned()
    }

    /// How the status shows the sample database: relative to the import folder, as the console
    /// takes a source, so a retry can send it back.
    const SHOWN: &'static str = "db.sqlite3";

    /// Waits for the background task to end the move.
    async fn finished(&self) -> MigrationStatus {
        for _ in 0..600 {
            let status = self.record().status().await.expect("a status");
            if status.state != MigrationState::Running {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the move didn't end in 30 seconds");
    }
}

#[tokio::test]
async fn a_move_starts_at_once_runs_in_the_background_and_writes_the_vaultwarden_data() {
    let rig = rig().await;
    vwfix::create_sample_folder(&rig.vw_folder()).await;
    let request = rig.request(&rig.vw_path());
    let by = request.by;

    let started = rig.runner.start(request).await.expect("started");
    assert_eq!(started.state, MigrationState::Running);
    assert_eq!(started.source.as_deref(), Some(Rig::SHOWN));
    assert_eq!(started.started_by, Some(by));

    let done = rig.finished().await;
    assert_eq!(done.state, MigrationState::Done, "{done:?}");
    let report = done.report.as_deref().expect("a report");
    assert!(report.starts_with("wrote "), "{report}");
    assert!(
        report.contains("restart Kemlock Server"),
        "the carried rsa key: {report}"
    );
    assert_eq!(done.stage, None);
    assert!(done.plan.is_some(), "the plan it worked from");
    assert!(done.finished_at.is_some());
    assert_eq!(done.started_by, Some(by));
    assert_eq!(done.at, started.at, "the start time is kept");

    // The real import ran: Vaultwarden's accounts are in this server's store.
    for who in ["alice@example.org", "bob@example.org"] {
        let email = Email::parse(who).expect("an email");
        let account = UserRepo::by_email(&rig.store, &email)
            .await
            .expect("a read");
        assert!(account.is_some(), "{who} was imported");
    }

    // The lease went back.
    assert_eq!(
        rig.store
            .try_lease(MIGRATION_LEASE, "probe", LEASE_TTL)
            .await,
        Ok(true)
    );
    rig.store
        .release_lease(MIGRATION_LEASE, "probe")
        .await
        .expect("released");

    // A finished move is the console's only one: what this server holds has been changed here
    // since, and a rerun would roll it back. Later passes are the command line's.
    let again = rig.runner.start(rig.request(&rig.vw_path())).await;
    assert!(matches!(again, Err(AdminError::State(_))), "{again:?}");
    assert_eq!(
        rig.record().status().await.expect("a status").state,
        MigrationState::Done,
        "the refused start left the result as it was"
    );
    assert_eq!(
        rig.store
            .try_lease(MIGRATION_LEASE, "probe", LEASE_TTL)
            .await,
        Ok(true),
        "and took no lease"
    );
}

#[tokio::test]
async fn a_source_that_is_there_but_cannot_be_read_fails_in_the_background() {
    let rig = rig().await;
    // A db.sqlite3 in the import folder that is not a database.
    std::fs::write(rig.vw_folder().join("db.sqlite3"), b"this is not sqlite").expect("a file");
    let started = rig
        .runner
        .start(rig.request(&rig.vw_path()))
        .await
        .expect("the request itself is fine");
    assert_eq!(started.state, MigrationState::Running);

    let failed = rig.finished().await;
    assert_eq!(failed.state, MigrationState::Failed, "{failed:?}");
    let error = failed.error.as_deref().expect("a reason");
    assert!(!error.is_empty());
    assert!(
        !error.contains(rig.dest.path().to_str().expect("a path")),
        "the reason names no path of the host: {error}"
    );
    assert_eq!(failed.source.as_deref(), Some(Rig::SHOWN));
    assert_eq!(failed.at, started.at);
    assert!(failed.finished_at.is_some());

    // Nothing was half written, and the lease is back: the admin can try again.
    let again = rig.runner.start(rig.request(&rig.vw_path())).await;
    assert!(again.is_ok(), "{again:?}");
    assert_eq!(rig.finished().await.state, MigrationState::Failed);
}

#[tokio::test]
async fn a_source_that_is_not_there_is_refused_and_records_nothing() {
    let rig = rig().await;
    let refused = rig
        .runner
        .start(rig.request("/definitely/not/a/vaultwarden/folder"))
        .await;
    assert!(
        matches!(refused, Err(AdminError::Invalid(_))),
        "{refused:?}"
    );
    assert_eq!(
        rig.record().status().await.expect("a status").state,
        MigrationState::Idle
    );
}

#[tokio::test]
async fn only_one_move_runs_at_a_time_across_replicas() {
    let rig = rig().await;
    vwfix::create_sample_folder(&rig.vw_folder()).await;
    // Another replica is moving right now.
    assert_eq!(
        rig.store
            .try_lease(MIGRATION_LEASE, "another replica", LEASE_TTL)
            .await,
        Ok(true)
    );
    let refused = rig.runner.start(rig.request(&rig.vw_path())).await;
    assert!(matches!(refused, Err(AdminError::State(_))), "{refused:?}");
    assert_eq!(
        rig.record().status().await.expect("a status").state,
        MigrationState::Idle,
        "the refused start recorded nothing"
    );

    rig.store
        .release_lease(MIGRATION_LEASE, "another replica")
        .await
        .expect("released");
    rig.runner
        .start(rig.request(&rig.vw_path()))
        .await
        .expect("started");
    assert_eq!(rig.finished().await.state, MigrationState::Done);
}

#[tokio::test]
async fn a_move_the_server_stopped_under_is_turned_into_a_failure_unless_someone_still_runs_it() {
    let rig = rig().await;
    let by = UserId::random();
    rig.record()
        .running(by, "/vw".to_owned())
        .await
        .expect("a running status");

    // Another replica holds the lease: it is really running, so nothing changes.
    rig.store
        .try_lease(MIGRATION_LEASE, "another replica", LEASE_TTL)
        .await
        .expect("leased");
    assert_eq!(rig.runner.recover().await, Ok(false));
    assert_eq!(
        rig.record().status().await.expect("a status").state,
        MigrationState::Running
    );

    // Nobody holds it: the move was orphaned, and the admin may start another.
    rig.store
        .release_lease(MIGRATION_LEASE, "another replica")
        .await
        .expect("released");
    assert_eq!(rig.runner.recover().await, Ok(true));
    let status = rig.record().status().await.expect("a status");
    assert_eq!(status.state, MigrationState::Failed);
    assert!(
        status
            .error
            .as_deref()
            .is_some_and(|e| e.contains("stopped"))
    );
    assert_eq!(status.started_by, Some(by));
    assert_eq!(status.source.as_deref(), Some("/vw"));
    // It took the lease only to look, and gave it back.
    assert_eq!(
        rig.store
            .try_lease(MIGRATION_LEASE, "probe", LEASE_TTL)
            .await,
        Ok(true)
    );

    // Nothing to recover when nothing was running.
    assert_eq!(rig.runner.recover().await, Ok(false));
}

#[tokio::test]
async fn the_console_takes_no_database_url_and_nothing_outside_the_import_folder() {
    let rig = rig().await;
    vwfix::create_sample_folder(&rig.vw_folder()).await;
    // A file of the host that isn't in the import folder, a folder beside it, and URLs of a
    // database server somewhere inside the network.
    let outside = rig.dest.path().join("server.key");
    std::fs::write(&outside, b"secret").expect("a file");
    let mut answers = Vec::new();
    for from in [
        "postgres://vw:pw@10.0.0.5:5432/vault".to_owned(),
        "mysql://vw:pw@internal-db/vault".to_owned(),
        outside.display().to_string(),
        rig.dest.path().display().to_string(),
        rig.vw_folder().join("db.sqlite3").display().to_string(),
        "//attacker/share/db.sqlite3".to_owned(),
        "../server.key".to_owned(),
        "/definitely/not/there".to_owned(),
    ] {
        let refused = rig.runner.start(rig.request(&from)).await;
        match refused {
            Err(AdminError::Invalid(text)) => answers.push(text),
            other => panic!("{from}: expected a refusal, got {other:?}"),
        }
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "a source that is missing and one that is refused get the same answer: {answers:?}"
    );
    assert!(!answers[0].contains("10.0.0.5"));
    // A database to read beside the data files may not be a URL either.
    let mut request = rig.request("db.sqlite3");
    request.files = Some("postgres://vw@db/vault".to_owned());
    assert!(matches!(
        rig.runner.start(request).await,
        Err(AdminError::Invalid(_))
    ));
    assert_eq!(
        rig.record().status().await.expect("a status").state,
        MigrationState::Idle,
        "none of them recorded a move"
    );
}

/// An account of this server, not made by a move, with the id and a different email than the
/// sample's alice.
fn native_alice() -> User {
    User {
        id: UserId(Uuid::parse_str(vwfix::ALICE).expect("a UUID")),
        email: Email::parse("native-alice@example.org").expect("an email"),
        name: Some("Native Alice".to_owned()),
        mode: AccountMode::KemlockOnly,
        role: Role::User,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 5000],
        bundle_signature: vec![4; 3400],
        sealed_private_keys: vec![5; 8000],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        updated_at: datetime!(2026-01-02 03:04:05 UTC),
    }
}

#[tokio::test]
async fn a_move_leaves_an_existing_account_alone_and_the_event_log_says_what_it_refused() {
    let rig = rig().await;
    vwfix::create_sample_folder(&rig.vw_folder()).await;
    let native = native_alice();
    UserRepo::insert(&rig.store, &native).await.expect("inserted");

    let request = rig.request(&rig.vw_path());
    let by = request.by;
    rig.runner.start(request).await.expect("started");
    let done = rig.finished().await;
    assert_eq!(done.state, MigrationState::Done, "{done:?}");

    // The status and the event log both name the id the move would have rewritten.
    let report = done.report.as_deref().expect("a report");
    assert!(report.contains("Left alone"), "{report}");
    assert!(report.contains(vwfix::ALICE), "{report}");

    // The account is as it was: the sample's alice didn't replace its email or name.
    let kept = UserRepo::by_id(&rig.store, native.id)
        .await
        .expect("a read")
        .expect("still there");
    assert_eq!(kept.email, native.email);
    assert_eq!(kept.name, native.name);
    assert_eq!(kept.mode, AccountMode::KemlockOnly);
    assert_eq!(kept.security_stamp, native.security_stamp);
    // What the move may create, it did.
    let bob = Email::parse("bob@example.org").expect("an email");
    assert!(
        UserRepo::by_email(&rig.store, &bob)
            .await
            .expect("a read")
            .is_some()
    );

    let events = rig
        .store
        .query_events(
            &EventFilter {
                action: Some("admin.migration.done".to_owned()),
                ..EventFilter::default()
            },
            None,
            10,
        )
        .await
        .expect("events");
    assert_eq!(events.events.len(), 1);
    let event = &events.events[0];
    assert_eq!(event.actor, Some(by));
    let target = event.target.as_deref().expect("a target");
    assert!(target.starts_with("import/db.sqlite3: wrote "), "{target}");
    assert!(target.contains("user 1"), "{target}");
    assert!(target.contains(vwfix::ALICE), "{target}");
}

#[tokio::test]
async fn a_failed_move_is_in_the_event_log_too() {
    let rig = rig().await;
    std::fs::write(rig.vw_folder().join("db.sqlite3"), b"this is not sqlite").expect("a file");
    let request = rig.request(&rig.vw_path());
    let by = request.by;
    rig.runner.start(request).await.expect("started");
    assert_eq!(rig.finished().await.state, MigrationState::Failed);
    let events = rig
        .store
        .query_events(
            &EventFilter {
                action: Some("admin.migration.failed".to_owned()),
                ..EventFilter::default()
            },
            None,
            10,
        )
        .await
        .expect("events");
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].actor, Some(by));
    assert!(
        events.events[0]
            .target
            .as_deref()
            .is_some_and(|t| t.starts_with("import/db.sqlite3: "))
    );
}

#[tokio::test]
async fn a_write_that_fails_tells_the_console_only_a_fixed_text() {
    let rig = rig().await;
    vwfix::create_sample_folder(&rig.vw_folder()).await;
    // An address Kemlock refuses: the write fails after the source was read and mapped.
    let mut conn = vwfix::writer(&rig.vw_folder()).await;
    vwfix::exec(
        &mut conn,
        "UPDATE users SET email = 'not an email' WHERE email = 'alice@example.org'",
    )
    .await;
    drop(conn);

    rig.runner
        .start(rig.request(&rig.vw_path()))
        .await
        .expect("started");
    let failed = rig.finished().await;
    assert_eq!(failed.state, MigrationState::Failed, "{failed:?}");
    assert_eq!(failed.error.as_deref(), Some(WRITE_FAILED));
}
