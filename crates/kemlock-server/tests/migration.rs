//! The move from Vaultwarden as the console starts it: the request returns at once, the import
//! runs in the background under a lease, and the status shows its stage and its result. Over a
//! real store and the Vaultwarden 1.37.5 sample folder `kemlock-vaultwarden`'s tests build.

#[allow(clippy::unwrap_used)]
#[path = "../../kemlock-vaultwarden/tests/common/mod.rs"]
mod vwfix;

use kemlock_app::admin::{
    AdminError, MigrationRecord, MigrationRequest, MigrationRunner, MigrationState, MigrationStatus,
};
use kemlock_app::ports::UserRepo;
use kemlock_blob::ObjectBlobStore;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::{Email, UserId};
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::files::BitwardenBlobs;
use kemlock_server::migration::{LEASE_TTL, MIGRATION_LEASE, VaultwardenMove};
use kemlock_store_sql::SqlStore;
use std::time::Duration;

const KEY: [u8; 32] = [7u8; 32];

struct Rig {
    store: SqlStore,
    crypto: ServerCrypto,
    runner: VaultwardenMove,
    /// Where the import copies `rsa_key.pem`.
    _dest: tempfile::TempDir,
    /// The Vaultwarden data folder.
    vw: tempfile::TempDir,
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
        _dest: dest,
        vw: tempfile::tempdir().expect("a temp dir"),
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

    fn vw_path(&self) -> String {
        self.vw.path().display().to_string()
    }

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
    vwfix::create_sample_folder(rig.vw.path()).await;
    let request = rig.request(&rig.vw_path());
    let by = request.by;

    let started = rig.runner.start(request).await.expect("started");
    assert_eq!(started.state, MigrationState::Running);
    assert_eq!(started.source.as_deref(), Some(rig.vw_path().as_str()));
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

    // The lease went back, and a rerun finds what the first one put.
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
    rig.runner
        .start(rig.request(&rig.vw_path()))
        .await
        .expect("started again");
    assert_eq!(rig.finished().await.state, MigrationState::Done);
}

#[tokio::test]
async fn a_source_that_is_there_but_cannot_be_read_fails_in_the_background() {
    let rig = rig().await;
    // A folder with no Vaultwarden database in it.
    let started = rig
        .runner
        .start(rig.request(&rig.vw_path()))
        .await
        .expect("the request itself is fine");
    assert_eq!(started.state, MigrationState::Running);

    let failed = rig.finished().await;
    assert_eq!(failed.state, MigrationState::Failed, "{failed:?}");
    assert!(failed.error.as_deref().is_some_and(|e| !e.is_empty()));
    assert_eq!(failed.source.as_deref(), Some(rig.vw_path().as_str()));
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
    vwfix::create_sample_folder(rig.vw.path()).await;
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
