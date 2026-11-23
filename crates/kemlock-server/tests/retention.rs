//! The daily retention job over a real store: what has outlived its period goes, an account whose
//! deletion grace period ended is erased, and only one replica runs it at a time.

use kemlock_app::ports::{Event, UserRepo};
use kemlock_app::privacy::{AccountEraser, PrivacyLog, SendEraser};
use kemlock_app::sends::SendRepo;
use kemlock_blob::ObjectBlobStore;
use kemlock_crypto::opaque::OpaqueServer;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::sends::{SendId, SendKind, SendRecord};
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_server::adapters::ServerCrypto;
use kemlock_server::privacy::{RETENTION_LEASE, ServerFiles, retention_once};
use kemlock_store_sql::SqlStore;
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

fn event(actor: UserId, at: OffsetDateTime) -> Event {
    Event {
        actor: Some(actor),
        device: None,
        action: "test.action",
        target: None,
        at,
    }
}

struct Rig {
    store: SqlStore,
    crypto: ServerCrypto,
    files: ServerFiles,
    _dir: tempfile::TempDir,
}

async fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("a temp dir");
    Rig {
        store: SqlStore::connect("sqlite::memory:").await.expect("a store"),
        crypto: ServerCrypto::new(ServerSeal::new(&[7u8; 32]), OpaqueServer::generate()),
        files: ServerFiles::new(ObjectBlobStore::memory(), dir.path()),
        _dir: dir,
    }
}

#[tokio::test]
async fn old_events_go_and_an_account_past_its_grace_period_is_erased() {
    let rig = rig().await;
    let now = OffsetDateTime::now_utc();
    let ada = account("ada@example.org");
    let bob = account("bob@example.org");
    UserRepo::insert(&rig.store, &ada).await.expect("account");
    UserRepo::insert(&rig.store, &bob).await.expect("account");
    PrivacyLog::record_event(&rig.store, event(bob.id, now - Duration::days(400)), None)
        .await
        .expect("an old event");
    PrivacyLog::record_event(&rig.store, event(bob.id, now - Duration::days(10)), None)
        .await
        .expect("a recent event");
    // Ada asked to delete her account a week ago and the grace period ended yesterday; Bob's has
    // days to go.
    AccountEraser::schedule_erasure(
        &rig.store,
        ada.id,
        now - Duration::days(8),
        now - Duration::days(1),
    )
    .await
    .expect("scheduled");
    AccountEraser::schedule_erasure(
        &rig.store,
        bob.id,
        now - Duration::days(1),
        now + Duration::days(6),
    )
    .await
    .expect("scheduled");

    let report = retention_once(&rig.store, &rig.crypto, &rig.files, "me")
        .await
        .expect("the job runs")
        .expect("the lease was free");

    assert_eq!(report.events, 1, "{report:?}");
    assert_eq!(UserRepo::by_id(&rig.store, ada.id).await, Ok(None));
    assert!(
        UserRepo::by_id(&rig.store, bob.id)
            .await
            .expect("a read")
            .is_some(),
        "Bob's grace period isn't over"
    );
    let events = PrivacyLog::events_of(&rig.store, bob.id)
        .await
        .expect("events");
    assert_eq!(events.len(), 1, "only the recent one is left");
}

#[tokio::test]
async fn only_the_replica_holding_the_lease_runs_the_job() {
    let rig = rig().await;
    assert_eq!(
        rig.store
            .try_lease(RETENTION_LEASE, "another replica", time::Duration::hours(1))
            .await,
        Ok(true)
    );

    let skipped = retention_once(&rig.store, &rig.crypto, &rig.files, "me")
        .await
        .expect("no error");
    assert!(skipped.is_none());

    rig.store
        .release_lease(RETENTION_LEASE, "another replica")
        .await
        .expect("released");
    assert!(
        retention_once(&rig.store, &rig.crypto, &rig.files, "me")
            .await
            .expect("no error")
            .is_some()
    );
    // And it gave the lease back.
    assert_eq!(
        rig.store
            .try_lease(RETENTION_LEASE, "next", time::Duration::hours(1))
            .await,
        Ok(true)
    );
}

#[tokio::test]
async fn the_servers_sends_eraser_deletes_the_sends_of_the_account_it_is_given() {
    let rig = rig().await;
    let now = OffsetDateTime::now_utc();
    let ada = account("ada@example.org");
    let bob = account("bob@example.org");
    UserRepo::insert(&rig.store, &ada).await.expect("account");
    UserRepo::insert(&rig.store, &bob).await.expect("account");
    let send = |owner: UserId| SendRecord {
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
        deletion_at: now + Duration::days(7),
        created_at: now,
        revised_at: now,
    };
    let (hers, his) = (send(ada.id), send(bob.id));
    rig.store.add_send(&hers).await.expect("a Send");
    rig.store.add_send(&his).await.expect("a Send");

    let erased = rig.files.send_eraser(&rig.store).erase_sends(ada.id).await;

    assert_eq!(erased, Ok(1));
    assert_eq!(rig.store.send_by_id(hers.id).await, Ok(None));
    assert_eq!(rig.store.send_by_id(his.id).await, Ok(Some(his)));
}

#[tokio::test]
async fn the_job_keeps_events_for_as_long_as_the_console_says_and_follows_a_change() {
    use kemlock_app::admin::{Change, NoEnv, Settings};
    use kemlock_server::live::{Layered, SettingsWatch};
    use std::collections::BTreeMap;

    let rig = rig().await;
    let now = OffsetDateTime::now_utc();
    let ada = account("ada@example.org");
    UserRepo::insert(&rig.store, &ada).await.expect("account");
    for days in [10, 100, 400] {
        PrivacyLog::record_event(&rig.store, event(ada.id, now - Duration::days(days)), None)
            .await
            .expect("an event");
    }

    // The console saves 90 days; the job is the one retention job, with no setting of its own.
    let console = Settings {
        repo: rig.store.clone(),
        seal: rig.crypto.clone(),
        env: NoEnv,
    };
    let change =
        |days: &str| BTreeMap::from([("event_log_days".to_owned(), Change::Set(days.to_owned()))]);
    console.apply(&change("90")).await.expect("saved");
    let watch = SettingsWatch::start(
        rig.store.clone(),
        rig.crypto.clone(),
        Layered::new(|_| None, BTreeMap::new()),
    )
    .await
    .expect("the settings are read");
    watch.overlay_retention(&rig.store);

    let report = retention_once(&rig.store, &rig.crypto, &rig.files, "me")
        .await
        .expect("the job runs")
        .expect("the lease was free");
    assert_eq!(
        report.events, 2,
        "the 100 and 400 day old events: {report:?}"
    );
    let left = PrivacyLog::events_of(&rig.store, ada.id)
        .await
        .expect("events");
    assert_eq!(left.len(), 1);

    // A longer period saved later applies to the next run, which finds nothing more to delete.
    console.apply(&change("2555")).await.expect("saved");
    assert!(watch.refresh().await.expect("reads"));
    let report = retention_once(&rig.store, &rig.crypto, &rig.files, "me")
        .await
        .expect("the job runs")
        .expect("the lease was free");
    assert_eq!(report.events, 0, "{report:?}");
}
