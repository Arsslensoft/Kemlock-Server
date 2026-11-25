//! Push tokens, the relay installation, the nudge log and the backend probe, on SQLite always and
//! on PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{device, external, memory, unique_email, user, user_owner};
use kemlock_app::ports::{DeviceRepo, StoreError, UserRepo};
use kemlock_app::push::{NudgeLog, PushInstallation, PushKind, PushRegistration, PushRepo};
use kemlock_domain::{DeviceId, Owner};
use kemlock_store_sql::{Dialect, SqlStore};
use time::macros::datetime;

fn registration(device: DeviceId, user: kemlock_domain::UserId, token: &str) -> PushRegistration {
    PushRegistration {
        device,
        user,
        kind: PushKind::Fcm,
        token: token.to_owned(),
        updated_at: datetime!(2026-11-23 12:00 UTC),
    }
}

async fn tokens_and_installation(store: &SqlStore) {
    let ada = user(&unique_email("ada"));
    UserRepo::insert(store, &ada).await.expect("insert user");
    let phone = device(ada.id, "Pixel", datetime!(2026-11-01 00:00 UTC));
    let tablet = device(ada.id, "Tablet", datetime!(2026-11-01 00:00 UTC));
    DeviceRepo::upsert(store, &phone).await.expect("phone");
    DeviceRepo::upsert(store, &tablet).await.expect("tablet");

    store
        .put_registration(&registration(phone.id, ada.id, "one"))
        .await
        .expect("registers");
    // The same device again replaces its token.
    let mut again = registration(phone.id, ada.id, "two");
    again.kind = PushKind::Apns;
    store.put_registration(&again).await.expect("replaces");
    // `unifiedpush` is longer than the table's first 8-character column.
    let mut tab = registration(tablet.id, ada.id, "tab");
    tab.kind = PushKind::UnifiedPush;
    store
        .put_registration(&tab)
        .await
        .expect("registers the tablet");

    let mut found = store.registrations_for(&[ada.id]).await.expect("lists");
    found.sort_by_key(|r| r.token.clone());
    assert_eq!(found.len(), 2);
    assert_eq!(found[0], tab);
    assert_eq!(found[1], again);
    assert!(
        store
            .registrations_for(&[])
            .await
            .expect("empty list")
            .is_empty()
    );

    // A device that doesn't exist can't have a token.
    assert_eq!(
        store
            .put_registration(&registration(DeviceId::random(), ada.id, "ghost"))
            .await,
        Err(StoreError::NotFound)
    );

    store.remove_registration(phone.id).await.expect("removes");
    store.remove_registration(phone.id).await.expect("again");
    assert_eq!(
        store
            .registrations_for(&[ada.id])
            .await
            .expect("lists")
            .len(),
        1
    );

    // Signing a device out takes its token with it.
    DeviceRepo::remove(store, tablet.id)
        .await
        .expect("sign out");
    assert!(
        store
            .registrations_for(&[ada.id])
            .await
            .expect("lists")
            .is_empty()
    );

    // The installation is one value: set, replaced, cleared.
    let first = PushInstallation {
        id: "inst-1".to_owned(),
        sealed_key: vec![0, 1, 2, 0xfe, 0xff],
    };
    store.set_installation(&first).await.expect("sets");
    assert_eq!(store.installation().await.expect("reads"), Some(first));
    let second = PushInstallation {
        id: "inst-2".to_owned(),
        sealed_key: vec![9; 70],
    };
    store.set_installation(&second).await.expect("replaces");
    assert_eq!(store.installation().await.expect("reads"), Some(second));
    store.clear_installation().await.expect("clears");
    assert_eq!(store.installation().await.expect("reads"), None);
}

async fn nudge_log(store: &SqlStore) {
    let start = store.latest_nudge().await.expect("latest");
    let a = user_owner();
    let b = Owner::Space(kemlock_domain::SpaceId::random());
    let first = store.append_nudge(a).await.expect("append");
    let second = store.append_nudge(b).await.expect("append");
    assert!(first > start && second > first, "ids only grow");
    assert_eq!(store.latest_nudge().await.expect("latest"), second);

    let seen = store.nudges_since(start, 100).await.expect("since");
    let mine: Vec<_> = seen.iter().filter(|e| e.id >= first).collect();
    assert_eq!(mine.len(), 2);
    assert_eq!((mine[0].id, mine[0].owner), (first, a));
    assert_eq!((mine[1].id, mine[1].owner), (second, b));

    // Reading after an id skips what came before it, and the limit holds.
    let after = store.nudges_since(first, 100).await.expect("since");
    assert!(after.iter().all(|e| e.id > first));
    assert_eq!(store.nudges_since(start, 1).await.expect("limit").len(), 1);

    // Pruning removes only what is older than the cut.
    assert_eq!(
        store
            .prune_nudges(datetime!(2000-01-01 00:00 UTC))
            .await
            .expect("prune"),
        0
    );
    let removed = store
        .prune_nudges(datetime!(2100-01-01 00:00 UTC))
        .await
        .expect("prune all");
    assert!(removed >= 2);
    assert!(store.nudges_since(0, 100).await.expect("since").is_empty());
}

#[tokio::test]
async fn tokens_and_the_installation_on_sqlite() {
    tokens_and_installation(&memory().await).await;
}

#[tokio::test]
async fn the_nudge_log_on_sqlite() {
    let store = memory().await;
    assert_eq!(store.dialect(), Dialect::Sqlite);
    nudge_log(&store).await;
}

#[tokio::test]
async fn notify_and_listen_need_postgres() {
    let store = memory().await;
    assert!(store.pg_notify("user:x").await.is_err());
    assert!(store.pg_listen().await.is_err());
}

#[tokio::test]
async fn external_backends() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        assert_eq!(store.dialect(), Dialect::Postgres);
        tokens_and_installation(&store).await;
        nudge_log(&store).await;
        // A notification reaches a listener, carrying the payload only.
        let mut listener = store.pg_listen().await.expect("listens");
        store.pg_notify("user:probe").await.expect("notifies");
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("a notification arrives")
            .expect("no error");
        assert_eq!(got.as_deref(), Some("user:probe"));
    }
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        assert_eq!(store.dialect(), Dialect::MySql);
        tokens_and_installation(&store).await;
        nudge_log(&store).await;
    }
}
