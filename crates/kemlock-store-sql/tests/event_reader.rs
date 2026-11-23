//! `EventReader`: one action's events in a time range, narrowed by what the target holds or who
//! made them, newest first.
//!
//! Runs on every backend that is available (see `admin.rs`); the log may hold other runs' rows, so
//! every check uses an action of its own.

mod common;

use common::{external, file, memory};
use kemlock_app::event_reader::{EventMatch, EventQuery, EventReader};
use kemlock_app::ports::{Event, EventLog};
use kemlock_domain::UserId;
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

async fn write(store: &SqlStore, action: &'static str, actor: UserId, target: &str, minute: i64) {
    EventLog::record(
        store,
        Event {
            actor: Some(actor),
            device: None,
            action,
            target: Some(target.to_owned()),
            at: T0 + Duration::minutes(minute),
        },
    )
    .await
    .expect("record");
}

async fn scenario(store: &SqlStore) {
    // The action is static in the port, so a run's own name is leaked once.
    let name = format!("bw.event.{}", Uuid::new_v4().simple());
    let action: &'static str = Box::leak(name.into_boxed_str());
    let ada = UserId::random();
    let bob = UserId::random();
    for i in 0..4 {
        write(
            store,
            action,
            ada,
            &format!("{{\"organizationId\":\"org-1\",\"type\":{}}}", 1100 + i),
            i,
        )
        .await;
    }
    write(
        store,
        action,
        bob,
        "{\"organizationId\":\"org-2\",\"type\":1500}",
        10,
    )
    .await;
    write(
        store,
        action,
        bob,
        "{\"organizationId\":\"org-1\",\"organizationUserId\":\"m-9\",\"type\":1501}",
        11,
    )
    .await;
    write(
        store,
        "other.action",
        ada,
        "{\"organizationId\":\"org-1\"}",
        12,
    )
    .await;

    let window = |limit| EventQuery::new(action, T0, T0 + Duration::hours(1), limit);

    // Everything of the action, newest first, and nothing of another action.
    let all = store.read_events(&window(100)).await.expect("read");
    assert_eq!(all.len(), 6);
    assert!(all.windows(2).all(|w| w[0].at >= w[1].at));
    assert_eq!(all[0].actor, Some(bob));
    assert!(all.iter().all(|e| e.action == action));

    // A text the target must contain.
    let org_1 = store
        .read_events(&window(100).containing("\"organizationId\":\"org-1\""))
        .await
        .expect("read");
    assert_eq!(org_1.len(), 5);

    // The limit cuts the oldest.
    let two = store.read_events(&window(2)).await.expect("read");
    assert_eq!(two.len(), 2);
    assert_eq!(two[0].at, T0 + Duration::minutes(11));
    assert_eq!(two[1].at, T0 + Duration::minutes(10));

    // The range is inclusive at both ends.
    let edge = EventQuery::new(
        action,
        T0 + Duration::minutes(1),
        T0 + Duration::minutes(2),
        100,
    );
    let edge = store.read_events(&edge).await.expect("read");
    assert_eq!(edge.len(), 2);
    assert_eq!(edge[0].at, T0 + Duration::minutes(2));
    assert_eq!(edge[1].at, T0 + Duration::minutes(1));

    // Any of: events about a member in the target, or made by them.
    let about_bob = window(100)
        .containing("\"organizationId\":\"org-1\"")
        .or(EventMatch::Target(
            "\"organizationUserId\":\"m-9\"".to_owned(),
        ))
        .or(EventMatch::Actor(ada));
    let found = store.read_events(&about_bob).await.expect("read");
    assert_eq!(found.len(), 5);
    let only_member = window(100).or(EventMatch::Target(
        "\"organizationUserId\":\"m-9\"".to_owned(),
    ));
    assert_eq!(
        store.read_events(&only_member).await.expect("read").len(),
        1
    );

    // Nothing in an empty range.
    let none = EventQuery::new(action, T0 + Duration::days(1), T0 + Duration::days(2), 100);
    assert!(store.read_events(&none).await.expect("read").is_empty());
}

#[tokio::test]
async fn events_are_read_on_memory_sqlite() {
    scenario(&memory().await).await;
}

#[tokio::test]
async fn events_are_read_on_file_sqlite() {
    let (store, _dir) = file().await;
    scenario(&store).await;
}

#[tokio::test]
async fn events_are_read_on_postgres() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        scenario(&store).await;
    }
}

#[tokio::test]
async fn events_are_read_on_mysql() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        scenario(&store).await;
    }
}
