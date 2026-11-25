//! `Withholding` on a real `SqlStore`: a cancelled queue is kept per peer and vault, a second
//! cancel adds to it, and forgetting a peer drops it.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, and PostgreSQL and
//! MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, memory};
use kemlock_domain::{ChangeId, Hlc, Owner, ServerId, UserId, VersionVector};
use kemlock_federation::outbox::Withholding;
use kemlock_store_sql::SqlStore;

fn change(origin: ServerId, seq: u64) -> ChangeId {
    ChangeId {
        origin,
        seq,
        hlc: Hlc::default(),
    }
}

fn upto(origin: ServerId, seq: u64) -> VersionVector {
    let mut vector = VersionVector::new();
    vector.observe(&change(origin, seq));
    vector
}

async fn a_cancelled_queue_is_kept_added_to_and_forgotten(store: &SqlStore) {
    let (peer, other_peer) = (ServerId::random(), ServerId::random());
    let (mine, theirs) = (Owner::User(UserId::random()), Owner::User(UserId::random()));
    let origin = ServerId::random();
    assert_eq!(store.withheld(peer, mine).await, Ok(None));

    store
        .withhold(peer, mine, &upto(origin, 5), 1_000)
        .await
        .expect("withhold");
    let held = store
        .withheld(peer, mine)
        .await
        .expect("read")
        .expect("kept");
    assert_eq!(held.at, 1_000);
    assert!(held.covers(&change(origin, 5)) && held.covers(&change(origin, 1)));
    assert!(!held.covers(&change(origin, 6)), "later changes flow");

    // Per peer and per vault.
    assert_eq!(store.withheld(other_peer, mine).await, Ok(None));
    assert_eq!(store.withheld(peer, theirs).await, Ok(None));

    // A second cancel adds to the first: the cursor only grows, and the time is the latest.
    let second = ServerId::random();
    let mut more = upto(origin, 3);
    more.observe(&change(second, 2));
    store
        .withhold(peer, mine, &more, 2_000)
        .await
        .expect("withhold again");
    let held = store
        .withheld(peer, mine)
        .await
        .expect("read")
        .expect("kept");
    assert_eq!(held.at, 2_000);
    assert!(
        held.covers(&change(origin, 5)),
        "the first cancel still holds"
    );
    assert!(held.covers(&change(second, 2)));

    // A release lifts one peer's rows in one vault and says whether there was anything to lift.
    store
        .withhold(other_peer, mine, &upto(origin, 1), 3_000)
        .await
        .expect("another peer first");
    assert_eq!(store.release_withheld(other_peer, mine).await, Ok(true));
    assert_eq!(store.release_withheld(other_peer, mine).await, Ok(false));
    assert_eq!(store.release_withheld(peer, theirs).await, Ok(false));

    // Forgetting a peer drops its rows and no one else's.
    store
        .withhold(other_peer, mine, &upto(origin, 1), 3_000)
        .await
        .expect("another peer");
    store.forget_withheld(peer).await.expect("forget");
    assert_eq!(store.withheld(peer, mine).await, Ok(None));
    assert!(
        store
            .withheld(other_peer, mine)
            .await
            .expect("read")
            .is_some()
    );
}

async fn run_all(store: &SqlStore) {
    a_cancelled_queue_is_kept_added_to_and_forgotten(store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}
