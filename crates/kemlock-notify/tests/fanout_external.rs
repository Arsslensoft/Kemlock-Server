//! The fan-out between two replicas on a real PostgreSQL or MySQL server, when
//! `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set (the same variables the store's
//! tests use). Each replica is its own connection pool on the one database.

use kemlock_domain::{Owner, UserId};
use kemlock_notify::fanout::{Fanout, FanoutOptions, Sink, Transport};
use kemlock_store_sql::SqlStore;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Default)]
struct Heard(Arc<Mutex<Vec<Owner>>>);

impl Heard {
    fn sink(&self) -> Sink {
        let owners = self.0.clone();
        Sink::new(move |owner| owners.lock().expect("lock").push(owner), || {})
    }

    fn count(&self, owner: Owner) -> usize {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .filter(|o| **o == owner)
            .count()
    }
}

async fn wait_for(mut check: impl FnMut() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never held");
}

async fn replicas(url: &str, expected: Transport) {
    let options = FanoutOptions {
        poll_every: Duration::from_millis(50),
        ..FanoutOptions::default()
    };
    let (a, b) = (Heard::default(), Heard::default());
    let store_a = SqlStore::connect(url).await.expect("replica a connects");
    let store_b = SqlStore::connect(url).await.expect("replica b connects");
    let fanout_a = Fanout::connect(&store_a, a.sink(), options)
        .await
        .expect("a");
    let fanout_b = Fanout::connect(&store_b, b.sink(), options)
        .await
        .expect("b");
    assert_eq!(fanout_a.transport(), expected);

    // Owners no earlier run used, so a database kept between runs doesn't confuse the counts.
    let (one, two) = (Owner::User(UserId::random()), Owner::User(UserId::random()));
    fanout_a.nudge(one);
    wait_for(|| a.count(one) >= 1 && b.count(one) >= 1).await;
    fanout_b.nudge(two);
    wait_for(|| a.count(two) >= 1 && b.count(two) >= 1).await;

    // Each replica heard each nudge exactly once, whichever path it took.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for owner in [one, two] {
        assert_eq!(a.count(owner), 1, "replica a, {owner}");
        assert_eq!(b.count(owner), 1, "replica b, {owner}");
    }
}

#[tokio::test]
async fn postgres_replicas_hear_each_other_through_notify() {
    match std::env::var("KEMLOCK_TEST_POSTGRES_URL") {
        Ok(url) if !url.is_empty() => replicas(&url, Transport::Postgres).await,
        _ => eprintln!("KEMLOCK_TEST_POSTGRES_URL is not set; skipping"),
    }
}

#[tokio::test]
async fn mysql_replicas_hear_each_other_by_polling() {
    match std::env::var("KEMLOCK_TEST_MYSQL_URL") {
        Ok(url) if !url.is_empty() => replicas(&url, Transport::Polling).await,
        _ => eprintln!("KEMLOCK_TEST_MYSQL_URL is not set; skipping"),
    }
}

#[tokio::test]
async fn sqlite_replicas_share_nothing_so_each_hears_only_its_own() {
    // SQLite is one process: there is no second replica, and the nudge stays in this one.
    let store = SqlStore::connect("sqlite::memory:").await.expect("store");
    let heard = Heard::default();
    let fanout = Fanout::connect(&store, heard.sink(), FanoutOptions::default())
        .await
        .expect("fanout");
    assert_eq!(fanout.transport(), Transport::InProcess);
    let owner = Owner::User(UserId::random());
    fanout.nudge(owner);
    assert_eq!(heard.count(owner), 1);
}
