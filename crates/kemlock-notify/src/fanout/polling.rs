//! The polling transport, for MySQL: append to the nudge log, read it every second.
//!
//! A replica delivers its own nudges to its sockets at once and remembers the log ids it
//! appended, so the poll skips them instead of nudging a socket twice. The poll starts from the
//! newest entry at start, so a replica never replays old nudges. Any replica prunes entries older
//! than `keep`.

use super::Sink;
use kemlock_app::ports::StoreError;
use kemlock_app::push::NudgeLog;
use kemlock_domain::Owner;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

/// How many entries one poll reads.
const PAGE: u32 = 500;
/// The most own ids remembered, in case the log is pruned before they are polled.
const MAX_REMEMBERED: usize = 10_000;

pub(crate) async fn start<L: NudgeLog + 'static>(
    log: Arc<L>,
    sink: Sink,
    poll_every: Duration,
    keep: Duration,
) -> Result<(mpsc::UnboundedSender<Owner>, Vec<JoinHandle<()>>), StoreError> {
    let cursor = log.latest_nudge().await?;
    let mine = Arc::new(Mutex::new(HashSet::new()));
    let (tx, rx) = mpsc::unbounded_channel();
    let publisher = tokio::spawn(publish_loop(log.clone(), sink.clone(), mine.clone(), rx));
    let poller = tokio::spawn(poll_loop(log, sink, mine, cursor, poll_every, keep));
    Ok((tx, vec![publisher, poller]))
}

async fn publish_loop<L: NudgeLog>(
    log: Arc<L>,
    sink: Sink,
    mine: Arc<Mutex<HashSet<i64>>>,
    mut queue: mpsc::UnboundedReceiver<Owner>,
) {
    while let Some(owner) = queue.recv().await {
        sink.owner(owner);
        // Held across the append, so the poller either runs before the entry exists or finds
        // its id here.
        let mut remembered = mine.lock().await;
        match log.append_nudge(owner).await {
            Ok(id) => {
                if remembered.len() >= MAX_REMEMBERED {
                    remembered.clear();
                }
                remembered.insert(id);
            }
            Err(error) => {
                tracing::warn!(%error, "couldn't append a nudge; other replicas catch up at their next sync");
            }
        }
    }
}

async fn poll_loop<L: NudgeLog>(
    log: Arc<L>,
    sink: Sink,
    mine: Arc<Mutex<HashSet<i64>>>,
    mut cursor: i64,
    poll_every: Duration,
    keep: Duration,
) {
    let mut ticker = tokio::time::interval(poll_every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_prune = Instant::now();
    loop {
        ticker.tick().await;
        loop {
            let mut remembered = mine.lock().await;
            match log.nudges_since(cursor, PAGE).await {
                Ok(page) => {
                    for entry in &page {
                        cursor = entry.id;
                        if !remembered.remove(&entry.id) {
                            sink.owner(entry.owner);
                        }
                    }
                    if page.len() < PAGE as usize {
                        break;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "couldn't read the nudge log");
                    break;
                }
            }
        }
        if last_prune.elapsed() >= keep {
            last_prune = Instant::now();
            let seconds = i64::try_from(keep.as_secs()).unwrap_or(60);
            let before = OffsetDateTime::now_utc() - time::Duration::seconds(seconds);
            if let Err(error) = log.prune_nudges(before).await {
                tracing::warn!(%error, "couldn't prune the nudge log");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{Heard, eventually};
    use super::super::{Fanout, FanoutOptions, Transport};
    use super::*;
    use kemlock_domain::UserId;
    use kemlock_store_sql::SqlStore;

    fn options() -> FanoutOptions {
        FanoutOptions {
            poll_every: Duration::from_millis(20),
            keep: Duration::from_secs(60),
            retry_after: Duration::from_millis(10),
        }
    }

    fn owner() -> Owner {
        Owner::User(UserId::random())
    }

    /// Two replicas on one database, as two `Fanout`s over the same log.
    async fn two_replicas(options: FanoutOptions) -> (SqlStore, Fanout, Heard, Fanout, Heard) {
        let store = SqlStore::connect("sqlite::memory:").await.expect("store");
        let (a, b) = (Heard::default(), Heard::default());
        let fa = Fanout::over_log(Arc::new(store.clone()), a.sink(), options)
            .await
            .expect("a");
        let fb = Fanout::over_log(Arc::new(store.clone()), b.sink(), options)
            .await
            .expect("b");
        (store, fa, a, fb, b)
    }

    #[tokio::test]
    async fn a_nudge_reaches_the_other_replica_and_this_one_only_once() {
        let (_store, fa, a, _fb, b) = two_replicas(options()).await;
        assert_eq!(fa.transport(), Transport::Polling);
        let o = owner();
        fa.nudge(o);
        eventually(|| a.owners().len() == 1 && b.owners().len() == 1).await;
        // Several polls later the committing replica has still heard it once.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(a.owners(), vec![o]);
        assert_eq!(b.owners(), vec![o]);
        assert_eq!(a.everyone_count() + b.everyone_count(), 0);
    }

    #[tokio::test]
    async fn nudges_arrive_in_order_in_both_directions() {
        let (_store, fa, a, fb, b) = two_replicas(options()).await;
        let (o1, o2, o3) = (owner(), owner(), owner());
        fa.nudge(o1);
        fb.nudge(o2);
        fa.nudge(o3);
        eventually(|| a.owners().len() == 3 && b.owners().len() == 3).await;
        // Each replica heard its own at once and the other's by polling; all three, none twice.
        let mut seen_a = a.owners();
        seen_a.sort();
        let mut want = vec![o1, o2, o3];
        want.sort();
        assert_eq!(seen_a, want);
        let mut seen_b = b.owners();
        seen_b.sort();
        assert_eq!(seen_b, want);
    }

    #[tokio::test]
    async fn a_replica_does_not_replay_what_was_logged_before_it_started() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("store");
        store.append_nudge(owner()).await.expect("old nudge");
        let heard = Heard::default();
        let _fanout = Fanout::over_log(Arc::new(store.clone()), heard.sink(), options())
            .await
            .expect("fanout");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(heard.owners().is_empty());
        // A nudge from another replica after the start is heard.
        let o = owner();
        store.append_nudge(o).await.expect("new nudge");
        eventually(|| heard.owners() == vec![o]).await;
    }

    #[tokio::test]
    async fn old_entries_are_pruned() {
        let mut quick = options();
        quick.keep = Duration::from_millis(50);
        let (store, fa, _a, _fb, _b) = two_replicas(quick).await;
        fa.nudge(owner());
        // The entry is there at first, and gone once it is older than `keep` and a poll prunes it.
        let mut appended = false;
        for _ in 0..500 {
            if !store.nudges_since(0, 10).await.expect("reads").is_empty() {
                appended = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(appended, "the nudge was never logged");
        let mut emptied = false;
        for _ in 0..500 {
            let entries = store.nudges_since(0, 10).await.expect("reads");
            if entries.is_empty() {
                emptied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(emptied, "the log was never pruned");
    }

    #[tokio::test]
    async fn a_busy_log_is_read_in_full_pages() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("store");
        let heard = Heard::default();
        let _fanout = Fanout::over_log(Arc::new(store.clone()), heard.sink(), options())
            .await
            .expect("fanout");
        let total = PAGE as usize + 20;
        for _ in 0..total {
            store.append_nudge(owner()).await.expect("append");
        }
        eventually(|| heard.owners().len() == total).await;
    }

    #[tokio::test]
    async fn dropping_the_fanout_stops_its_tasks() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("store");
        let heard = Heard::default();
        let fanout = Fanout::over_log(Arc::new(store.clone()), heard.sink(), options())
            .await
            .expect("fanout");
        drop(fanout);
        tokio::time::sleep(Duration::from_millis(50)).await;
        store.append_nudge(owner()).await.expect("append");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(heard.owners().is_empty(), "a stopped replica hears nothing");
    }
}
