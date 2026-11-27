//! One password check at a time per account, a second apart.
//!
//! Every password finish costs the server a key check, and anyone can send one for any email. The
//! per-source limits stop one address; many addresses together are slowed by the account's own
//! limits. This gate bounds what is left: for one account at most one finish is in flight, and
//! the next starts at least [`MIN_INTERVAL`] after the last ended. A finish that finds another in
//! flight waits its turn (in order), so the right password is only ever later, never refused.
//!
//! So that the owner is not queued behind an unbounded line, at most [`MAX_WAITING`] finishes wait
//! per account; one that arrives past that skips the queue and is held back by the caller instead
//! (see `attempts::begin_password_attempt`). That keeps the rate for the account bounded by the
//! queue's own pace, not by how many requests arrive.

use kemlock_crypto::hash;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::Instant;

/// The least time between the end of one finish and the start of the next, for one account.
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);
/// The most finishes that wait their turn for one account.
pub const MAX_WAITING: usize = 16;
/// The most accounts the gate remembers; past it, the ones nobody holds or waits for are forgotten
/// (which can only let a finish start a moment early).
const MAX_ENTRIES: usize = 20_000;

type Key = [u8; 16];
type Last = Arc<AsyncMutex<Option<Instant>>>;

#[derive(Debug)]
pub struct PasswordGate {
    /// The interval in milliseconds; the tests of a whole API set it to nothing.
    interval_ms: AtomicU64,
    max_waiting: usize,
    slots: Mutex<HashMap<Key, (Last, Arc<AtomicUsize>)>>,
}

/// A finish in progress for one account; dropping it ends the finish and starts the interval.
#[derive(Debug)]
pub struct GateGuard {
    held: OwnedMutexGuard<Option<Instant>>,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        *self.held = Some(Instant::now());
    }
}

impl Default for PasswordGate {
    fn default() -> Self {
        PasswordGate::new(MIN_INTERVAL, MAX_WAITING)
    }
}

impl PasswordGate {
    pub fn new(interval: Duration, max_waiting: usize) -> Self {
        PasswordGate {
            interval_ms: AtomicU64::new(u64::try_from(interval.as_millis()).unwrap_or(u64::MAX)),
            max_waiting,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The least time between the end of one finish and the start of the next, for one account.
    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Relaxed))
    }

    /// Changes the interval (for tests that sign in many times).
    pub fn set_interval(&self, interval: Duration) {
        self.interval_ms.store(
            u64::try_from(interval.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn slot(&self, account: &str) -> (Last, Arc<AtomicUsize>) {
        let full = hash::sha256(account.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&full[..16]);
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if slots.len() >= MAX_ENTRIES && !slots.contains_key(&key) {
            slots.retain(|_, (last, _)| Arc::strong_count(last) > 1);
        }
        let (last, waiting) = slots.entry(key).or_insert_with(|| {
            (
                Arc::new(AsyncMutex::new(None)),
                Arc::new(AtomicUsize::new(0)),
            )
        });
        (Arc::clone(last), Arc::clone(waiting))
    }

    /// Waits for the account's turn: until no other finish is in flight and the interval since the
    /// last one has passed. `None` when [`MAX_WAITING`] others already wait (the caller holds the
    /// request back instead of queueing it).
    pub async fn enter(&self, account: &str) -> Option<GateGuard> {
        let (last, waiting) = self.slot(account);
        if waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
            waiting.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let held = last.lock_owned().await;
        waiting.fetch_sub(1, Ordering::SeqCst);
        if let Some(ended) = *held {
            tokio::time::sleep_until(ended + self.interval()).await;
        }
        Some(GateGuard { held })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEP: Duration = Duration::from_millis(80);

    #[tokio::test]
    async fn the_first_finish_starts_at_once_and_the_next_waits_the_interval() {
        let gate = PasswordGate::new(STEP, 4);
        let started = Instant::now();
        drop(gate.enter("acct:a").await.expect("a turn"));
        assert!(started.elapsed() < STEP, "no wait for the first");
        let second = Instant::now();
        let guard = gate.enter("acct:a").await.expect("a turn");
        assert!(
            second.elapsed() >= STEP,
            "a second apart: {:?}",
            second.elapsed()
        );
        drop(guard);
        // Another account has its own turn.
        let other = Instant::now();
        drop(gate.enter("acct:b").await.expect("a turn"));
        assert!(other.elapsed() < STEP);
    }

    #[tokio::test]
    async fn one_finish_is_in_flight_and_the_others_wait_in_turn() {
        let gate = Arc::new(PasswordGate::new(Duration::ZERO, 4));
        let first = gate.enter("acct:a").await.expect("a turn");
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for n in 0..3u32 {
            let (gate, order) = (Arc::clone(&gate), Arc::clone(&order));
            tasks.push(tokio::spawn(async move {
                let guard = gate.enter("acct:a").await.expect("waits, is not refused");
                order.lock().expect("lock").push(n);
                drop(guard);
            }));
            // Let each task join the line before the next, so the order is the arrival order.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            order.lock().expect("lock").is_empty(),
            "nothing runs beside the first"
        );
        drop(first);
        for task in tasks {
            task.await.expect("the task ran");
        }
        assert_eq!(*order.lock().expect("lock"), vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn past_the_waiting_line_a_finish_skips_it_and_is_not_queued() {
        let gate = Arc::new(PasswordGate::new(Duration::ZERO, 2));
        let first = gate.enter("acct:a").await.expect("a turn");
        let mut waiting = Vec::new();
        for _ in 0..2 {
            let gate = Arc::clone(&gate);
            waiting.push(tokio::spawn(
                async move { gate.enter("acct:a").await.is_some() },
            ));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(gate.enter("acct:a").await.is_none(), "the line is full");
        drop(first);
        for task in waiting {
            assert!(
                task.await.expect("the task ran"),
                "those in line still get their turn"
            );
        }
        assert!(
            gate.enter("acct:a").await.is_some(),
            "and the line is open again"
        );
    }
}
