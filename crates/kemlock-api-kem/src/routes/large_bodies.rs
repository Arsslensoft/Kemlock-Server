//! Who may have a large body in hand on the space chain routes: the places for bodies above
//! 8 MiB, which are the requests of a key replacement (docs/crypto.md, "Accepting records").
//!
//! A large body is costly: up to 32 MiB held in memory and 1,800 or more signatures to check. So:
//!
//! - **Places.** The server has two. An account and a space have one each at a time. The places
//!   are served as a queue: a request that finds none waits up to ten seconds, and the next place
//!   goes to the request that has waited longest. An account has one place or one turn in the
//!   queue, never two, so the queue is round-robin between accounts: a request that comes back
//!   after its turn goes behind the others.
//! - **Every large body counts** against the account that sent it, whatever came of it: the
//!   account waits a minute, from the moment the request is over, before another. The one
//!   exception is a request that replaced a marked collection key and was stored (`201`), which
//!   is what the places are for; it doesn't count.
//! - **A budget** of four large bodies an hour for each account, on top of the places.
//!
//! The places are owned by the router that serves the routes, never by the process, so each
//! router (and each test) has its own.

use crate::problem::{Problem, rate_limited};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

/// The most large bodies a server reads and handles at once.
const PLACES: usize = 2;
/// How long an account waits after a large body, in seconds.
const COOLDOWN_SECS: i64 = 60;
/// How many large bodies an account may send in [`BUDGET_WINDOW_SECS`].
const BUDGET: usize = 4;
const BUDGET_WINDOW_SECS: i64 = 3600;
/// How long a request waits for a place before it is told to try again.
const QUEUE_WAIT: Duration = Duration::from_secs(10);
/// What a request that waited in vain is told to wait, in seconds.
const QUEUE_RETRY_SECS: u64 = 15;

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The places for large bodies and who waits for them. Cloning it shares them.
#[derive(Clone)]
pub struct LargeBodies(Arc<Inner>);

struct Inner {
    state: Mutex<State>,
    /// Woken whenever a place is freed or a request leaves the queue.
    notify: Notify,
}

struct State {
    max: usize,
    cooldown: i64,
    budget: usize,
    wait: Duration,
    clock: Clock,
    /// Places in use.
    active: usize,
    /// The accounts and spaces that have a place or a turn in the queue.
    accounts: BTreeSet<[u8; 16]>,
    spaces: BTreeSet<[u8; 16]>,
    queue: VecDeque<Waiter>,
    next_id: u64,
    /// The accounts that wait after a large body, and until when (Unix seconds).
    cooling: BTreeMap<[u8; 16], i64>,
    /// When each account was given its places in the last hour.
    taken: BTreeMap<[u8; 16], VecDeque<i64>>,
}

struct Waiter {
    id: u64,
    account: [u8; 16],
    space: [u8; 16],
}

impl State {
    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Whether `account` may ask for a place in `space` at `now`: it isn't waiting out a large
    /// body, has budget left, and neither it nor the space has a place or a turn already.
    fn admit(&mut self, account: [u8; 16], space: [u8; 16], now: i64) -> Result<(), Problem> {
        self.cooling.retain(|_, until| *until > now);
        if let Some(until) = self.cooling.get(&account) {
            return Err(rate_limited(u64::try_from(*until - now).unwrap_or(1).max(1)));
        }
        let window = self.taken.entry(account).or_default();
        while window
            .front()
            .is_some_and(|at| *at <= now - BUDGET_WINDOW_SECS)
        {
            window.pop_front();
        }
        if window.len() >= self.budget {
            let free_at = window.front().map_or(now, |at| at + BUDGET_WINDOW_SECS);
            return Err(rate_limited(u64::try_from(free_at - now).unwrap_or(1).max(1)));
        }
        if self.accounts.contains(&account) || self.spaces.contains(&space) {
            return Err(rate_limited(5));
        }
        Ok(())
    }

    /// Gives `account` a place at `now`.
    fn grant(&mut self, account: [u8; 16], now: i64) {
        self.active += 1;
        self.taken.entry(account).or_default().push_back(now);
    }
}

impl fmt::Debug for LargeBodies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LargeBodies").finish_non_exhaustive()
    }
}

impl Default for LargeBodies {
    fn default() -> LargeBodies {
        LargeBodies::new(PLACES, COOLDOWN_SECS)
    }
}

impl LargeBodies {
    /// Room for `max` large bodies at once, and `cooldown` seconds of waiting after each large
    /// body, with the budget of four an hour and ten seconds in the queue.
    pub fn new(max: usize, cooldown: i64) -> LargeBodies {
        let clock: Clock = Arc::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        });
        LargeBodies(Arc::new(Inner {
            state: Mutex::new(State {
                max,
                cooldown,
                budget: BUDGET,
                wait: QUEUE_WAIT,
                clock,
                active: 0,
                accounts: BTreeSet::new(),
                spaces: BTreeSet::new(),
                queue: VecDeque::new(),
                next_id: 0,
                cooling: BTreeMap::new(),
                taken: BTreeMap::new(),
            }),
            notify: Notify::new(),
        }))
    }

    /// Allows each account `per_hour` large bodies an hour.
    #[must_use]
    pub fn with_budget(self, per_hour: usize) -> LargeBodies {
        self.lock().budget = per_hour;
        self
    }

    /// Makes a request wait `wait` for a place.
    #[must_use]
    pub fn with_wait(self, wait: Duration) -> LargeBodies {
        self.lock().wait = wait;
        self
    }

    /// Reads the time, in Unix seconds, from `clock`.
    #[must_use]
    pub fn with_clock(self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> LargeBodies {
        self.lock().clock = Arc::new(clock);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn place(&self, account: [u8; 16], space: [u8; 16]) -> LargeBody {
        LargeBody {
            places: self.clone(),
            account,
            space,
            replaced: false,
        }
    }

    /// A place for `account` in `space`, or `429`: the account waits out its last large body, is
    /// out of budget, or has a place or a turn already, the space has one, or no place came free
    /// in the time a request waits for one.
    pub async fn take(&self, account: [u8; 16], space: [u8; 16]) -> Result<LargeBody, Problem> {
        let (id, wait) = {
            let mut state = self.lock();
            let now = state.now();
            state.admit(account, space, now)?;
            state.accounts.insert(account);
            state.spaces.insert(space);
            if state.queue.is_empty() && state.active < state.max {
                state.grant(account, now);
                return Ok(self.place(account, space));
            }
            let id = state.next_id;
            state.next_id += 1;
            state.queue.push_back(Waiter { id, account, space });
            (id, state.wait)
        };
        // Leaving the queue for any reason (a place, a timeout, the client going away) lets go of
        // the turn.
        let mut waiting = Waiting {
            places: self.clone(),
            id,
            account,
            space,
            queued: true,
        };
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Asked for before the state is read, so a place freed in between is not missed.
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock();
                if state.active < state.max && state.queue.front().is_some_and(|w| w.id == id) {
                    state.queue.pop_front();
                    let now = state.now();
                    state.grant(account, now);
                    waiting.queued = false;
                    drop(state);
                    // The one behind may fit as well.
                    self.0.notify.notify_waiters();
                    return Ok(self.place(account, space));
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(rate_limited(QUEUE_RETRY_SECS));
            }
        }
    }

    /// A place taken without a request, for a test that fills them.
    #[doc(hidden)]
    pub async fn occupy(&self, account: [u8; 16], space: [u8; 16]) -> Result<LargeBody, Problem> {
        self.take(account, space).await
    }
}

/// A turn in the queue, given up when it is dropped while it still waits.
struct Waiting {
    places: LargeBodies,
    id: u64,
    account: [u8; 16],
    space: [u8; 16],
    queued: bool,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if !self.queued {
            return;
        }
        let mut state = self.places.lock();
        state.queue.retain(|w| w.id != self.id);
        state.accounts.remove(&self.account);
        state.spaces.remove(&self.space);
        drop(state);
        self.places.0.notify.notify_waiters();
    }
}

/// A place among the large bodies, held until the request is answered. Dropping it frees the place
/// and starts the account's wait, unless the request [`replaced`](LargeBody::replaced) a key.
#[derive(Debug)]
pub struct LargeBody {
    places: LargeBodies,
    account: [u8; 16],
    space: [u8; 16],
    replaced: bool,
}

impl LargeBody {
    /// The request replaced a marked collection key and was stored: it is what the places are for,
    /// so it costs the account neither a wait nor budget.
    pub(crate) fn replaced(&mut self) {
        self.replaced = true;
    }
}

impl Drop for LargeBody {
    fn drop(&mut self) {
        let mut state = self.places.lock();
        // From the moment the request is over, not from the moment it began.
        let now = state.now();
        state.active = state.active.saturating_sub(1);
        state.accounts.remove(&self.account);
        state.spaces.remove(&self.space);
        if self.replaced {
            if let Some(window) = state.taken.get_mut(&self.account) {
                window.pop_back();
            }
        } else {
            let until = now.saturating_add(state.cooldown);
            state.cooling.insert(self.account, until);
        }
        drop(state);
        self.places.0.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use std::sync::atomic::{AtomicI64, Ordering};

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const C: [u8; 16] = [3; 16];
    const S1: [u8; 16] = [11; 16];
    const S2: [u8; 16] = [12; 16];
    const S3: [u8; 16] = [13; 16];

    /// Places with a clock the test sets.
    fn timed(max: usize, cooldown: i64) -> (LargeBodies, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(0));
        let clock = now.clone();
        let places = LargeBodies::new(max, cooldown).with_clock(move || clock.load(Ordering::SeqCst));
        (places, now)
    }

    /// Long enough for a spawned request to reach its wait.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    fn spawn_take(
        places: &LargeBodies,
        account: [u8; 16],
        space: [u8; 16],
    ) -> tokio::task::JoinHandle<Result<LargeBody, Problem>> {
        let places = places.clone();
        tokio::spawn(async move { places.take(account, space).await })
    }

    #[tokio::test]
    async fn a_place_is_for_one_account_and_one_space_at_a_time() {
        let places = LargeBodies::new(3, 0).with_budget(100);
        let first = places.take(A, S1).await.expect("a place");
        assert_eq!(
            places.take(A, S2).await.expect_err("the account has one").status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            places.take(B, S1).await.expect_err("the space has one").status,
            StatusCode::TOO_MANY_REQUESTS
        );
        let other = places.take(B, S2).await.expect("another place");
        drop(first);
        drop(other);
        places.take(A, S1).await.expect("the places came back");
    }

    #[tokio::test]
    async fn the_next_place_goes_to_whoever_waited_longest_and_a_return_goes_behind() {
        let places = LargeBodies::new(1, 0)
            .with_budget(100)
            .with_wait(Duration::from_secs(5));
        let held = places.take(A, S1).await.expect("a place");
        let b = spawn_take(&places, B, S2);
        settle().await;
        let c = spawn_take(&places, C, S3);
        settle().await;
        assert!(!b.is_finished() && !c.is_finished());

        // A's place comes back: B was first, so B has it, and C still waits.
        drop(held);
        let b_body = b.await.expect("joined").expect("B's turn");
        settle().await;
        assert!(!c.is_finished());

        // A asks again: it goes behind C, though it is the one that just had a place.
        let a = spawn_take(&places, A, S1);
        settle().await;
        drop(b_body);
        let c_body = c.await.expect("joined").expect("C's turn");
        settle().await;
        assert!(!a.is_finished());
        drop(c_body);
        a.await.expect("joined").expect("A's turn again");
    }

    #[tokio::test]
    async fn a_request_that_waits_in_vain_is_told_to_try_again_and_leaves_no_turn_behind() {
        let places = LargeBodies::new(1, 0)
            .with_budget(100)
            .with_wait(Duration::from_millis(60));
        let held = places.take(A, S1).await.expect("a place");
        let told = places.take(B, S2).await.expect_err("no place came free");
        assert_eq!(told.status, StatusCode::TOO_MANY_REQUESTS);
        // B's turn and claims are gone: once the place is free, B has it at once.
        drop(held);
        places.take(B, S2).await.expect("B's turn");
    }

    #[tokio::test]
    async fn an_account_waits_a_minute_from_the_end_of_its_large_body() {
        let (places, now) = timed(2, 60);
        now.store(100, Ordering::SeqCst);
        let body = places.take(A, S1).await.expect("a place");
        // The body takes a while: it is over at 150, so the wait runs to 210, not to 160.
        now.store(150, Ordering::SeqCst);
        drop(body);
        now.store(209, Ordering::SeqCst);
        assert_eq!(
            places.take(A, S1).await.expect_err("still waiting").status,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Others are not held up by it.
        places.take(B, S2).await.expect("B's place");
        now.store(210, Ordering::SeqCst);
        places.take(A, S1).await.expect("the wait is over");
    }

    #[tokio::test]
    async fn a_request_that_replaced_a_key_costs_neither_a_wait_nor_budget() {
        let (places, _now) = timed(2, 60);
        let places = places.with_budget(1);
        let mut body = places.take(A, S1).await.expect("a place");
        body.replaced();
        drop(body);
        // No wait, and the one large body of the hour is still there to send.
        let again = places.take(A, S1).await.expect("it didn't count");
        // This one didn't replace anything: it counts, however it ended.
        drop(again);
        assert_eq!(
            places.take(A, S1).await.expect_err("it did count").status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn an_account_has_four_large_bodies_an_hour() {
        let (places, now) = timed(2, 0);
        now.store(1_000, Ordering::SeqCst);
        for _ in 0..4 {
            let body = places.take(A, S1).await.expect("within the budget");
            drop(body);
        }
        let told = places.take(A, S1).await.expect_err("out of budget");
        assert_eq!(told.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(told.headers.iter().any(|(name, _)| name == "retry-after"));
        // The budget is the account's own.
        places.take(B, S2).await.expect("B's budget");
        // An hour after the first, one comes back.
        now.store(1_000 + BUDGET_WINDOW_SECS, Ordering::SeqCst);
        places.take(A, S1).await.expect("an hour has passed");
    }
}
