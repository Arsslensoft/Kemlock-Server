//! The gate every PBKDF2 over a client's password hash goes through.
//!
//! The check is 600,000 rounds, 0.1 to 0.3 s of one core, and it is asked for by clients nobody has
//! signed in. The gate bounds what that can cost the server:
//!
//! - **The whole server:** a pool of permits about the size of the CPU count. A request waits for
//!   one a bounded time and is then answered 429, so the queue is never longer than the wait.
//! - **One account:** at most one hash in flight, and a minimum time between the end of one and the
//!   start of the next (a second by default). A right password still passes, only a little later,
//!   so nobody can keep the owner out by asking again and again. An address with no account is
//!   treated the same way, keyed by a MAC of the address, so the treatment says nothing about who
//!   has an account.
//! - **One client prefix** (a /56 for IPv6, an IPv4 address): at most one hash in flight. A second
//!   request from the same prefix is answered 429 at once.
//!
//! The permit and the claims on the account and the prefix are held by the blocking task that does
//! the work, not by the request: a request that is dropped (a reset connection, a timeout) leaves
//! the hash running, and the claims stay until it ends.
//!
//! What is left: someone with many prefixes can make the waits of the accounts and the pool longer
//! for others, as with Vaultwarden, and that is all; they can no longer stop the rest of the
//! server, which the hash never runs on.

use crate::error::{BwError, BwResult};
use axum::http::StatusCode;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// How long a request waits for the pool, and for its account's turn.
pub(crate) const DEFAULT_WAIT: Duration = Duration::from_secs(5);
/// The least time between two hashes of one account.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
/// The most accounts followed at once before idle ones are dropped.
const MAX_FOLLOWED: usize = 10_000;
/// How often a waiting request looks again at its account's turn.
const POLL: Duration = Duration::from_millis(25);

/// Who a hash is for: the account (a MAC of it, so a decoy for an address with no account has one
/// too) and the client's prefix, each when there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Who {
    pub account: Option<[u8; 32]>,
    pub prefix: Option<IpAddr>,
}

#[derive(Debug, Default)]
struct Account {
    in_flight: bool,
    /// The earliest the account's next hash may start.
    next: Option<Instant>,
}

#[derive(Debug)]
struct Inner {
    pool: Arc<Semaphore>,
    wait: Duration,
    interval: Duration,
    accounts: Mutex<HashMap<[u8; 32], Account>>,
    prefixes: Mutex<std::collections::HashSet<IpAddr>>,
}

/// The gate; cheap to clone.
#[derive(Clone, Debug)]
pub(crate) struct HashGate(Arc<Inner>);

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn too_many() -> BwError {
    BwError::status(StatusCode::TOO_MANY_REQUESTS, "Too many login requests")
}

/// What a running hash holds; it is given back when the hash ends, on whichever thread.
struct Claims {
    gate: HashGate,
    who: Who,
    started: bool,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Claims {
    fn drop(&mut self) {
        let inner = &self.gate.0;
        if let Some(key) = self.who.account {
            let mut accounts = locked(&inner.accounts);
            if let Some(account) = accounts.get_mut(&key) {
                account.in_flight = false;
                // Only a hash that ran makes the next one wait.
                if self.started {
                    account.next = Some(Instant::now() + inner.interval);
                }
            }
        }
        if let Some(prefix) = self.who.prefix {
            locked(&inner.prefixes).remove(&prefix);
        }
    }
}

impl HashGate {
    /// A gate of `permits` hashes at once (at least one), a wait of `wait` and `interval` between
    /// the hashes of one account.
    pub(crate) fn new(permits: usize, wait: Duration, interval: Duration) -> HashGate {
        HashGate(Arc::new(Inner {
            pool: Arc::new(Semaphore::new(permits.max(1))),
            wait,
            interval,
            accounts: Mutex::new(HashMap::new()),
            prefixes: Mutex::new(std::collections::HashSet::new()),
        }))
    }

    /// About the CPU count.
    pub(crate) fn default_permits() -> usize {
        std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get)
    }

    /// The permits not in use now.
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.0.pool.available_permits()
    }

    /// Takes the account's turn, waiting for it up to `deadline`.
    async fn claim_account(&self, key: [u8; 32], deadline: Instant) -> BwResult<()> {
        loop {
            {
                let mut accounts = locked(&self.0.accounts);
                let now = Instant::now();
                if accounts.len() >= MAX_FOLLOWED && !accounts.contains_key(&key) {
                    accounts.retain(|_, a| a.in_flight || a.next.is_some_and(|at| at > now));
                }
                let account = accounts.entry(key).or_default();
                if !account.in_flight && account.next.is_none_or(|at| at <= now) {
                    account.in_flight = true;
                    return Ok(());
                }
            }
            if Instant::now() + POLL > deadline {
                return Err(too_many());
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Runs `work` on a blocking thread for `who`, under the gate. `Err` is a 429 when the prefix
    /// has a hash running, or the account's turn or a permit did not come in time.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        who: Who,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> BwResult<T> {
        let deadline = Instant::now() + self.0.wait;
        if let Some(prefix) = who.prefix
            && !locked(&self.0.prefixes).insert(prefix)
        {
            return Err(too_many());
        }
        // From here the claims are given back by `Claims`, wherever this returns.
        let mut claims = Claims {
            gate: self.clone(),
            who: Who {
                account: None,
                prefix: who.prefix,
            },
            started: false,
            _permit: None,
        };
        if let Some(key) = who.account {
            self.claim_account(key, deadline).await?;
            claims.who.account = Some(key);
        }
        let permit =
            match tokio::time::timeout_at(deadline, Arc::clone(&self.0.pool).acquire_owned()).await
            {
                Ok(Ok(permit)) => permit,
                _ => return Err(too_many()),
            };
        claims._permit = Some(permit);
        claims.started = true;
        tokio::task::spawn_blocking(move || {
            let _claims = claims;
            work()
        })
        .await
        .map_err(|e| BwError::Server(format!("a password hash check stopped: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    fn who(n: u8, prefix: Option<u8>) -> Who {
        Who {
            account: Some([n; 32]),
            prefix: prefix.map(|p| IpAddr::from([10, 0, 0, p])),
        }
    }

    fn is_429(error: &BwError) -> bool {
        matches!(error, BwError::Status(StatusCode::TOO_MANY_REQUESTS, _))
    }

    /// A hash that starts, tells the test, and ends when the test says.
    fn held(
        gate: &HashGate,
        who: Who,
    ) -> (
        tokio::task::JoinHandle<BwResult<()>>,
        mpsc::Sender<()>,
        mpsc::Receiver<()>,
    ) {
        let (release, hold) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        let gate = gate.clone();
        let task = tokio::spawn(async move {
            gate.run(who, move || {
                started_tx.send(()).expect("sent");
                hold.recv().expect("released");
            })
            .await
        });
        (task, release, started)
    }

    async fn wait_started(started: mpsc::Receiver<()>) {
        tokio::task::spawn_blocking(move || started.recv().expect("started"))
            .await
            .expect("waited");
    }

    #[tokio::test]
    async fn work_runs_and_the_claims_are_given_back() {
        let gate = HashGate::new(2, Duration::from_millis(500), Duration::ZERO);
        assert_eq!(gate.run(who(1, Some(1)), || 7).await.expect("runs"), 7);
        assert_eq!(gate.run(who(1, Some(1)), || 8).await.expect("runs"), 8);
        assert_eq!(gate.available(), 2);
    }

    #[tokio::test]
    async fn a_second_hash_of_one_prefix_is_refused_while_one_runs() {
        let gate = HashGate::new(4, Duration::from_millis(500), Duration::ZERO);
        let (task, release, started) = held(&gate, who(1, Some(9)));
        wait_started(started).await;
        let refused = gate.run(who(2, Some(9)), || ()).await.expect_err("refused");
        assert!(is_429(&refused));
        gate.run(who(3, Some(8)), || ())
            .await
            .expect("another prefix runs");
        release.send(()).expect("released");
        task.await.expect("joined").expect("the first finished");
        gate.run(who(2, Some(9)), || ()).await.expect("runs again");
    }

    #[tokio::test]
    async fn an_account_waits_between_hashes_and_other_accounts_do_not() {
        let gate = HashGate::new(4, Duration::from_millis(900), Duration::from_millis(150));
        let began = Instant::now();
        gate.run(who(1, None), || ()).await.expect("runs");
        gate.run(who(1, None), || ())
            .await
            .expect("runs after the interval");
        assert!(began.elapsed() >= Duration::from_millis(150));
        let other = Instant::now();
        gate.run(who(2, None), || ()).await.expect("runs");
        assert!(other.elapsed() < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn an_account_whose_turn_does_not_come_in_time_is_refused() {
        let gate = HashGate::new(4, Duration::from_millis(100), Duration::from_secs(5));
        gate.run(who(1, None), || ()).await.expect("runs");
        let refused = gate.run(who(1, None), || ()).await.expect_err("too soon");
        assert!(is_429(&refused));
    }

    #[tokio::test]
    async fn a_full_pool_makes_a_request_wait_and_then_answer_429() {
        let gate = HashGate::new(1, Duration::from_millis(150), Duration::ZERO);
        let (task, release, started) = held(&gate, who(1, None));
        wait_started(started).await;
        assert_eq!(gate.available(), 0);
        let began = Instant::now();
        let refused = gate.run(who(2, None), || ()).await.expect_err("refused");
        assert!(is_429(&refused));
        assert!(began.elapsed() >= Duration::from_millis(100), "it waited");
        release.send(()).expect("released");
        task.await.expect("joined").expect("finished");
        // The refused one gave its account back.
        gate.run(who(2, None), || ()).await.expect("runs");
    }

    #[tokio::test]
    async fn a_dropped_request_leaves_its_permit_with_the_running_hash() {
        let gate = HashGate::new(1, Duration::from_millis(200), Duration::ZERO);
        let ran = Arc::new(AtomicUsize::new(0));
        let (release, hold) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        let request = {
            let (gate, ran) = (gate.clone(), ran.clone());
            tokio::spawn(async move {
                gate.run(who(1, None), move || {
                    started_tx.send(()).expect("sent");
                    hold.recv().expect("released");
                    ran.fetch_add(1, Ordering::SeqCst);
                })
                .await
            })
        };
        wait_started(started).await;
        // The request goes away (a reset connection): the hash keeps its permit.
        request.abort();
        let _ = request.await;
        assert_eq!(
            gate.available(),
            0,
            "the running hash still holds the permit"
        );
        let refused = gate.run(who(2, None), || ()).await.expect_err("full");
        assert!(is_429(&refused));
        release.send(()).expect("released");
        for _ in 0..100 {
            if gate.available() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(gate.available(), 1);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }
}
