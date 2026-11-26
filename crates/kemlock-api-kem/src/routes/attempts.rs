//! Counting the attempts that guess a secret: a second-step code, a security key's answer.
//!
//! An attempt is reserved *before* the answer is looked at, in one atomic step in the store, and
//! only a right answer gives it back (by clearing the account's count). Reading the count first and
//! counting the failure afterwards let every request that arrived before the first failure was
//! counted through, so a burst of parallel guesses got past the limit. The count is the store's, so
//! it holds across restarts and between replicas.

use crate::problem::{Problem, rate_limited};
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use kemlock_app::AppError;
use kemlock_app::ports::TokenSigner;
use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
use kemlock_domain::UserId;

/// Reserves one second-step attempt for `user` under the limit the console sets (5 in 15 minutes
/// by default, then doubling waits, whichever challenge or address the attempt comes from). A 429
/// when the account waits; nothing is counted then.
pub(crate) async fn reserve_second_step<S, P, K>(
    api: &Api<S, P, K>,
    user: UserId,
    now: i64,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let limit = &api.limits.second_step;
    match SecondStepGuard::reserve_second_step(
        &api.store,
        user,
        now,
        limit.limit(),
        limit.window_secs(),
    )
    .await
    .map_err(AppError::from)?
    {
        Reservation::Granted => Ok(()),
        Reservation::Wait(wait) => Err(rate_limited(wait)),
    }
}

/// Gives the account's count back after a right answer. Any other end leaves the reservation
/// counted as the failure it was, whatever the error: only a right answer earns it back.
pub(crate) async fn settle_second_step<S, P, K, T>(
    api: &Api<S, P, K>,
    user: UserId,
    finished: &Result<T, AppError>,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    if finished.is_ok() {
        forget_second_step(api, user).await;
    }
}

/// Clears the account's count; a failure is logged, not returned, as the answer it follows was
/// right.
pub(crate) async fn forget_second_step<S, P, K>(api: &Api<S, P, K>, user: UserId)
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    if let Err(error) = SecondStepGuard::clear_second_step(&api.store, user).await {
        tracing::warn!(%error, "couldn't clear an account's second-step attempts");
    }
}

/// The longest a request is held back because its account has seen many wrong passwords, in
/// seconds. The slowdown never refuses anything.
const MAX_SLOWDOWN_SECS: u64 = 3;

/// A password attempt in progress: the two counts it is under.
#[derive(Debug)]
pub(crate) struct PasswordAttempt {
    /// The account as seen from one source: `scope:account|address`. The hard limit.
    source: String,
    /// The account from every source: `scope:account`. Only slows.
    account: String,
}

/// Starts a password attempt on `credential` (the account's sign-in name as `credential_id`
/// makes it) from `ip`, under `scope` (`acct` for the account's password, `bwhash` for the
/// Bitwarden master password hash).
///
/// The hard limit (10 wrong in 15 minutes by default, then doubling waits) is kept per account
/// and source, and the attempt is reserved before the password is looked at, so parallel guesses
/// can't all pass it. The account's name comes from the request, and anyone can send wrong
/// passwords for any name, so a limit on the name alone would let anyone lock the real owner out;
/// per source, each stranger can only lock themselves out. What every source adds up to only
/// slows: once an account has seen many wrong passwords, every request for it, right or wrong,
/// is held back a few seconds, which a right password rides out and a distributed guesser pays
/// for on every guess (OPAQUE already makes each guess cost a key stretch on the client).
pub(crate) async fn begin_password_attempt<S, P, K>(
    api: &Api<S, P, K>,
    scope: &str,
    credential: &str,
    ip: std::net::IpAddr,
) -> Result<PasswordAttempt, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let now = api.now();
    let account = format!("{scope}:{credential}");
    let source = format!("{account}|{}", ip_key(ip));
    api.limits
        .account
        .reserve(&source, now)
        .map_err(rate_limited)?;
    if let Err(wait) = api.limits.account_slow.blocked(&account, now) {
        tokio::time::sleep(std::time::Duration::from_secs(wait.min(MAX_SLOWDOWN_SECS))).await;
    }
    Ok(PasswordAttempt { source, account })
}

/// Ends a password attempt: a right password clears both counts; a wrong one stays counted
/// against its source (it was reserved) and adds to the account's slowdown.
pub(crate) fn end_password_attempt<S, P, K, T>(
    api: &Api<S, P, K>,
    attempt: &PasswordAttempt,
    finished: &Result<T, AppError>,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    match finished {
        Ok(_) => {
            api.limits.account.clear(&attempt.source);
            api.limits.account_slow.clear(&attempt.account);
        }
        Err(AppError::Unauthorized) => api.limits.account_slow.fail(&attempt.account, api.now()),
        Err(_) => {}
    }
}
