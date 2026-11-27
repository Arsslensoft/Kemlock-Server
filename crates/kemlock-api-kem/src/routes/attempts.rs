//! Counting the attempts that guess a secret: a second-step code, a security key's answer.
//!
//! An attempt is reserved *before* the answer is looked at, in one atomic step in the store, and
//! only a right answer gives it back (by clearing the account's count). Reading the count first and
//! counting the failure afterwards let every request that arrived before the first failure was
//! counted through, so a burst of parallel guesses got past the limit. The count is the store's, so
//! it holds across restarts and between replicas.

use crate::problem::{Problem, rate_limited};
use crate::ratelimit::ip_key_64;
use crate::state::{Api, Crypto, Store};
use kemlock_app::AppError;
use kemlock_app::ports::TokenSigner;
use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
use kemlock_domain::UserId;

/// Reserves one second-step attempt for `user` under the limit the console sets (5 in 15 minutes
/// by default, then doubling waits, whichever challenge or address the attempt comes from). A 429
/// when the account waits; nothing is counted then.
pub async fn reserve_second_step<S, P, K>(
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
pub async fn forget_second_step<S, P, K>(api: &Api<S, P, K>, user: UserId)
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

/// A password attempt in progress: the counts it is under.
#[derive(Debug)]
pub(crate) struct PasswordAttempt {
    /// The account as seen from one source: `scope:account|address`. The hard limit.
    source: String,
    /// The account from every source: `scope:account`. Slows it, and caps it far higher.
    account: String,
    /// Whether the soft cap counted this attempt. It doesn't while the account is over the cap:
    /// the attempt is held back instead, and so has nothing to give back.
    counted: bool,
}

/// Starts a password attempt on `credential` (the account's sign-in name as `credential_id`
/// makes it) from `ip`, under `scope` (`acct` for the account's password, `bwhash` for the
/// Bitwarden master password hash).
///
/// The hard limit (10 wrong in 15 minutes by default, then doubling waits) is kept per account
/// and source, and the attempt is reserved before the password is looked at, so parallel guesses
/// can't all pass it. The account's name comes from the request, and anyone can send wrong
/// passwords for any name, so a limit on the name alone would let anyone lock the real owner out;
/// per source, each stranger can only lock themselves out. What every source adds up to slows
/// the account: once it has seen many wrong passwords, every request for it, right or wrong, is
/// held back a few seconds, which a right password rides out and a distributed guesser pays for
/// on every guess (OPAQUE already makes each guess cost a key stretch on the client). Past 100
/// wrong passwords in an hour from all sources together the hold-back is the same few seconds
/// and never a refusal, so many addresses can't keep the owner out; a far higher backstop (600 an
/// hour, then doubling waits) refuses, so guesses spread over many addresses stay bounded. Both
/// are in this replica's memory.
///
/// Whoever calls this must end the attempt with [`end_password_attempt`], or give it back with
/// [`abandon_password_attempt`] when the password is never looked at.
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
    let source = format!("{account}|{}", ip_key_64(ip));
    api.limits
        .account
        .reserve(&source, now)
        .map_err(rate_limited)?;
    // However many addresses the guesses come from, an account takes only so many.
    if let Err(wait) = api.limits.account_cap_hard.reserve(&account, now) {
        api.limits.account.refund(&source, now);
        return Err(rate_limited(wait));
    }
    let mut hold = 0;
    let counted = match api.limits.account_cap.reserve(&account, now) {
        Ok(()) => true,
        Err(wait) => {
            hold = wait.min(MAX_SLOWDOWN_SECS);
            false
        }
    };
    if let Err(wait) = api.limits.account_slow.blocked(&account, now) {
        hold = hold.max(wait.min(MAX_SLOWDOWN_SECS));
    }
    if hold > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(hold)).await;
    }
    Ok(PasswordAttempt {
        source,
        account,
        counted,
    })
}

/// Gives back everything [`begin_password_attempt`] counted, for a request that ended before the
/// password was looked at (a body that doesn't parse, a login state already used): it guessed
/// nothing, so it must not take the account's tries.
pub(crate) fn abandon_password_attempt<S, P, K>(api: &Api<S, P, K>, attempt: &PasswordAttempt)
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let now = api.now();
    api.limits.account.refund(&attempt.source, now);
    api.limits.account_cap_hard.refund(&attempt.account, now);
    if attempt.counted {
        api.limits.account_cap.refund(&attempt.account, now);
    }
}

/// Ends a password attempt: a right password clears the source's count and the account's
/// slowdown and is given back to the account's caps; a wrong one stays counted against its source
/// (it was reserved) and the caps, and adds to the account's slowdown.
pub(crate) fn end_password_attempt<S, P, K, T>(
    api: &Api<S, P, K>,
    attempt: &PasswordAttempt,
    finished: &Result<T, AppError>,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let now = api.now();
    match finished {
        Ok(_) => {
            api.limits.account.clear(&attempt.source);
            api.limits.account_slow.clear(&attempt.account);
            give_back_caps(api, attempt, now);
        }
        Err(AppError::Unauthorized) => api.limits.account_slow.fail(&attempt.account, now),
        // Not a wrong password: it doesn't add up toward the account's caps.
        Err(_) => give_back_caps(api, attempt, now),
    }
}

fn give_back_caps<S, P, K>(api: &Api<S, P, K>, attempt: &PasswordAttempt, now: i64)
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    api.limits.account_cap_hard.refund(&attempt.account, now);
    if attempt.counted {
        api.limits.account_cap.refund(&attempt.account, now);
    }
}
