//! Counting the attempts that guess a secret: a second-step code, a security key's answer.
//!
//! An attempt is reserved *before* the answer is looked at, in one atomic step in the store, and
//! only a right answer gives it back (by clearing the account's count). Reading the count first and
//! counting the failure afterwards let every request that arrived before the first failure was
//! counted through, so a burst of parallel guesses got past the limit. The count is the store's, so
//! it holds across restarts and between replicas.

use crate::problem::{Problem, rate_limited};
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
