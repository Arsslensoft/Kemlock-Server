//! The stored count of an account's second-step attempts, so guessing a code is limited the same
//! whichever replica a try lands on and whatever the server did since.
//!
//! An attempt is **reserved before the code is looked at**: the count moves and the answer comes
//! back in one atomic step, so a burst of parallel requests can't all pass before the first
//! failure is counted. A right code then clears the count; a wrong one leaves the reservation
//! standing as the failure. The count follows the in-memory limiter's rule: `limit` attempts a
//! window, and the attempt that reaches the limit starts a wait of 1 second, doubling with every
//! further attempt after a wait (at most an hour) while the window lasts. A quiet window earns
//! one level of forgiveness.

use crate::ports::StoreError;
use kemlock_domain::UserId;
use std::future::Future;

/// The longest wait, in seconds.
pub const MAX_DELAY_SECS: i64 = 3600;

/// What the store keeps for one account. All times are Unix seconds. `Default` is an account
/// that never made an attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attempts {
    /// When the current window began.
    pub window_start: i64,
    /// Attempts reserved in the window.
    pub count: i64,
    /// How many waits in a row were started; each level doubles the wait.
    pub level: i64,
    /// Attempts are refused until this time.
    pub blocked_until: i64,
}

/// The answer to a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The attempt may go on; it is counted.
    Granted,
    /// The account waits this many seconds; nothing was counted.
    Wait(u64),
}

impl Attempts {
    /// Reserves one attempt at `now` under a limit of `limit` attempts per `window_secs`: the
    /// state after it, and whether the attempt may go on.
    pub fn reserve(self, now: i64, limit: u32, window_secs: i64) -> (Attempts, Reservation) {
        let mut next = self;
        if now < next.blocked_until {
            let wait = u64::try_from(next.blocked_until - now).unwrap_or(1);
            return (next, Reservation::Wait(wait));
        }
        if now - next.window_start >= window_secs {
            // A window with no wait started in it earns one level of forgiveness.
            if next.blocked_until < next.window_start {
                next.level = next.level.saturating_sub(1);
            }
            next.window_start = now;
            next.count = 0;
        }
        next.count = next.count.saturating_add(1);
        if next.count >= i64::from(limit) {
            // This attempt goes on, and the next one waits.
            next.level = next.level.saturating_add(1);
            let delay = (1i64 << (next.level - 1).clamp(0, 20)).min(MAX_DELAY_SECS);
            next.blocked_until = now.saturating_add(delay);
        }
        (next, Reservation::Granted)
    }
}

/// Where the counts are kept: one row per account.
pub trait SecondStepGuard: Send + Sync {
    /// Reserves one attempt for the account, atomically ([`Attempts::reserve`] on the stored
    /// state). A store that can't settle the reservation under contention refuses it with a
    /// short wait, never grants it.
    fn reserve_second_step(
        &self,
        user: UserId,
        now: i64,
        limit: u32,
        window_secs: i64,
    ) -> impl Future<Output = Result<Reservation, StoreError>> + Send;

    /// Forgets the account's count, after a right code.
    fn clear_second_step(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reserves `n` attempts at `now`, returning the last answer.
    fn reserve_n(mut state: Attempts, n: u32, now: i64, limit: u32) -> (Attempts, Reservation) {
        let mut last = (state, Reservation::Granted);
        for _ in 0..n {
            last = state.reserve(now, limit, 900);
            state = last.0;
        }
        last
    }

    #[test]
    fn the_limit_th_attempt_goes_on_and_the_next_waits_one_second() {
        let (state, answer) = reserve_n(Attempts::default(), 5, 1000, 5);
        assert_eq!(answer, Reservation::Granted);
        let (state, answer) = state.reserve(1000, 5, 900);
        assert_eq!(answer, Reservation::Wait(1));
        assert_eq!(state.count, 5, "a refused attempt is not counted");
    }

    #[test]
    fn each_attempt_after_a_wait_doubles_the_next_wait() {
        let (state, _) = reserve_n(Attempts::default(), 5, 1000, 5);
        let (state, answer) = state.reserve(1001, 5, 900);
        assert_eq!(answer, Reservation::Granted, "one try once the wait is over");
        let (state, answer) = state.reserve(1001, 5, 900);
        assert_eq!(answer, Reservation::Wait(2));
        let (state, answer) = state.reserve(1003, 5, 900);
        assert_eq!(answer, Reservation::Granted);
        let (_, answer) = state.reserve(1003, 5, 900);
        assert_eq!(answer, Reservation::Wait(4));
    }

    #[test]
    fn the_wait_is_capped_at_an_hour() {
        let mut state = Attempts::default();
        let mut now = 0;
        // An odd number of steps ends on a granted attempt, which has just armed its wait.
        for _ in 0..79 {
            let (next, answer) = state.reserve(now, 1, 1_000_000);
            state = next;
            now += match answer {
                Reservation::Wait(wait) => i64::try_from(wait).expect("small"),
                Reservation::Granted => 0,
            };
        }
        assert_eq!(state.blocked_until - now, MAX_DELAY_SECS);
    }

    #[test]
    fn a_new_window_starts_the_count_again_and_a_quiet_one_forgives_a_level() {
        let (state, _) = reserve_n(Attempts::default(), 5, 0, 5);
        assert_eq!(state.level, 1);
        // A window later, the wait is long over and the count is new.
        let (state, answer) = state.reserve(901, 5, 900);
        assert_eq!(answer, Reservation::Granted);
        assert_eq!(state.count, 1);
        assert_eq!(state.level, 1, "the window had a wait in it: no forgiveness");
        // Another window with no wait in it forgives the level.
        let (state, _) = state.reserve(1802, 5, 900);
        assert_eq!(state.level, 0);
        assert_eq!(state.count, 1);
    }

    #[test]
    fn a_limit_of_one_waits_after_every_attempt() {
        let (state, answer) = Attempts::default().reserve(10, 1, 900);
        assert_eq!(answer, Reservation::Granted);
        assert_eq!(state.reserve(10, 1, 900).1, Reservation::Wait(1));
    }
}
