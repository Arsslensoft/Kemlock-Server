//! The limit on password attempts at one Send: the design's "Password-protected Send access, 10 a
//! minute, counted per Send". The `send_access` grant is public, so without it the password of a
//! Send could be guessed as fast as the server answers; the limit is on the Send, whoever asks.
//!
//! A fixed window per Send, kept in memory (a restart forgets it, which only lets a guesser have a
//! few more tries). The map is bounded: when it is full, windows that have run out are dropped,
//! and if none has, the oldest half.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use uuid::Uuid;

/// Attempts a Send takes in one window.
pub(crate) const ATTEMPTS_PER_WINDOW: u32 = 10;
/// The window, in seconds.
pub(crate) const WINDOW_SECS: i64 = 60;
/// The most Sends followed at once.
const MAX_SENDS: usize = 10_000;

#[derive(Debug, Default)]
pub(crate) struct SendAccessLimit {
    windows: Mutex<HashMap<Uuid, Window>>,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    started: i64,
    count: u32,
}

impl SendAccessLimit {
    /// Counts one attempt at `send` at `now` (Unix seconds). `Err(seconds)` is how long until the
    /// window turns over and attempts are taken again.
    pub(crate) fn attempt(&self, send: Uuid, now: i64) -> Result<(), u64> {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= MAX_SENDS && !windows.contains_key(&send) {
            windows.retain(|_, w| now - w.started < WINDOW_SECS);
            if windows.len() >= MAX_SENDS {
                let mut starts: Vec<i64> = windows.values().map(|w| w.started).collect();
                starts.sort_unstable();
                let cut = starts[starts.len() / 2];
                windows.retain(|_, w| w.started > cut);
            }
        }
        let window = windows.entry(send).or_insert(Window {
            started: now,
            count: 0,
        });
        if now - window.started >= WINDOW_SECS {
            *window = Window {
                started: now,
                count: 0,
            };
        }
        if window.count >= ATTEMPTS_PER_WINDOW {
            let wait = (window.started + WINDOW_SECS - now).max(1);
            return Err(u64::try_from(wait).unwrap_or(1));
        }
        window.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_takes_ten_attempts_a_minute_and_each_send_has_its_own() {
        let limit = SendAccessLimit::default();
        let (one, other) = (Uuid::from_u128(1), Uuid::from_u128(2));
        for _ in 0..ATTEMPTS_PER_WINDOW {
            assert_eq!(limit.attempt(one, 1_000), Ok(()));
        }
        assert_eq!(limit.attempt(one, 1_010), Err(50));
        assert_eq!(limit.attempt(other, 1_010), Ok(()));
        // The window turns over after a minute.
        assert_eq!(limit.attempt(one, 1_060), Ok(()));
    }

    #[test]
    fn the_map_stays_bounded() {
        let limit = SendAccessLimit::default();
        for n in 0..u128::try_from(MAX_SENDS * 2).expect("a count") {
            assert_eq!(limit.attempt(Uuid::from_u128(n), 5_000), Ok(()));
        }
        let held = limit.windows.lock().expect("the map").len();
        assert!(held <= MAX_SENDS, "{held}");
    }
}
