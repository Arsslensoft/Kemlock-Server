//! A bounded set of values seen recently, for replay checks: DPoP proof ids and the OPAQUE login
//! states that were already used.
//!
//! Values are kept for a fixed time in time buckets, oldest first, so expiring is dropping whole
//! buckets from the front, with no scan of the set and no work proportional to its size. Values
//! are stored as 16-byte hashes, so what a client sends costs the same however long it is. The
//! set never holds more than its cap: when full it refuses new values instead of growing or
//! forgetting, because a replay check that forgets can be replayed past.

use kemlock_crypto::hash;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};

/// The time one bucket spans. A value lives until its bucket is older than this plus the TTL, so
/// it is kept for at least the TTL and at most this much more.
const BUCKET_SECS: i64 = 30;

type Key = [u8; 16];

fn digest(value: &[u8]) -> Key {
    let full = hash::sha256(value);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// The set is at its cap and can't take another value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

#[derive(Debug, Default)]
struct State {
    /// `(start of the bucket, its values)`, oldest first.
    buckets: VecDeque<(i64, HashSet<Key>)>,
    len: usize,
}

/// Values seen in the last `ttl_secs`, at most `cap` of them.
#[derive(Debug)]
pub struct TimedSet {
    ttl_secs: i64,
    cap: usize,
    state: Mutex<State>,
}

impl TimedSet {
    pub fn new(ttl_secs: i64, cap: usize) -> Self {
        TimedSet {
            ttl_secs,
            cap,
            state: Mutex::new(State::default()),
        }
    }

    /// Remembers `value` as seen at `now` (Unix seconds). `Ok(true)` when it is new, `Ok(false)`
    /// when it was seen within the TTL (a replay; nothing changes), `Err(Full)` when it is new
    /// but the set is at its cap (it is not remembered).
    pub fn insert(&self, value: &[u8], now: i64) -> Result<bool, Full> {
        let key = digest(value);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.expire(now, self.ttl_secs);
        if state.buckets.iter().any(|(_, set)| set.contains(&key)) {
            return Ok(false);
        }
        if state.len >= self.cap {
            return Err(Full);
        }
        let start = now.div_euclid(BUCKET_SECS) * BUCKET_SECS;
        match state.buckets.back_mut() {
            // The newest bucket takes values stamped in the past too, if the clock stepped back.
            Some((newest, set)) if start <= *newest => {
                set.insert(key);
            }
            _ => state.buckets.push_back((start, HashSet::from([key]))),
        }
        state.len += 1;
        Ok(true)
    }

    /// How many values are remembered (some may be past their TTL until the next insert).
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl State {
    fn expire(&mut self, now: i64, ttl_secs: i64) {
        while let Some((start, set)) = self.buckets.front() {
            if start + BUCKET_SECS + ttl_secs > now {
                break;
            }
            self.len -= set.len();
            self.buckets.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_value_is_new_once_and_a_replay_after_that() {
        let set = TimedSet::new(300, 100);
        assert_eq!(set.insert(b"a", NOW), Ok(true));
        assert_eq!(set.insert(b"a", NOW), Ok(false));
        assert_eq!(set.insert(b"a", NOW + 299), Ok(false));
        assert_eq!(set.insert(b"b", NOW), Ok(true));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_value_is_kept_for_at_least_the_ttl_and_then_forgotten() {
        let set = TimedSet::new(300, 100);
        // The worst case for the bucket: a value stamped at the very end of its bucket.
        let late = NOW + BUCKET_SECS - 1;
        assert_eq!(set.insert(b"a", late), Ok(true));
        assert_eq!(
            set.insert(b"a", late + 300),
            Ok(false),
            "still inside the TTL"
        );
        // Past the TTL and its bucket it may be used again.
        assert_eq!(set.insert(b"a", NOW + BUCKET_SECS + 300), Ok(true));
        assert_eq!(set.len(), 1, "the old bucket went with it");
    }

    #[test]
    fn the_cap_is_hard_and_old_values_free_room() {
        let set = TimedSet::new(300, 3);
        for n in 0..3 {
            assert_eq!(set.insert(format!("v{n}").as_bytes(), NOW), Ok(true));
        }
        assert_eq!(set.insert(b"extra", NOW), Err(Full));
        // A replay is still recognised at the cap, not mistaken for something to refuse.
        assert_eq!(set.insert(b"v1", NOW + 1), Ok(false));
        assert_eq!(set.len(), 3, "never above the cap");
        // Time makes room again.
        assert_eq!(set.insert(b"extra", NOW + 400), Ok(true));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_flood_of_distinct_values_never_grows_the_set_past_its_cap() {
        let set = TimedSet::new(300, 1_000);
        let mut refused = 0;
        for n in 0..5_000 {
            if set.insert(format!("flood-{n}").as_bytes(), NOW + n / 100) == Err(Full) {
                refused += 1;
            }
        }
        assert!(set.len() <= 1_000, "{} values", set.len());
        assert!(refused >= 4_000 - 100, "{refused} refused");
    }

    #[test]
    fn long_values_cost_what_short_ones_do() {
        let set = TimedSet::new(300, 10);
        let long = vec![b'x'; 1_000_000];
        assert_eq!(set.insert(&long, NOW), Ok(true));
        assert_eq!(set.insert(&long, NOW), Ok(false));
    }

    #[test]
    fn a_clock_that_steps_back_cannot_break_the_order() {
        let set = TimedSet::new(300, 100);
        assert_eq!(set.insert(b"a", NOW + 1_000), Ok(true));
        assert_eq!(set.insert(b"b", NOW), Ok(true));
        assert_eq!(set.len(), 2);
        assert_eq!(set.insert(b"b", NOW + 1_000), Ok(false));
        // Everything is forgotten once it is all past the TTL.
        assert_eq!(set.insert(b"c", NOW + 5_000), Ok(true));
        assert_eq!(set.len(), 1);
    }
}
