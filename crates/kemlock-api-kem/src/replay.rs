//! A bounded set of values seen recently, for replay checks: DPoP proof ids and the OPAQUE login
//! states that were already used.
//!
//! Values are kept for a fixed time in time buckets, oldest first, so expiring is dropping whole
//! buckets from the front, with no scan of the set and no work proportional to its size. Values
//! are stored as 16-byte hashes, so what a client sends costs the same however long it is. The
//! set never holds more than its cap: when full it refuses new values instead of growing or
//! forgetting, because a replay check that forgets can be replayed past.
//!
//! A value may be inserted on behalf of a *source* (a client address), with a cap per source, so
//! that a few sources can't take the whole set: see [`TimedSet::insert_from`].

use kemlock_crypto::hash;
use std::collections::{HashMap, HashSet, VecDeque};
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

#[derive(Debug)]
struct Bucket {
    /// The start of the bucket.
    start: i64,
    values: HashSet<Key>,
    /// The source of each value that came with one, so expiring the bucket gives the room back.
    sources: Vec<Key>,
}

#[derive(Debug, Default)]
struct State {
    /// Oldest first.
    buckets: VecDeque<Bucket>,
    len: usize,
    /// How many remembered values each source put in.
    by_source: HashMap<Key, usize>,
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
        self.insert_inner(None, value, now)
    }

    /// [`TimedSet::insert`] on behalf of `source`: the value is also refused (`Err(Full)`) when
    /// the source already has `source_cap` values in the set, so a few sources can't fill it.
    /// A replay is still recognised first.
    pub fn insert_from(
        &self,
        source: &[u8],
        source_cap: usize,
        value: &[u8],
        now: i64,
    ) -> Result<bool, Full> {
        self.insert_inner(Some((digest(source), source_cap)), value, now)
    }

    fn insert_inner(
        &self,
        source: Option<(Key, usize)>,
        value: &[u8],
        now: i64,
    ) -> Result<bool, Full> {
        let key = digest(value);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.expire(now, self.ttl_secs);
        if state.buckets.iter().any(|b| b.values.contains(&key)) {
            return Ok(false);
        }
        if state.len >= self.cap {
            return Err(Full);
        }
        if let Some((source, source_cap)) = source
            && state.by_source.get(&source).copied().unwrap_or(0) >= source_cap
        {
            return Err(Full);
        }
        let start = now.div_euclid(BUCKET_SECS) * BUCKET_SECS;
        // The newest bucket takes values stamped in the past too, if the clock stepped back.
        if !state.buckets.back().is_some_and(|b| start <= b.start) {
            state.buckets.push_back(Bucket {
                start,
                values: HashSet::new(),
                sources: Vec::new(),
            });
        }
        if let Some(bucket) = state.buckets.back_mut() {
            bucket.values.insert(key);
            if let Some((source, _)) = source {
                bucket.sources.push(source);
            }
        }
        if let Some((source, _)) = source {
            *state.by_source.entry(source).or_insert(0) += 1;
        }
        state.len += 1;
        Ok(true)
    }

    /// Whether `value` is remembered at `now`, without remembering it.
    pub fn contains(&self, value: &[u8], now: i64) -> bool {
        let key = digest(value);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.expire(now, self.ttl_secs);
        state.buckets.iter().any(|b| b.values.contains(&key))
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
        while let Some(front) = self.buckets.front() {
            if front.start + BUCKET_SECS + ttl_secs > now {
                break;
            }
            self.len -= front.values.len();
            for source in &front.sources {
                if let Some(count) = self.by_source.get_mut(source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.by_source.remove(source);
                    }
                }
            }
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

    #[test]
    fn one_source_cannot_take_more_than_its_share_and_time_gives_it_back() {
        let set = TimedSet::new(300, 100);
        for n in 0..3 {
            assert_eq!(
                set.insert_from(b"a", 3, format!("a{n}").as_bytes(), NOW),
                Ok(true)
            );
        }
        assert_eq!(set.insert_from(b"a", 3, b"a3", NOW), Err(Full));
        // Another source is not held back by it, and a replay is still told from a new value.
        assert_eq!(set.insert_from(b"b", 3, b"b0", NOW), Ok(true));
        assert_eq!(set.insert_from(b"a", 3, b"a0", NOW), Ok(false));
        assert_eq!(set.len(), 4);
        // Past the TTL the room is back.
        assert_eq!(set.insert_from(b"a", 3, b"a3", NOW + 400), Ok(true));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn contains_looks_without_remembering() {
        let set = TimedSet::new(300, 10);
        assert!(!set.contains(b"a", NOW));
        assert!(set.is_empty());
        assert_eq!(set.insert(b"a", NOW), Ok(true));
        assert!(set.contains(b"a", NOW + 1));
        assert!(!set.contains(b"a", NOW + 400));
    }
}
