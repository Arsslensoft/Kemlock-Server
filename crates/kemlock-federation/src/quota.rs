//! What one origin server may write to this one: a rate and a size (docs/federation.md,
//! "Per-origin quotas").
//!
//! A replica in a vault's set can sign as many change records as it likes. Without a bound, one
//! malicious replica fills the disk of every other server of the vault. The bound is counted per
//! origin, over a fixed window of an hour, in memory: it limits a flood, and a restart gives a
//! malicious origin one more window, which doesn't change what it can do.
//!
//! A record past a bound is refused like any other refusal: left out, the rest of the page is
//! applied, and the comparison that runs next fetches it again, when the window has passed or the
//! bound was raised.

use kemlock_domain::ServerId;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// The window the rate is counted over, in seconds.
pub const WINDOW_SECS: u64 = 3600;
/// The most origins the meter remembers; one with the oldest window is forgotten past it.
const MAX_ORIGINS: usize = 4096;

/// The bounds on one origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Records taken from one origin in a window.
    pub records_per_window: u64,
    /// Bytes of records taken from one origin in a window.
    pub bytes_per_window: u64,
    /// The size of one signed record.
    pub max_record_bytes: usize,
}

impl Default for Quota {
    /// Room for the honest catch-up of a large vault, and no more: 50,000 records and 1 GiB an
    /// hour per origin, and 4 MiB for one record (an item's ciphertext is at most 1 MiB by default).
    fn default() -> Quota {
        Quota {
            records_per_window: 50_000,
            bytes_per_window: 1 << 30,
            max_record_bytes: 4 * 1024 * 1024,
        }
    }
}

/// What the meter says of one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    /// The record is larger than `max_record_bytes`.
    TooLarge,
    /// The origin has used its records or bytes for this window.
    OverRate,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    start: u64,
    records: u64,
    bytes: u64,
}

/// The counts of every origin.
#[derive(Debug, Default)]
pub struct Meter {
    windows: Mutex<HashMap<ServerId, Window>>,
}

impl Meter {
    /// Counts a record of `bytes` from `origin` at `now` (Unix seconds) if the quota allows it. A
    /// refused record is not counted.
    pub fn admit(&self, quota: &Quota, origin: ServerId, bytes: usize, now: u64) -> Admission {
        if bytes > quota.max_record_bytes {
            return Admission::TooLarge;
        }
        let bytes = bytes as u64;
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= MAX_ORIGINS && !windows.contains_key(&origin) {
            // Origins are paired servers, so this is far past any federation; make room anyway.
            if let Some(oldest) = windows.iter().min_by_key(|(_, w)| w.start).map(|(k, _)| *k) {
                windows.remove(&oldest);
            }
        }
        let window = windows.entry(origin).or_insert(Window {
            start: now,
            records: 0,
            bytes: 0,
        });
        if now >= window.start.saturating_add(WINDOW_SECS) {
            *window = Window {
                start: now,
                records: 0,
                bytes: 0,
            };
        }
        if window.records >= quota.records_per_window
            || window.bytes.saturating_add(bytes) > quota.bytes_per_window
        {
            return Admission::OverRate;
        }
        window.records += 1;
        window.bytes += bytes;
        Admission::Admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Quota {
        Quota {
            records_per_window: 3,
            bytes_per_window: 100,
            max_record_bytes: 60,
        }
    }

    #[test]
    fn records_are_counted_per_origin_and_per_window() {
        let meter = Meter::default();
        let (a, b) = (ServerId::random(), ServerId::random());
        for _ in 0..3 {
            assert_eq!(meter.admit(&small(), a, 10, 1_000), Admission::Admitted);
        }
        assert_eq!(meter.admit(&small(), a, 10, 1_001), Admission::OverRate);
        // Another origin has its own count.
        assert_eq!(meter.admit(&small(), b, 10, 1_001), Admission::Admitted);
        // The window passes.
        assert_eq!(
            meter.admit(&small(), a, 10, 1_000 + WINDOW_SECS),
            Admission::Admitted
        );
    }

    #[test]
    fn bytes_and_the_size_of_one_record_are_bounded() {
        let meter = Meter::default();
        let a = ServerId::random();
        assert_eq!(meter.admit(&small(), a, 61, 5), Admission::TooLarge);
        assert_eq!(meter.admit(&small(), a, 60, 5), Admission::Admitted);
        // 40 more would be 100: allowed. One more byte is over.
        assert_eq!(meter.admit(&small(), a, 40, 5), Admission::Admitted);
        assert_eq!(meter.admit(&small(), a, 1, 5), Admission::OverRate);
    }

    #[test]
    fn a_refused_record_costs_nothing() {
        let meter = Meter::default();
        let a = ServerId::random();
        assert_eq!(meter.admit(&small(), a, 99, 5), Admission::TooLarge);
        for _ in 0..3 {
            assert_eq!(meter.admit(&small(), a, 10, 5), Admission::Admitted);
        }
    }

    #[test]
    fn the_defaults_leave_room_for_a_large_vault() {
        let q = Quota::default();
        assert!(q.records_per_window >= 50_000);
        assert!(q.max_record_bytes >= 2 * 1024 * 1024);
    }
}
