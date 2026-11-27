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
    windows: Mutex<HashMap<(ServerId, ServerId), Window>>,
}

impl Meter {
    /// Counts a record of `bytes` that `origin` made and `peer` sent at `now` (Unix seconds) if the
    /// quota allows it. The count is per pair: what one peer relays of an origin doesn't use up what
    /// another does, so a peer that sends garbage can't keep the origin's records from the rest.
    /// A refused record is not counted.
    pub fn admit(
        &self,
        quota: &Quota,
        peer: ServerId,
        origin: ServerId,
        bytes: usize,
        now: u64,
    ) -> Admission {
        let key = (peer, origin);
        if bytes > quota.max_record_bytes {
            return Admission::TooLarge;
        }
        let bytes = bytes as u64;
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= MAX_ORIGINS && !windows.contains_key(&key) {
            // Origins are paired servers, so this is far past any federation; make room anyway.
            if let Some(oldest) = windows.iter().min_by_key(|(_, w)| w.start).map(|(k, _)| *k) {
                windows.remove(&oldest);
            }
        }
        let window = windows.entry(key).or_insert(Window {
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

/// What a peer may ask this server to read or scan, over a window of an hour, in memory: a request
/// that costs the server much more than it costs the peer (a chunk read from offset 0 through a
/// large file, a scan of every item of a vault) is counted by what it costs, so a paired peer can't
/// use the disk and the database of this server for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkLimits {
    /// Bytes of blob storage one peer may make this server read in a window. A chunk at offset N
    /// reads N plus its length from the store (storage has no ranged read), so a file fetched in
    /// 2 MiB chunks costs about its size squared over 4 MiB.
    pub blob_bytes_per_window: u64,
    /// Scans of one vault (a summary or a list of leaves) one peer may ask for in a window.
    pub scans_per_window: u32,
}

impl Default for WorkLimits {
    /// Room for the honest hourly comparison and a few large files, and not for a loop: 128 GiB of
    /// reads (a 512 MiB file fetched whole costs about 64 GiB) and 30 scans of one vault.
    fn default() -> WorkLimits {
        WorkLimits {
            blob_bytes_per_window: 128 << 30,
            scans_per_window: 30,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Work {
    start: u64,
    blob_bytes: u64,
    scans: u32,
}

/// The work each peer asked for, by peer and (for scans) vault.
#[derive(Debug, Default)]
pub struct WorkMeter {
    blobs: Mutex<HashMap<ServerId, Work>>,
    scans: Mutex<HashMap<(ServerId, kemlock_domain::Owner), Work>>,
}

impl WorkMeter {
    fn fresh(start: u64) -> Work {
        Work {
            start,
            blob_bytes: 0,
            scans: 0,
        }
    }

    /// Counts a read that costs `bytes`; false when the peer has used its window.
    pub fn allow_blob_read(
        &self,
        limits: &WorkLimits,
        peer: ServerId,
        bytes: u64,
        now: u64,
    ) -> bool {
        let mut blobs = self.blobs.lock().unwrap_or_else(PoisonError::into_inner);
        if blobs.len() >= MAX_ORIGINS && !blobs.contains_key(&peer) {
            blobs.retain(|_, w| now < w.start.saturating_add(WINDOW_SECS));
        }
        let work = blobs.entry(peer).or_insert_with(|| WorkMeter::fresh(now));
        if now >= work.start.saturating_add(WINDOW_SECS) {
            *work = WorkMeter::fresh(now);
        }
        if work.blob_bytes.saturating_add(bytes) > limits.blob_bytes_per_window {
            return false;
        }
        work.blob_bytes += bytes;
        true
    }

    /// Counts one scan of `vault`; false when the peer has used its window for it.
    pub fn allow_scan(
        &self,
        limits: &WorkLimits,
        peer: ServerId,
        vault: kemlock_domain::Owner,
        now: u64,
    ) -> bool {
        let mut scans = self.scans.lock().unwrap_or_else(PoisonError::into_inner);
        if scans.len() >= MAX_ORIGINS && !scans.contains_key(&(peer, vault)) {
            scans.retain(|_, w| now < w.start.saturating_add(WINDOW_SECS));
        }
        let work = scans
            .entry((peer, vault))
            .or_insert_with(|| WorkMeter::fresh(now));
        if now >= work.start.saturating_add(WINDOW_SECS) {
            *work = WorkMeter::fresh(now);
        }
        if work.scans >= limits.scans_per_window {
            return false;
        }
        work.scans += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server that sends, in the tests that don't care which.
    const P: ServerId = ServerId(uuid::Uuid::from_u128(1));

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
            assert_eq!(meter.admit(&small(), P, a, 10, 1_000), Admission::Admitted);
        }
        assert_eq!(meter.admit(&small(), P, a, 10, 1_001), Admission::OverRate);
        // Another origin has its own count.
        assert_eq!(meter.admit(&small(), P, b, 10, 1_001), Admission::Admitted);
        // The window passes.
        assert_eq!(
            meter.admit(&small(), P, a, 10, 1_000 + WINDOW_SECS),
            Admission::Admitted
        );
    }

    #[test]
    fn what_one_peer_sends_does_not_use_up_what_another_does() {
        let meter = Meter::default();
        let origin = ServerId::random();
        let (noisy, quiet) = (ServerId::random(), ServerId::random());
        for _ in 0..3 {
            assert_eq!(
                meter.admit(&small(), noisy, origin, 10, 5),
                Admission::Admitted
            );
        }
        assert_eq!(
            meter.admit(&small(), noisy, origin, 10, 5),
            Admission::OverRate
        );
        assert_eq!(
            meter.admit(&small(), quiet, origin, 10, 5),
            Admission::Admitted
        );
    }

    #[test]
    fn bytes_and_the_size_of_one_record_are_bounded() {
        let meter = Meter::default();
        let a = ServerId::random();
        assert_eq!(meter.admit(&small(), P, a, 61, 5), Admission::TooLarge);
        assert_eq!(meter.admit(&small(), P, a, 60, 5), Admission::Admitted);
        // 40 more would be 100: allowed. One more byte is over.
        assert_eq!(meter.admit(&small(), P, a, 40, 5), Admission::Admitted);
        assert_eq!(meter.admit(&small(), P, a, 1, 5), Admission::OverRate);
    }

    #[test]
    fn a_refused_record_costs_nothing() {
        let meter = Meter::default();
        let a = ServerId::random();
        assert_eq!(meter.admit(&small(), P, a, 99, 5), Admission::TooLarge);
        for _ in 0..3 {
            assert_eq!(meter.admit(&small(), P, a, 10, 5), Admission::Admitted);
        }
    }

    #[test]
    fn a_peers_reads_and_scans_are_counted_for_a_window() {
        let meter = WorkMeter::default();
        let limits = WorkLimits {
            blob_bytes_per_window: 100,
            scans_per_window: 2,
        };
        let (a, b) = (ServerId::random(), ServerId::random());
        let vault = kemlock_domain::Owner::User(kemlock_domain::UserId::random());
        assert!(meter.allow_blob_read(&limits, a, 60, 10));
        assert!(!meter.allow_blob_read(&limits, a, 41, 11));
        assert!(meter.allow_blob_read(&limits, a, 40, 11));
        // Another peer has its own, and the window passes.
        assert!(meter.allow_blob_read(&limits, b, 100, 11));
        assert!(meter.allow_blob_read(&limits, a, 100, 10 + WINDOW_SECS));

        assert!(meter.allow_scan(&limits, a, vault, 10));
        assert!(meter.allow_scan(&limits, a, vault, 11));
        assert!(!meter.allow_scan(&limits, a, vault, 12));
        assert!(meter.allow_scan(&limits, b, vault, 12));
        assert!(meter.allow_scan(&limits, a, vault, 10 + WINDOW_SECS));
    }

    #[test]
    fn the_defaults_leave_room_for_a_large_vault() {
        let q = Quota::default();
        assert!(q.records_per_window >= 50_000);
        assert!(q.max_record_bytes >= 2 * 1024 * 1024);
    }
}
