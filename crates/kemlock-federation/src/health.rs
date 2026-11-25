//! Whether a paired peer answers: the probes, and the status they derive.
//!
//! The replication job visits a peer when there is something to do, which may be many minutes
//! apart. A probe is the cheap call between visits: the peer's public descriptor, fetched over the
//! federation transport and checked against the key pinned at pairing, so an answer from the wrong
//! server is a failure, not a sign of life (`Connector::probe`). Each probe has a timeout; probes
//! of a failing peer back off (the interval doubles to a ceiling) and every delay carries jitter,
//! so two servers that restarted together don't probe in step.
//!
//! What a probe finds is kept in memory per peer ([`PeerHealth`]): when it last answered, how long
//! that took, why it last failed. The status is derived from it ([`PeerHealth::status`]):
//!
//! | Status | When |
//! | --- | --- |
//! | `unknown` | nothing has been probed or visited yet |
//! | `online` | the last probe answered within [`HealthConfig::slow_ms`] |
//! | `degraded` | the last probe answered slowly, or fewer than [`HealthConfig::offline_after`] probes in a row failed |
//! | `offline` | at least [`HealthConfig::offline_after`] probes in a row failed |
//! | `key-mismatch` | the peer answers with an identity key that isn't the pinned one: not an outage, and not a reason to drop what waits for it |
//!
//! A session that opened (a visit) counts as an answer, and one that failed to open as a failed
//! probe, so the status stays right where the probes are turned off. A status nobody has refreshed
//! for [`HealthConfig::stale_after_secs`] is `unknown` again.

use std::time::Duration;

/// How often each peer is probed, by default.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;
/// How long one probe may take, by default.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// The most a failing peer's probe interval backs off to, by default.
pub const DEFAULT_BACKOFF_CEILING_SECS: u64 = 10 * 60;
/// An answer slower than this is `degraded`, by default.
pub const DEFAULT_SLOW_MS: u64 = 3_000;
/// Failed probes in a row that make a peer `offline`, by default.
pub const DEFAULT_OFFLINE_AFTER: u32 = 3;
/// How far a delay is spread, by default: up to this percent of it, either way.
pub const DEFAULT_JITTER_PERCENT: u64 = 20;

/// How the probes run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthConfig {
    /// Seconds between two probes of a healthy peer; 0 turns the probes off.
    pub interval_secs: u64,
    /// Seconds one probe may take before it is a failure.
    pub timeout_secs: u64,
    /// Percent of a delay that is added or taken off at random, 0 to 50.
    pub jitter_percent: u64,
    /// The longest a failing peer waits between probes.
    pub backoff_ceiling_secs: u64,
    /// A peer that answers slower than this many milliseconds is `degraded`.
    pub slow_ms: u64,
    /// How many failures in a row make a peer `offline`.
    pub offline_after: u32,
    /// A status older than this many seconds is `unknown` again.
    pub stale_after_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> HealthConfig {
        HealthConfig::every(DEFAULT_INTERVAL_SECS)
    }
}

impl HealthConfig {
    /// The defaults, probing every `interval_secs` (0: never).
    pub fn every(interval_secs: u64) -> HealthConfig {
        HealthConfig {
            interval_secs,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            jitter_percent: DEFAULT_JITTER_PERCENT,
            backoff_ceiling_secs: DEFAULT_BACKOFF_CEILING_SECS.max(interval_secs),
            slow_ms: DEFAULT_SLOW_MS,
            offline_after: DEFAULT_OFFLINE_AFTER,
            // Probes back off to the ceiling, and a visit is due every five minutes: a status
            // that went twice that long without either has lost its footing.
            stale_after_secs: 2 * DEFAULT_BACKOFF_CEILING_SECS.max(interval_secs),
        }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    /// Whether probes run at all.
    pub fn enabled(&self) -> bool {
        self.interval_secs > 0
    }
}

/// What this server can say of a peer's health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    Unknown,
    Online,
    Degraded,
    Offline,
    /// It answered with a key other than the pinned one.
    KeyMismatch,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Unknown => "unknown",
            HealthStatus::Online => "online",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Offline => "offline",
            HealthStatus::KeyMismatch => "key-mismatch",
        }
    }
}

impl From<HealthStatus> for kemlock_app::federation_view::PeerStatus {
    fn from(status: HealthStatus) -> Self {
        use kemlock_app::federation_view::PeerStatus;
        match status {
            HealthStatus::Unknown => PeerStatus::Unknown,
            HealthStatus::Online => PeerStatus::Online,
            HealthStatus::Degraded => PeerStatus::Degraded,
            HealthStatus::Offline => PeerStatus::Offline,
            HealthStatus::KeyMismatch => PeerStatus::KeyMismatch,
        }
    }
}

/// What the probes (and the visits) found of one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerHealth {
    /// Unix seconds of the last probe or visit, whether it answered or not.
    pub last_checked: Option<u64>,
    /// Unix seconds of the last answer.
    pub last_seen: Option<u64>,
    /// Why the last probe failed, until one answers.
    pub last_error: Option<String>,
    /// How long the last answer took, in milliseconds.
    pub latency_ms: Option<u64>,
    /// Failed probes in a row.
    pub consecutive_failures: u32,
    /// The last probe met an identity key that isn't the pinned one.
    pub key_mismatch: bool,
    /// Unix seconds since when the probes have been failing.
    pub down_since: Option<u64>,
    /// Unix seconds the next probe is due.
    pub next_probe_at: u64,
}

impl PeerHealth {
    /// The status at `now`.
    pub fn status(&self, now: u64, config: &HealthConfig) -> HealthStatus {
        let Some(checked) = self.last_checked else {
            return HealthStatus::Unknown;
        };
        if now > checked.saturating_add(config.stale_after_secs) {
            return HealthStatus::Unknown;
        }
        if self.key_mismatch {
            HealthStatus::KeyMismatch
        } else if self.consecutive_failures >= config.offline_after.max(1) {
            HealthStatus::Offline
        } else if self.consecutive_failures > 0
            || self.latency_ms.is_some_and(|ms| ms > config.slow_ms)
        {
            HealthStatus::Degraded
        } else {
            HealthStatus::Online
        }
    }

    /// The peer answered, `latency_ms` after it was asked (`None` when that wasn't timed).
    pub fn record_answer(&mut self, now: u64, latency_ms: Option<u64>) {
        self.last_checked = Some(now);
        self.last_seen = Some(now);
        self.last_error = None;
        self.key_mismatch = false;
        self.consecutive_failures = 0;
        self.down_since = None;
        if latency_ms.is_some() {
            self.latency_ms = latency_ms;
        }
    }

    /// The peer didn't answer.
    pub fn record_failure(&mut self, now: u64, error: String) {
        self.key_mismatch = false;
        self.last_checked = Some(now);
        self.last_error = Some(error);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.down_since.get_or_insert(now);
    }

    /// The peer answered, with a key that isn't the one pinned at pairing. It isn't down, so it
    /// doesn't count as a failure to answer, but it isn't trusted either.
    pub fn record_key_mismatch(&mut self, now: u64, error: String) {
        self.last_checked = Some(now);
        self.last_error = Some(error);
        self.key_mismatch = true;
    }

    /// Whether the next probe is due.
    pub fn due(&self, now: u64) -> bool {
        now >= self.next_probe_at
    }

    /// Sets when the next probe is due, `random` being any 64 random bits.
    pub fn schedule(&mut self, now: u64, config: &HealthConfig, random: u64) {
        self.next_probe_at = now.saturating_add(next_delay(config, self.consecutive_failures, random));
    }
}

/// Seconds until the next probe of a peer that has failed `failures` times in a row: the interval,
/// doubled for each failure after the first up to the ceiling, then spread by the jitter. Never
/// less than a second.
pub fn next_delay(config: &HealthConfig, failures: u32, random: u64) -> u64 {
    let base = if failures == 0 {
        config.interval_secs
    } else {
        let shift = failures.saturating_sub(1).min(16);
        config
            .interval_secs
            .saturating_mul(1u64 << shift)
            .min(config.backoff_ceiling_secs.max(config.interval_secs))
    };
    let spread = base.saturating_mul(config.jitter_percent.min(50)) / 100;
    let delay = if spread == 0 {
        base
    } else {
        // A point in [base - spread, base + spread].
        base - spread + random % (2 * spread + 1)
    };
    delay.max(1)
}

/// 64 random bits, for the jitter.
pub fn random_bits() -> u64 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn config() -> HealthConfig {
        HealthConfig::every(60)
    }

    #[test]
    fn nothing_is_known_until_the_first_probe() {
        let health = PeerHealth::default();
        assert_eq!(health.status(NOW, &config()), HealthStatus::Unknown);
        assert!(health.due(NOW), "a peer never probed is due at once");
    }

    #[test]
    fn an_answer_is_online_and_a_slow_one_degraded() {
        let mut health = PeerHealth::default();
        health.record_answer(NOW, Some(120));
        assert_eq!(health.status(NOW, &config()), HealthStatus::Online);
        assert_eq!((health.last_seen, health.latency_ms), (Some(NOW), Some(120)));
        health.record_answer(NOW + 60, Some(config().slow_ms + 1));
        assert_eq!(health.status(NOW + 60, &config()), HealthStatus::Degraded);
        // An answer that wasn't timed (a visit) keeps the last latency.
        health.record_answer(NOW + 120, None);
        assert_eq!(health.latency_ms, Some(config().slow_ms + 1));
    }

    #[test]
    fn failures_make_a_peer_degraded_then_offline_and_an_answer_brings_it_back() {
        let cfg = config();
        let mut health = PeerHealth::default();
        health.record_answer(NOW, Some(50));
        health.record_failure(NOW + 60, "timed out".to_owned());
        assert_eq!(health.status(NOW + 60, &cfg), HealthStatus::Degraded);
        health.record_failure(NOW + 120, "timed out".to_owned());
        assert_eq!(health.status(NOW + 120, &cfg), HealthStatus::Degraded);
        health.record_failure(NOW + 240, "refused".to_owned());
        assert_eq!(health.status(NOW + 240, &cfg), HealthStatus::Offline);
        assert_eq!(health.down_since, Some(NOW + 60));
        assert_eq!(health.last_error.as_deref(), Some("refused"));
        assert_eq!(health.last_seen, Some(NOW), "the last answer is kept");

        health.record_answer(NOW + 300, Some(80));
        assert_eq!(health.status(NOW + 300, &cfg), HealthStatus::Online);
        assert_eq!((health.down_since, health.last_error), (None, None));
    }

    #[test]
    fn a_status_nobody_refreshed_is_unknown_again() {
        let cfg = config();
        let mut health = PeerHealth::default();
        health.record_answer(NOW, Some(50));
        assert_eq!(
            health.status(NOW + cfg.stale_after_secs, &cfg),
            HealthStatus::Online
        );
        assert_eq!(
            health.status(NOW + cfg.stale_after_secs + 1, &cfg),
            HealthStatus::Unknown
        );
    }

    #[test]
    fn the_delay_doubles_to_the_ceiling_and_stays_within_its_jitter() {
        let mut cfg = config();
        cfg.jitter_percent = 0;
        assert_eq!(next_delay(&cfg, 0, 7), 60);
        assert_eq!(next_delay(&cfg, 1, 7), 60);
        assert_eq!(next_delay(&cfg, 2, 7), 120);
        assert_eq!(next_delay(&cfg, 3, 7), 240);
        assert_eq!(next_delay(&cfg, 5, 7), 600, "the ceiling");
        assert_eq!(next_delay(&cfg, 500, 7), 600);

        cfg.jitter_percent = 20;
        for random in [0, 1, 11, 12, 13, 1 << 40, u64::MAX] {
            let delay = next_delay(&cfg, 0, random);
            assert!((48..=72).contains(&delay), "{delay}");
        }
        assert_eq!(next_delay(&cfg, 0, 0), 48);
        assert_eq!(next_delay(&cfg, 0, 24), 72);
        // A jitter above half is held to half.
        cfg.jitter_percent = 400;
        assert!((30..=90).contains(&next_delay(&cfg, 0, u64::MAX)));
    }

    #[test]
    fn a_schedule_sets_the_next_probe_after_its_delay() {
        let mut cfg = config();
        cfg.jitter_percent = 0;
        let mut health = PeerHealth::default();
        health.record_failure(NOW, "x".to_owned());
        health.schedule(NOW, &cfg, 0);
        assert_eq!(health.next_probe_at, NOW + 60);
        assert!(!health.due(NOW + 59) && health.due(NOW + 60));
        health.record_failure(NOW + 60, "x".to_owned());
        health.schedule(NOW + 60, &cfg, 0);
        assert_eq!(health.next_probe_at, NOW + 60 + 120);
    }

    #[test]
    fn probes_can_be_turned_off() {
        assert!(HealthConfig::every(60).enabled());
        assert!(!HealthConfig::every(0).enabled());
        assert_eq!(HealthConfig::every(0).timeout(), Duration::from_secs(10));
    }

    #[test]
    fn a_key_that_is_not_the_pinned_one_is_its_own_status_not_offline() {
        let cfg = config();
        let mut health = PeerHealth::default();
        health.record_answer(NOW, Some(50));
        health.record_key_mismatch(NOW + 60, "the peer's identity key does not match".to_owned());
        assert_eq!(health.status(NOW + 60, &cfg), HealthStatus::KeyMismatch);
        assert_eq!(health.status(NOW + 60, &cfg).as_str(), "key-mismatch");
        // Repeated, it stays a mismatch and never turns offline.
        for n in 2..6 {
            health.record_key_mismatch(NOW + 60 * n, "again".to_owned());
        }
        assert_eq!(health.status(NOW + 300, &cfg), HealthStatus::KeyMismatch);
        // A peer that stops answering is then down, and a good answer clears it.
        health.record_failure(NOW + 360, "refused".to_owned());
        assert_eq!(health.status(NOW + 360, &cfg), HealthStatus::Degraded);
        health.record_key_mismatch(NOW + 420, "x".to_owned());
        health.record_answer(NOW + 480, Some(10));
        assert_eq!(health.status(NOW + 480, &cfg), HealthStatus::Online);
    }
}
