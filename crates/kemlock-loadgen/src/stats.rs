//! Latency summaries.

use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    pub(crate) count: usize,
    pub(crate) errors: u64,
    pub(crate) rate_limited: u64,
    pub(crate) p50_ms: f64,
    pub(crate) p95_ms: f64,
    pub(crate) p99_ms: f64,
    pub(crate) max_ms: f64,
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The nearest-rank percentile of a sorted, non-empty slice.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Summarises the successful samples, with the failures counted beside them.
pub(crate) fn summarize(mut samples: Vec<Duration>, errors: u64, rate_limited: u64) -> Summary {
    samples.sort();
    if samples.is_empty() {
        return Summary {
            count: 0,
            errors,
            rate_limited,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
        };
    }
    Summary {
        count: samples.len(),
        errors,
        rate_limited,
        p50_ms: millis(percentile(&samples, 50.0)),
        p95_ms: millis(percentile(&samples, 95.0)),
        p99_ms: millis(percentile(&samples, 99.0)),
        max_ms: millis(samples[samples.len() - 1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let samples: Vec<Duration> = (1..=100).map(ms).collect();
        let s = summarize(samples, 0, 0);
        assert_eq!(s.count, 100);
        assert!((s.p50_ms - 50.0).abs() < 1e-9);
        assert!((s.p95_ms - 95.0).abs() < 1e-9);
        assert!((s.p99_ms - 99.0).abs() < 1e-9);
        assert!((s.max_ms - 100.0).abs() < 1e-9);
    }

    #[test]
    fn one_sample_is_every_percentile() {
        let s = summarize(vec![ms(7)], 0, 0);
        assert!((s.p50_ms - 7.0).abs() < 1e-9);
        assert!((s.p99_ms - 7.0).abs() < 1e-9);
    }

    #[test]
    fn no_samples_is_all_zero_with_the_failures_kept() {
        let s = summarize(Vec::new(), 3, 2);
        assert_eq!(s.count, 0);
        assert_eq!(s.errors, 3);
        assert_eq!(s.rate_limited, 2);
        assert!(s.p95_ms.abs() < 1e-9);
    }
}
