//! Vaultwarden's login rate limiter, for the unauthenticated routes it guards: a token bucket per
//! client address, `LOGIN_RATELIMIT_MAX_BURST` requests at once (10) and one more every
//! `LOGIN_RATELIMIT_SECONDS` (60). A refusal is a 429; its message is the route's to choose.
//!
//! Kept in memory (a restart forgets it, which only lets a client have a few more tries). The map
//! is bounded: when it is full, buckets that have refilled are dropped, and if none has, the
//! oldest half.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

/// The most addresses followed at once.
const MAX_ADDRESSES: usize = 10_000;

#[derive(Debug)]
pub(crate) struct IpLimit {
    burst: u32,
    /// Seconds for one request to be given back.
    period: i64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: u32,
    /// When the last token was given back (or the bucket was last full).
    refilled: i64,
}

impl IpLimit {
    /// A limiter of `burst` requests at once, one given back every `period_secs` seconds. A burst
    /// or period of 0 is taken as 1, so a mistaken setting can't turn the route off.
    pub(crate) fn new(burst: u32, period_secs: u64) -> Self {
        IpLimit {
            burst: burst.max(1),
            period: i64::try_from(period_secs.max(1)).unwrap_or(i64::MAX),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one request of `ip` at `now` (Unix seconds). `Err(seconds)` is how long until one is
    /// given back.
    pub(crate) fn check(&self, ip: IpAddr, now: i64) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if buckets.len() >= MAX_ADDRESSES && !buckets.contains_key(&ip) {
            let full_after = self.period.saturating_mul(i64::from(self.burst));
            buckets.retain(|_, b| now - b.refilled < full_after);
            if buckets.len() >= MAX_ADDRESSES {
                let mut stamps: Vec<i64> = buckets.values().map(|b| b.refilled).collect();
                stamps.sort_unstable();
                let cut = stamps[stamps.len() / 2];
                buckets.retain(|_, b| b.refilled > cut);
            }
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            refilled: now,
        });
        let given = (now - bucket.refilled).max(0) / self.period;
        if given > 0 {
            let tokens = i64::from(bucket.tokens).saturating_add(given);
            bucket.tokens = u32::try_from(tokens.min(i64::from(self.burst))).unwrap_or(self.burst);
            bucket.refilled = if bucket.tokens == self.burst {
                now
            } else {
                bucket.refilled + given * self.period
            };
        }
        if bucket.tokens == 0 {
            let wait = (bucket.refilled + self.period - now).max(1);
            return Err(u64::try_from(wait).unwrap_or(1));
        }
        bucket.tokens -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ONE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

    #[test]
    fn an_address_has_its_burst_then_one_request_every_period() {
        let limit = IpLimit::new(10, 60);
        for _ in 0..10 {
            assert_eq!(limit.check(ONE, 1_000), Ok(()));
        }
        assert_eq!(limit.check(ONE, 1_000), Err(60));
        assert_eq!(limit.check(ONE, 1_030), Err(30));
        // Another address has a bucket of its own.
        assert_eq!(limit.check(OTHER, 1_030), Ok(()));
        // One request is given back after a period, and only one.
        assert_eq!(limit.check(ONE, 1_060), Ok(()));
        assert_eq!(limit.check(ONE, 1_061), Err(59));
    }

    #[test]
    fn a_quiet_address_is_back_to_a_full_burst_and_no_more() {
        let limit = IpLimit::new(3, 10);
        for _ in 0..3 {
            assert_eq!(limit.check(ONE, 0), Ok(()));
        }
        assert!(limit.check(ONE, 0).is_err());
        // Far more than the burst's worth of time later: three, not more.
        for _ in 0..3 {
            assert_eq!(limit.check(ONE, 10_000), Ok(()));
        }
        assert_eq!(limit.check(ONE, 10_000), Err(10));
    }

    #[test]
    fn a_zero_setting_does_not_turn_the_limit_off() {
        let limit = IpLimit::new(0, 0);
        assert_eq!(limit.check(ONE, 5), Ok(()));
        assert_eq!(limit.check(ONE, 5), Err(1));
    }
}
