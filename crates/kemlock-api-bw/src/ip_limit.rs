//! Vaultwarden's login rate limiter, for the unauthenticated routes it guards: a token bucket per
//! client address, `LOGIN_RATELIMIT_MAX_BURST` requests at once (10) and one more every
//! `LOGIN_RATELIMIT_SECONDS` (60). A refusal is a 429; its message is the route's to choose.
//!
//! Kept in memory (a restart forgets it, which only lets a client have a few more tries). The map
//! is bounded: when it is full, buckets that have refilled are dropped first, then the least
//! recently used tenth. A bucket keeps its state (drained or partly) until then, so an address that
//! keeps asking is the last to go, and a flood of new addresses can't push out a busy one.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};

/// The address a client is followed by: an IPv6 client holds a whole /56 (what a household gets,
/// and what a mobile network may hand out per device), so changing the low 72 bits is not a new
/// client, and an IPv4-mapped address is the IPv4 one.
pub(crate) fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[7] = 0;
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

/// The most addresses followed at once before the map makes room.
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
    /// When the address last asked, which says what to drop first when the map is full.
    last_used: i64,
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

    /// Drops the buckets that are full again, and, when that is not enough, the least recently used
    /// ones, a bucket with some tokens spent as well as a drained one keeping its state until it is
    /// the least recent. A busy address is the most recent, so it is the last to go.
    fn make_room(&self, buckets: &mut HashMap<IpAddr, Bucket>, now: i64) {
        let full = i64::from(self.burst);
        buckets.retain(|_, b| {
            let given = (now - b.refilled).max(0) / self.period;
            i64::from(b.tokens).saturating_add(given) < full
        });
        if buckets.len() < MAX_ADDRESSES {
            return;
        }
        // Down to nine tenths, the oldest use first.
        let mut seen: Vec<(i64, IpAddr)> =
            buckets.iter().map(|(ip, b)| (b.last_used, *ip)).collect();
        seen.sort_unstable();
        for (_, ip) in seen.into_iter().take(MAX_ADDRESSES / 10) {
            buckets.remove(&ip);
        }
    }

    /// Takes one request of `ip` at `now` (Unix seconds). `Err(seconds)` is how long until one is
    /// given back.
    pub(crate) fn check(&self, ip: IpAddr, now: i64) -> Result<(), u64> {
        let ip = bucket_key(ip);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if buckets.len() >= MAX_ADDRESSES && !buckets.contains_key(&ip) {
            self.make_room(&mut buckets, now);
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            refilled: now,
            last_used: now,
        });
        bucket.last_used = now;
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
    fn an_ipv6_client_is_followed_by_its_56_bit_prefix() {
        let limit = IpLimit::new(2, 60);
        let a: IpAddr = "2001:db8:1:2::1".parse().expect("an address");
        let b: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd"
            .parse()
            .expect("an address");
        // Another /64 of the same /56 is the same client; the next /56 is not.
        let same_56: IpAddr = "2001:db8:1:ff::1".parse().expect("an address");
        let elsewhere: IpAddr = "2001:db8:1:100::1".parse().expect("an address");
        assert_eq!(limit.check(a, 0), Ok(()));
        assert_eq!(limit.check(b, 0), Ok(()));
        assert_eq!(
            limit.check(a, 0),
            Err(60),
            "one client, however it picks its low bits"
        );
        assert_eq!(limit.check(same_56, 0), Err(60));
        assert_eq!(limit.check(elsewhere, 0), Ok(()));
    }

    #[test]
    fn making_room_drops_the_least_recently_used_and_keeps_a_busy_drained_bucket() {
        let limit = IpLimit::new(2, 60);
        // One address drains its bucket and keeps asking; the map then fills with addresses that
        // each used a token once.
        for _ in 0..2 {
            assert_eq!(limit.check(ONE, 0), Ok(()));
        }
        assert!(limit.check(ONE, 0).is_err());
        for n in 0..u32::try_from(MAX_ADDRESSES).expect("small") {
            let [a, b, c, d] = n.to_be_bytes();
            assert_eq!(
                limit.check(IpAddr::V4(Ipv4Addr::new(a | 10, b, c, d)), 1),
                Ok(())
            );
            if n % 1_000 == 0 {
                assert!(limit.check(ONE, 1).is_err());
            }
        }
        // A new address is let in (the oldest tenth went), and the busy drained one is still limited.
        assert_eq!(limit.check(OTHER, 2), Ok(()));
        assert!(limit.check(ONE, 2).is_err(), "the busy bucket stayed");
        // An address that asked once, a while ago, was one of those dropped: it starts afresh.
        let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(limit.check(first, 3), Ok(()));
        assert_eq!(limit.check(first, 3), Ok(()));
    }

    #[test]
    fn an_ipv4_mapped_address_is_the_ipv4_one() {
        let limit = IpLimit::new(1, 60);
        let mapped: IpAddr = "::ffff:203.0.113.1".parse().expect("an address");
        assert_eq!(limit.check(ONE, 0), Ok(()));
        assert_eq!(limit.check(mapped, 0), Err(60));
    }

    #[test]
    fn a_zero_setting_does_not_turn_the_limit_off() {
        let limit = IpLimit::new(0, 0);
        assert_eq!(limit.check(ONE, 5), Ok(()));
        assert_eq!(limit.check(ONE, 5), Err(1));
    }
}
