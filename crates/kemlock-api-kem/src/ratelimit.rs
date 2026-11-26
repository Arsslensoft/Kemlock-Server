//! In-memory rate limits (design, "Security", Rate limits): so many tries per window, then
//! doubling delays. Failures slow down rather than lock an account. State is per process; a
//! restart forgets it, which only ever lets an attacker try a few more times.
//!
//! The limiter's memory is bounded whatever keys callers send. A key is stored as a 16-byte hash
//! of itself, never as the text (an email can be long and chosen by an attacker). Entries live in
//! two generations: the current one and the one before. A generation is dropped whole once it is
//! older than the retention time, or early when it holds [`MAX_KEYS`] entries, so eviction is
//! O(1) amortised with no scan of the map, and at most `2 * MAX_KEYS` entries exist at once. A
//! flood of new keys can therefore only make the limiter forget older counters, which is the
//! same as a restart.

use kemlock_crypto::hash;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};

/// A stored key: the first 16 bytes of the SHA-256 of the key text.
type Key = [u8; 16];

fn digest(key: &str) -> Key {
    let full = hash::sha256(key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[derive(Debug)]
struct Entry {
    window_start: i64,
    count: u32,
    /// How many times in a row the limit was exceeded; each level doubles the delay.
    level: u32,
    /// Whether the level was raised in the current window; a quiet window earns forgiveness.
    raised: bool,
    blocked_until: i64,
}

impl Entry {
    fn fresh(now: i64) -> Self {
        Entry {
            window_start: now,
            count: 0,
            level: 0,
            raised: false,
            blocked_until: 0,
        }
    }

    /// Starts a new window when the current one has run out.
    fn roll(&mut self, now: i64, window_secs: i64) {
        if now - self.window_start >= window_secs {
            // A quiet window earns one level of forgiveness.
            if !self.raised {
                self.level = self.level.saturating_sub(1);
            }
            self.window_start = now;
            self.count = 0;
            self.raised = false;
        }
    }

    /// Raises the level and blocks for the delay it earns. Returns the delay in seconds.
    fn raise(&mut self, now: i64) -> i64 {
        self.level = self.level.saturating_add(1);
        self.raised = true;
        let delay = (1i64 << (self.level - 1).min(20)).min(MAX_DELAY_SECS);
        self.blocked_until = now + delay;
        delay
    }

    fn wait(&self, now: i64) -> Option<u64> {
        (now < self.blocked_until).then(|| u64::try_from(self.blocked_until - now).unwrap_or(1))
    }
}

#[derive(Debug, Default)]
struct Generations {
    current: HashMap<Key, Entry>,
    previous: HashMap<Key, Entry>,
    /// When `current` began.
    rotated_at: Option<i64>,
}

impl Generations {
    /// The entry for `key`, made if it is new, after dropping what is too old or too many.
    fn entry(&mut self, key: Key, now: i64, retention: i64) -> &mut Entry {
        match self.rotated_at {
            None => self.rotated_at = Some(now),
            Some(at) if now - at >= retention * 2 => {
                self.current.clear();
                self.previous.clear();
                self.rotated_at = Some(now);
            }
            Some(at) if now - at >= retention => self.rotate(now),
            Some(_) => {}
        }
        if !self.current.contains_key(&key) && self.current.len() >= MAX_KEYS {
            self.rotate(now);
        }
        let Generations {
            current, previous, ..
        } = self;
        current
            .entry(key)
            .or_insert_with(|| previous.remove(&key).unwrap_or_else(|| Entry::fresh(now)))
    }

    fn rotate(&mut self, now: i64) {
        self.previous = std::mem::take(&mut self.current);
        self.rotated_at = Some(now);
    }

    fn peek(&self, key: &Key) -> Option<&Entry> {
        self.current.get(key).or_else(|| self.previous.get(key))
    }

    fn remove(&mut self, key: &Key) {
        self.current.remove(key);
        self.previous.remove(key);
    }
}

/// `limit` tries per `window_secs`, then delays of 1, 2, 4, … seconds (at most an hour) for each
/// further try.
#[derive(Debug)]
pub struct Limiter {
    /// Tries per window; the console can change it while the server runs.
    limit: AtomicU32,
    window_secs: i64,
    /// How long an untouched entry is kept at least: long enough to outlast any delay.
    retention_secs: i64,
    state: Mutex<Generations>,
}

const MAX_DELAY_SECS: i64 = 3600;
/// The most entries one generation holds.
const MAX_KEYS: usize = 20_000;

impl Limiter {
    pub fn new(limit: u32, window_secs: i64) -> Self {
        Limiter {
            limit: AtomicU32::new(limit),
            window_secs,
            retention_secs: (window_secs.saturating_mul(10)).max(2 * MAX_DELAY_SECS),
            state: Mutex::new(Generations::default()),
        }
    }

    /// Tries per window now.
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Changes the tries per window (at least 1). Counts already made stay: they are compared
    /// with the new limit at the next try.
    pub fn set_limit(&self, limit: u32) {
        self.limit.store(limit.max(1), Ordering::Relaxed);
    }

    /// Counts one try for `key` at `now` (Unix seconds). `Err(seconds)` says how long to wait.
    pub fn check(&self, key: &str, now: i64) -> Result<(), u64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = state.entry(digest(key), now, self.retention_secs);
        if let Some(wait) = entry.wait(now) {
            return Err(wait);
        }
        entry.roll(now, self.window_secs);
        entry.count = entry.count.saturating_add(1);
        if entry.count > self.limit() {
            let delay = entry.raise(now);
            return Err(u64::try_from(delay).unwrap_or(1));
        }
        Ok(())
    }

    /// Whether `key` is waiting out a delay at `now`, without counting a try. `Err(seconds)` says
    /// how long to wait.
    pub fn blocked(&self, key: &str, now: i64) -> Result<(), u64> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.peek(&digest(key)).and_then(|entry| entry.wait(now)) {
            Some(wait) => Err(wait),
            None => Ok(()),
        }
    }

    /// Counts one failure for `key`, for limits that only failures count against (a wrong
    /// password, a wrong code). After `limit` failures in a window the key waits 1 second, and
    /// each further failure doubles the wait, up to an hour. Callers check [`Limiter::blocked`]
    /// before they try.
    pub fn fail(&self, key: &str, now: i64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = state.entry(digest(key), now, self.retention_secs);
        entry.roll(now, self.window_secs);
        entry.count = entry.count.saturating_add(1);
        if entry.count >= self.limit() {
            entry.raise(now);
        }
    }

    /// Forgets the count and the delay of `key`, after a success.
    pub fn clear(&self, key: &str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.remove(&digest(key));
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.current.len() + state.previous.len()
    }
}

/// The key a client counts under: its IPv4 address, or its IPv6 /48, so one host can't dodge the
/// limits by rotating addresses. A site is typically given a /48 (or a /56) and a host can use any
/// of its /64s, so counting by /64 left 65,536 keys to one customer. An IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`, how a dual-stack listener shows an IPv4 peer) is keyed as the IPv4 address
/// it carries; without that, every IPv4 client would share the one key of the `::/48` prefix.
pub fn ip_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for s in &mut segments[3..] {
                *s = 0;
            }
            format!("ip:{}/48", Ipv6Addr::from(segments))
        }
    }
}

/// Every value of the header `name`, in the order the request carried them, joined with commas
/// as HTTP says a repeated header may be. A proxy that appends to a forwarded header (HAProxy's
/// `option forwardfor`) adds its own line instead of extending the client's, and the proxy's line
/// is last, so a reader that looks at the first line only reads what the client wrote. `None`
/// when the header is absent or no line is text.
pub fn joined_header(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

/// The real client address: the peer's, or, when the peer is a trusted proxy and the configured
/// header names the client, the right-most address in that header that isn't itself a trusted
/// proxy (`KEMLOCK_TRUSTED_PROXIES`, `IP_HEADER`). Every address is canonicalised first, so an
/// IPv4 proxy listed as `10.0.0.1` matches a peer shown as `::ffff:10.0.0.1`.
pub fn client_ip(peer: IpAddr, header: Option<&str>, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    let Some(header) = header else {
        return peer;
    };
    let trusted: Vec<IpAddr> = trusted.iter().map(IpAddr::to_canonical).collect();
    if !trusted.contains(&peer) {
        return peer;
    }
    let addresses: Vec<IpAddr> = header
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();
    addresses
        .iter()
        .rev()
        .find(|ip| !trusted.contains(ip))
        .or(addresses.first())
        .copied()
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_up_to_the_limit_pass_and_the_next_waits() {
        let l = Limiter::new(3, 60);
        for _ in 0..3 {
            assert_eq!(l.check("a", 1000), Ok(()));
        }
        assert_eq!(l.check("a", 1000), Err(1));
        // Still inside the first delay.
        assert_eq!(l.check("a", 1000), Err(1));
    }

    #[test]
    fn a_changed_limit_applies_to_the_next_try() {
        let l = Limiter::new(1, 60);
        assert_eq!(l.check("a", 0), Ok(()));
        assert_eq!(l.check("b", 0), Ok(()));
        l.set_limit(3);
        assert_eq!(l.limit(), 3);
        // "a" had one try; two more now pass, and the fourth waits.
        assert_eq!(l.check("a", 1), Ok(()));
        assert_eq!(l.check("a", 1), Ok(()));
        assert_eq!(l.check("a", 1), Err(1));
        // A limit can't go below one try.
        l.set_limit(0);
        assert_eq!(l.limit(), 1);
    }

    #[test]
    fn delays_double_with_each_further_try() {
        let l = Limiter::new(1, 60);
        assert_eq!(l.check("a", 0), Ok(()));
        assert_eq!(l.check("a", 0), Err(1));
        assert_eq!(l.check("a", 1), Err(2));
        assert_eq!(l.check("a", 3), Err(4));
        assert_eq!(l.check("a", 7), Err(8));
        // Waiting out the delay inside the same window is still over the limit.
        assert_eq!(l.check("a", 15), Err(16));
    }

    #[test]
    fn a_new_window_resets_the_count() {
        let l = Limiter::new(2, 60);
        assert_eq!(l.check("a", 0), Ok(()));
        assert_eq!(l.check("a", 1), Ok(()));
        assert_eq!(l.check("a", 61), Ok(()));
        assert_eq!(l.check("a", 62), Ok(()));
        assert_eq!(l.check("a", 63), Err(1));
    }

    #[test]
    fn keys_are_independent() {
        let l = Limiter::new(1, 60);
        assert_eq!(l.check("a", 0), Ok(()));
        assert_eq!(l.check("b", 0), Ok(()));
        assert!(l.check("a", 0).is_err());
        assert!(l.check("b", 0).is_err());
    }

    #[test]
    fn a_flood_of_new_keys_never_holds_more_than_two_generations() {
        let l = Limiter::new(5, 60);
        for i in 0..(3 * MAX_KEYS) {
            let _ = l.check(&format!("acct:flood-{i}@example.org"), 100);
        }
        assert!(l.tracked() <= 2 * MAX_KEYS, "{} entries", l.tracked());
    }

    #[test]
    fn keys_are_stored_hashed_so_a_long_key_costs_no_more_than_a_short_one() {
        let l = Limiter::new(1, 60);
        let long = format!("acct:{}", "x".repeat(1_000_000));
        assert_eq!(l.check(&long, 0), Ok(()));
        assert!(l.check(&long, 0).is_err());
        assert_eq!(l.tracked(), 1);
        assert_eq!(l.check(&format!("{long}y"), 0), Ok(()));
        assert_eq!(l.tracked(), 2);
    }

    #[test]
    fn idle_entries_are_forgotten_without_scanning_the_map() {
        let l = Limiter::new(1, 60);
        for i in 0..100 {
            let _ = l.check(&format!("k{i}"), 0);
        }
        assert_eq!(l.tracked(), 100);
        // Past two retention periods both generations go at the next touch.
        let later = l.retention_secs * 2 + 1;
        assert_eq!(l.check("fresh", later), Ok(()));
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn an_entry_keeps_its_level_through_one_rotation() {
        let l = Limiter::new(1, 60);
        assert_eq!(l.check("a", 0), Ok(()));
        assert_eq!(l.check("a", 0), Err(1));
        // One retention period later the entry sits in the older generation.
        assert_eq!(l.check("b", l.retention_secs), Ok(()));
        assert_eq!(l.tracked(), 2);
        // A touch finds it there: the delay is over and the window is new, but the level
        // survived, so the next excess doubles the delay instead of starting again at one.
        assert_eq!(l.check("a", l.retention_secs), Ok(()));
        assert_eq!(l.check("a", l.retention_secs), Err(2));
    }

    #[test]
    fn blocked_counts_nothing_and_fail_counts_only_failures() {
        let l = Limiter::new(3, 60);
        for _ in 0..50 {
            assert_eq!(l.blocked("a", 0), Ok(()));
        }
        assert_eq!(l.tracked(), 0, "looking costs no entry");
        l.fail("a", 0);
        l.fail("a", 0);
        assert_eq!(l.blocked("a", 0), Ok(()), "two failures are free");
        l.fail("a", 0);
        assert_eq!(
            l.blocked("a", 0),
            Err(1),
            "the limit-th failure starts the delay"
        );
        // Waiting it out allows a try; failing again doubles the wait.
        assert_eq!(l.blocked("a", 1), Ok(()));
        l.fail("a", 1);
        assert_eq!(l.blocked("a", 1), Err(2));
        assert_eq!(l.blocked("a", 3), Ok(()));
        l.fail("a", 3);
        assert_eq!(l.blocked("a", 3), Err(4));
        // Other keys are untouched.
        assert_eq!(l.blocked("b", 3), Ok(()));
    }

    #[test]
    fn a_success_clears_the_failures() {
        let l = Limiter::new(2, 60);
        l.fail("a", 0);
        l.fail("a", 0);
        assert!(l.blocked("a", 0).is_err());
        l.clear("a");
        assert_eq!(l.blocked("a", 0), Ok(()));
        l.fail("a", 0);
        assert_eq!(l.blocked("a", 0), Ok(()), "the count started again");
    }

    #[test]
    fn failures_in_old_windows_are_forgotten() {
        let l = Limiter::new(3, 60);
        l.fail("a", 0);
        l.fail("a", 0);
        // A window later the count is new: two more failures don't reach the limit.
        l.fail("a", 61);
        l.fail("a", 61);
        assert_eq!(l.blocked("a", 61), Ok(()));
    }

    #[test]
    fn the_delay_is_capped() {
        let l = Limiter::new(0, 1_000_000);
        let mut now = 0;
        let mut last = 0;
        for _ in 0..40 {
            if let Err(wait) = l.check("a", now) {
                last = wait;
                now += i64::try_from(wait).expect("small");
            }
        }
        assert_eq!(last, 3600);
    }

    #[test]
    fn an_ipv6_client_counts_by_its_slash_48() {
        let a: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().expect("ip");
        let b: IpAddr = "2001:db8:1:2:1:2:3:4".parse().expect("ip");
        // Another /64 of the same /48 is the same client: a site has 65,536 of them.
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        let d: IpAddr = "2001:db8:2:2::1".parse().expect("ip");
        assert_eq!(ip_key(a), ip_key(b));
        assert_eq!(ip_key(a), ip_key(c));
        assert_ne!(ip_key(a), ip_key(d));
        assert_eq!(ip_key(a), "ip:2001:db8:1::/48");
        assert_eq!(ip_key("192.0.2.7".parse().expect("ip")), "ip:192.0.2.7");
    }

    #[test]
    fn an_ipv4_mapped_peer_is_keyed_as_its_ipv4_address() {
        // A dual-stack listener (ROCKET_ADDRESS="::") shows IPv4 peers like this.
        let a: IpAddr = "::ffff:192.0.2.7".parse().expect("ip");
        let b: IpAddr = "::ffff:192.0.2.8".parse().expect("ip");
        assert_eq!(ip_key(a), "ip:192.0.2.7");
        assert_ne!(ip_key(a), ip_key(b));
        assert_eq!(ip_key(a), ip_key("192.0.2.7".parse().expect("ip")));
    }

    #[test]
    fn a_mapped_peer_matches_an_ipv4_trusted_proxy_and_mapped_headers_are_read() {
        let proxy: IpAddr = "10.0.0.1".parse().expect("ip");
        let mapped_proxy: IpAddr = "::ffff:10.0.0.1".parse().expect("ip");
        let client: IpAddr = "198.51.100.4".parse().expect("ip");
        let header = "::ffff:198.51.100.4, ::ffff:10.0.0.1";
        assert_eq!(client_ip(mapped_proxy, Some(header), &[proxy]), client);
        // The other way round: a mapped entry in the list, an IPv4 peer.
        assert_eq!(client_ip(proxy, Some(header), &[mapped_proxy]), client);
        // An untrusted mapped peer is returned canonical, so it keys per IPv4 address.
        let outsider: IpAddr = "::ffff:203.0.113.9".parse().expect("ip");
        assert_eq!(
            client_ip(outsider, Some(header), &[proxy]),
            "203.0.113.9".parse::<IpAddr>().expect("ip")
        );
    }

    #[test]
    fn the_forwarded_header_is_trusted_only_from_a_trusted_proxy() {
        let proxy: IpAddr = "10.0.0.1".parse().expect("ip");
        let outsider: IpAddr = "203.0.113.9".parse().expect("ip");
        let client: IpAddr = "198.51.100.4".parse().expect("ip");
        let header = "198.51.100.4, 10.0.0.1";
        assert_eq!(client_ip(proxy, Some(header), &[proxy]), client);
        assert_eq!(client_ip(outsider, Some(header), &[proxy]), outsider);
        assert_eq!(client_ip(proxy, None, &[proxy]), proxy);
        assert_eq!(client_ip(proxy, Some("garbage"), &[proxy]), proxy);
    }

    #[test]
    fn every_line_of_a_repeated_header_is_read_in_order() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(joined_header(&headers, "x-forwarded-for"), None);
        headers.append("x-forwarded-for", "1.2.3.4".parse().expect("value"));
        headers.append("x-forwarded-for", "198.51.100.4".parse().expect("value"));
        assert_eq!(
            joined_header(&headers, "x-forwarded-for").as_deref(),
            Some("1.2.3.4,198.51.100.4")
        );
        // HAProxy's `option forwardfor` adds its own line after the client's: the client's own
        // line must not decide the address.
        let proxy: IpAddr = "10.0.0.1".parse().expect("ip");
        let real: IpAddr = "198.51.100.4".parse().expect("ip");
        let joined = joined_header(&headers, "x-forwarded-for");
        assert_eq!(client_ip(proxy, joined.as_deref(), &[proxy]), real);
        let first_only = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok());
        assert_eq!(
            client_ip(proxy, first_only, &[proxy]),
            "1.2.3.4".parse::<IpAddr>().expect("ip"),
            "the first line alone is only the client's own claim"
        );
    }

    #[test]
    fn a_spoofed_leading_address_is_ignored() {
        let proxy: IpAddr = "10.0.0.1".parse().expect("ip");
        let real: IpAddr = "198.51.100.4".parse().expect("ip");
        // The client sent "X-Forwarded-For: 1.2.3.4"; the proxy appended the real address.
        assert_eq!(
            client_ip(proxy, Some("1.2.3.4, 198.51.100.4"), &[proxy]),
            real
        );
    }
}
