//! The public pairing routes of `/fed/v1`: where the admin who typed a one-time code sends the
//! CPace messages to the server that showed it (`docs/federation.md`, Pairing).
//!
//! - `POST /fed/v1/pair/start`: message 1 in, message 2 out.
//! - `POST /fed/v1/pair/finish?initiator=<server id>`: message 3 in, 204 out.
//!
//! The code is the authentication, so the routes are open, and they say as little as they can: any
//! refusal is the same bare 400, so a wrong code teaches the other side nothing. A code is good for
//! one attempt (the hub takes it by value). A message 1 that is malformed (not the CBOR map with its
//! four fields, or naming this server as the initiator) is refused first and leaves the code
//! waiting; a well-formed one uses the code up, whoever sends it, so a stranger who can send one
//! still can. Bodies are capped at 64 KiB and the routes answer 429 past 20 requests a minute from
//! one source address (an IPv6 one by its /64) and past 300 across all of them, so one host can't
//! use up the limit of the admin who is pairing.

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use kemlock_app::privacy::ClientAddr;
use kemlock_domain::ServerId;
use kemlock_federation::{FedStore, Pairings, unix_now};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

/// The media type of a pairing message.
pub const PAIRING_MEDIA_TYPE: &str = "application/vnd.kemlock.federation-pairing+cbor";
/// The largest pairing message accepted.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests a minute from one source address, across both routes.
pub const MAX_PER_MINUTE: u32 = 20;
/// Requests a minute from all source addresses together: what a hub can answer without being
/// hammered, far above what pairing needs.
pub const MAX_PER_MINUTE_ALL: u32 = 300;
/// How many source addresses are counted at once; past it a new one is refused until a minute has
/// passed, so the table can't grow without bound.
const MAX_SOURCES: usize = 4096;

struct PairState<S> {
    pairings: Arc<Pairings<S>>,
    limits: Arc<Mutex<Limits>>,
}

/// Requests counted in the current minute.
#[derive(Debug, Default)]
struct Window {
    started: u64,
    count: u32,
}

impl Window {
    fn allow(&mut self, now: u64, limit: u32) -> bool {
        if now >= self.started.saturating_add(60) {
            self.started = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= limit
    }
}

/// The request counts: one per source address and one for everybody.
#[derive(Debug, Default)]
struct Limits {
    all: Window,
    by_source: HashMap<Option<IpAddr>, Window>,
}

impl Limits {
    /// Counts one request from `source` (`None` when the server doesn't say where it came from,
    /// as in tests); false when it is over a limit.
    fn allow(&mut self, source: Option<IpAddr>, now: u64) -> bool {
        let source = source.map(network_of);
        if self.by_source.len() >= MAX_SOURCES {
            self.by_source
                .retain(|_, w| now < w.started.saturating_add(60));
        }
        let everybody = self.all.allow(now, MAX_PER_MINUTE_ALL);
        let own = if self.by_source.len() < MAX_SOURCES || self.by_source.contains_key(&source) {
            self.by_source
                .entry(source)
                .or_default()
                .allow(now, MAX_PER_MINUTE)
        } else {
            false
        };
        everybody && own
    }
}

impl<S> Clone for PairState<S> {
    fn clone(&self) -> Self {
        PairState {
            pairings: self.pairings.clone(),
            limits: self.limits.clone(),
        }
    }
}

impl<S> PairState<S> {
    /// Counts one request in the current minute; false when it is over a limit.
    fn allow(&self, source: Option<IpAddr>, now: u64) -> bool {
        self.limits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(source, now)
    }
}

/// Where a request came from, as the server's request layer settled it (the connection's peer, or
/// the forwarded address when that peer is a trusted proxy). Absent when the server doesn't say.
struct Source(Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Source {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Source, Infallible> {
        Ok(Source(parts.extensions.get::<ClientAddr>().map(|a| a.0)))
    }
}

/// The network a source address is counted as: an IPv6 address by its /64, which is what one
/// subscriber is given, so one host can't take a fresh address for each request; an IPv4 address
/// as it is.
fn network_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(octets.into())
        }
    }
}

/// The same answer to every refused pairing message: a 400 that says nothing more.
fn refused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/problem+json")],
        r#"{"type":"urn:kemlock:problem:pairing-failed","title":"Pairing failed","status":400}"#,
    )
        .into_response()
}

async fn start<S: FedStore + 'static>(
    State(state): State<PairState<S>>,
    Source(source): Source,
    body: Bytes,
) -> Response {
    let now = unix_now();
    if !state.allow(source, now) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    match state.pairings.respond(&body, now) {
        Ok(reply) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, PAIRING_MEDIA_TYPE)],
            reply,
        )
            .into_response(),
        Err(_) => refused(),
    }
}

#[derive(Debug, Deserialize)]
struct FinishQuery {
    initiator: String,
}

async fn finish<S: FedStore + 'static>(
    State(state): State<PairState<S>>,
    Source(source): Source,
    query: Result<Query<FinishQuery>, QueryRejection>,
    body: Bytes,
) -> Response {
    let now = unix_now();
    if !state.allow(source, now) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(Query(query)) = query else {
        return refused();
    };
    let Ok(initiator) = uuid::Uuid::parse_str(&query.initiator).map(ServerId) else {
        return refused();
    };
    match state.pairings.finish(initiator, &body, now) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => refused(),
    }
}

/// The two public pairing routes.
pub fn pair_router<S: FedStore + 'static>(pairings: Arc<Pairings<S>>) -> Router {
    let state = PairState {
        pairings,
        limits: Arc::new(Mutex::new(Limits::default())),
    };
    Router::new()
        .route("/fed/v1/pair/start", post(start::<S>))
        .route("/fed/v1/pair/finish", post(finish::<S>))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().expect("an address"))
    }

    #[test]
    fn the_window_allows_twenty_a_minute_and_resets() {
        let mut window = Window::default();
        for _ in 0..MAX_PER_MINUTE {
            assert!(window.allow(100, MAX_PER_MINUTE));
        }
        assert!(!window.allow(101, MAX_PER_MINUTE));
        assert!(window.allow(161, MAX_PER_MINUTE));
    }

    #[test]
    fn one_host_using_up_its_limit_leaves_the_others_theirs() {
        let mut limits = Limits::default();
        let noisy = ip("203.0.113.9");
        for _ in 0..MAX_PER_MINUTE {
            assert!(limits.allow(noisy, 100));
        }
        assert!(!limits.allow(noisy, 101), "the noisy host is over its limit");
        // The admin who is pairing comes from elsewhere and is not affected.
        assert!(limits.allow(ip("198.51.100.4"), 101));
        // A minute later the noisy host may try again.
        assert!(limits.allow(noisy, 161));
    }

    #[test]
    fn an_ipv6_host_is_counted_by_its_64_not_by_each_address() {
        let mut limits = Limits::default();
        for n in 0..MAX_PER_MINUTE {
            // A fresh address in the same /64 each time.
            assert!(limits.allow(ip(&format!("2001:db8:1:2::{:x}", n + 1)), 100));
        }
        assert!(!limits.allow(ip("2001:db8:1:2::ffff"), 101));
        // Another /64 is another subscriber, and IPv4 addresses stay as they are.
        assert!(limits.allow(ip("2001:db8:1:3::1"), 101));
        assert!(limits.allow(ip("192.0.2.1"), 101));
    }

    #[test]
    fn the_limit_across_all_hosts_still_holds() {
        let mut limits = Limits::default();
        let mut allowed = 0;
        for n in 0..=u32::from(u16::MAX).min(1000) {
            let source = Some(IpAddr::from([10, 0, (n >> 8) as u8, (n & 0xff) as u8]));
            if limits.allow(source, 100) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, MAX_PER_MINUTE_ALL);
    }

    #[test]
    fn the_table_of_sources_is_bounded() {
        let mut limits = Limits::default();
        for n in 0..MAX_SOURCES as u32 {
            limits.by_source.insert(
                Some(IpAddr::from([10, (n >> 16) as u8, (n >> 8) as u8, n as u8])),
                Window {
                    started: 100,
                    count: 1,
                },
            );
        }
        // Full, and every entry is current: a new source is refused, a known one still counted.
        assert!(!limits.allow(ip("203.0.113.1"), 110));
        assert!(limits.by_source.len() <= MAX_SOURCES);
        // A minute on, the old entries are forgotten and a new source is served.
        assert!(limits.allow(ip("203.0.113.1"), 170));
    }
}
