//! The public pairing routes of `/fed/v1`: where the admin who typed a one-time code sends the
//! CPace messages to the server that showed it (`docs/federation.md`, Pairing).
//!
//! - `POST /fed/v1/pair/start`: message 1 in, message 2 out.
//! - `POST /fed/v1/pair/finish?initiator=<server id>`: message 3 in, 204 out.
//!
//! The code is the authentication, so the routes are open, and they say as little as they can: any
//! refusal is the same bare 400, so a wrong code teaches the other side nothing. A code is good for
//! one attempt (the hub takes it by value). Bodies are capped at 64 KiB and the routes answer 429
//! past 20 requests a minute across both, so they can't be used to hammer the hub.

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use kemlock_domain::ServerId;
use kemlock_federation::{FedStore, Pairings, unix_now};
use serde::Deserialize;
use std::sync::{Arc, Mutex, PoisonError};

/// The media type of a pairing message.
pub const PAIRING_MEDIA_TYPE: &str = "application/vnd.kemlock.federation-pairing+cbor";
/// The largest pairing message accepted.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests a minute, across both routes.
pub const MAX_PER_MINUTE: u32 = 20;

struct PairState<S> {
    pairings: Arc<Pairings<S>>,
    window: Arc<Mutex<Window>>,
}

/// Requests counted in the current minute.
#[derive(Debug, Default)]
struct Window {
    started: u64,
    count: u32,
}

impl Window {
    fn allow(&mut self, now: u64) -> bool {
        if now >= self.started.saturating_add(60) {
            self.started = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= MAX_PER_MINUTE
    }
}

impl<S> Clone for PairState<S> {
    fn clone(&self) -> Self {
        PairState {
            pairings: self.pairings.clone(),
            window: self.window.clone(),
        }
    }
}

impl<S> PairState<S> {
    /// Counts one request in the current minute; false when it is over the limit.
    fn allow(&self, now: u64) -> bool {
        self.window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(now)
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

async fn start<S: FedStore + 'static>(State(state): State<PairState<S>>, body: Bytes) -> Response {
    let now = unix_now();
    if !state.allow(now) {
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
    query: Result<Query<FinishQuery>, QueryRejection>,
    body: Bytes,
) -> Response {
    let now = unix_now();
    if !state.allow(now) {
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
        window: Arc::new(Mutex::new(Window::default())),
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

    #[test]
    fn the_window_allows_twenty_a_minute_and_resets() {
        let mut window = Window::default();
        for _ in 0..MAX_PER_MINUTE {
            assert!(window.allow(100));
        }
        assert!(!window.allow(101));
        assert!(window.allow(161));
    }
}
