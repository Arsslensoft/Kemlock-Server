//! The `/fed/v1` routes.
//!
//! - `GET /fed/v1/descriptor` and `GET /.well-known/kemlock-federation`: the signed descriptor,
//!   as the deterministic CBOR envelope `docs/federation.md` defines. Public: it holds only public
//!   keys, and a peer checks it against the key it pinned at pairing.
//! - `POST /fed/v1/keys`: a signed key record (a rotation or a revocation of an identity key), open
//!   because the record is signed by a key the receiver holds.
//! - `GET /fed/v1/session`: a WebSocket of binary messages. The first message is the peer's hello,
//!   the answer is the reply, and every message after is a sealed frame answered by a sealed frame.
//!   Only a paired peer gets past the first message.
//!
//! The pairing routes are in [`crate::pair`] and the admin routes `/admin/v1/federation` in
//! [`crate::admin`].

use crate::session::{Duplex, serve};
use crate::state::FedState;
use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kemlock_federation::keyrecs::MAX_RECORD;
use kemlock_federation::{FedStore, unix_now};

/// The media type of a descriptor.
pub const DESCRIPTOR_MEDIA_TYPE: &str = "application/vnd.kemlock.federation-descriptor+cbor";
/// The largest WebSocket message accepted: a frame carries at most 4 MiB, plus its header, tag
/// and padding.
pub const MAX_MESSAGE_BYTES: usize = 5 * 1024 * 1024;

/// The `/fed/v1` router and the well-known document.
pub fn router<S: FedStore + 'static>(state: FedState<S>) -> Router {
    Router::new()
        .route("/fed/v1/descriptor", get(descriptor::<S>))
        .route("/.well-known/kemlock-federation", get(descriptor::<S>))
        .route("/fed/v1/session", get(session::<S>))
        .route(
            "/fed/v1/keys",
            post(key_record::<S>).layer(DefaultBodyLimit::max(MAX_RECORD)),
        )
        .with_state(state)
}

async fn descriptor<S: FedStore + 'static>(State(state): State<FedState<S>>) -> Response {
    let bytes = state.replica().identity().descriptor.to_bytes();
    (
        [
            (header::CONTENT_TYPE, DESCRIPTOR_MEDIA_TYPE),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        bytes,
    )
        .into_response()
}

/// A signed key record, a rotation or a revocation of a server's identity key. The record is its
/// own authentication (it is signed by a key the receiver holds), so the route is open; a refusal
/// is a bare 400.
async fn key_record<S: FedStore + 'static>(
    State(state): State<FedState<S>>,
    body: Bytes,
) -> Response {
    match state.replica().accept_key_record(&body, unix_now()).await {
        Ok(outcome) => {
            tracing::debug!(?outcome, "a key record was accepted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::info!(error = %e, "a key record was refused");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn session<S: FedStore + 'static>(
    State(state): State<FedState<S>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let mut io = Socket(socket);
            let end = serve(&state, &mut io).await;
            tracing::debug!(?end, "a federation session ended");
        })
}

/// A WebSocket as a [`Duplex`] of binary messages.
struct Socket(WebSocket);

impl Duplex for Socket {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.0.recv().await {
                Some(Ok(Message::Binary(bytes))) => return Some(bytes.to_vec()),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                // Text is not part of the protocol; close, errors and the end of the stream end it.
                Some(Ok(Message::Text(_) | Message::Close(_)) | Err(_)) | None => return None,
            }
        }
    }

    async fn send(&mut self, message: Vec<u8>) -> bool {
        self.0.send(Message::Binary(message.into())).await.is_ok()
    }
}
