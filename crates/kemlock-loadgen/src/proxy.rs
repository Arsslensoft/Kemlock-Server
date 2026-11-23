//! A signing reverse proxy for tools that can't make DPoP proofs, such as oha. Every request it
//! receives goes to the server with one account's access token and a new proof, so oha can hit
//! the unchanged sync and the attachment routes without the server's replay check refusing a
//! repeated proof. It buffers each body, so it is for the rigs, never for production.
//!
//! The proxy adds a hop on loopback, a fraction of a millisecond. The rigs compare each run with
//! main's last run on the same machine, which cancels it; read absolute numbers from it with
//! that in mind.

use crate::device::remember_nonce;
use crate::serve::Served;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// The largest body the proxy will hold: the design's 256 MiB attachment, with room.
const MAX_BODY: usize = 512 * 1024 * 1024;

/// Request headers that pass through to the server.
const FORWARDED_REQUEST: [&str; 7] = [
    "content-type",
    "if-match",
    "if-none-match",
    "range",
    "accept",
    "accept-encoding",
    "content-encoding",
];

/// Response headers that pass back. Length and framing are the proxy's own.
const FORWARDED_RESPONSE: [&str; 8] = [
    "content-type",
    "content-encoding",
    "etag",
    "content-range",
    "accept-ranges",
    "location",
    "retry-after",
    "dpop-nonce",
];

#[derive(Debug)]
pub(crate) struct ProxyState {
    pub(crate) served: Arc<Served>,
    pub(crate) account: usize,
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
}

pub(crate) fn router(state: Arc<ProxyState>) -> Router {
    Router::new().fallback(forward).with_state(state)
}

async fn forward(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    match forward_inner(&state, request).await {
        Ok(response) => response,
        Err(message) => (StatusCode::BAD_GATEWAY, message).into_response(),
    }
}

async fn forward_inner(
    state: &ProxyState,
    request: Request,
) -> std::result::Result<Response, String> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|e| format!("can't read the request body: {e}"))?;
    let uri = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let path = parts.uri.path().to_owned();
    let (Some(device), Some(session)) = (
        state.served.devices.get(state.account),
        state.served.sessions.get(state.account),
    ) else {
        return Err("the proxy's account isn't in the accounts file".to_owned());
    };
    let token = session.read().await.tokens.access_token.clone();

    for attempt in 0..2 {
        let proof = device.proof(parts.method.as_str(), &path, Some(&token));
        let mut upstream = state
            .http
            .request(parts.method.clone(), format!("{}{}", state.base_url, uri))
            .header("dpop", proof)
            .header("authorization", format!("DPoP {token}"));
        for name in FORWARDED_REQUEST {
            if let Some(value) = parts.headers.get(name) {
                upstream = upstream.header(name, value.clone());
            }
        }
        if !bytes.is_empty() {
            upstream = upstream.body(bytes.clone());
        }
        let answer = upstream
            .send()
            .await
            .map_err(|e| format!("the server didn't answer: {e}"))?;
        let status = answer.status();
        let headers = answer.headers().clone();
        let payload = answer
            .bytes()
            .await
            .map_err(|e| format!("can't read the server's body: {e}"))?;
        if let Some(nonce) = headers.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            remember_nonce(nonce);
        }
        let wants_nonce = status == StatusCode::UNAUTHORIZED
            && String::from_utf8_lossy(&payload).contains("use-dpop-nonce");
        if wants_nonce && attempt == 0 {
            continue;
        }
        let mut response = Response::builder().status(status);
        for name in FORWARDED_RESPONSE {
            if let Some(value) = headers.get(name) {
                response = response.header(name, value.clone());
            }
        }
        return response
            .body(Body::from(payload))
            .map_err(|e| format!("can't build the response: {e}"));
    }
    Err("the server kept asking for a new nonce".to_owned())
}
