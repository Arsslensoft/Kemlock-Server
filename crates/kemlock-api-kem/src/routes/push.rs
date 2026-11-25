//! `POST` and `DELETE /kem/v1/devices/push-token`: the signed-in device's push token, for the
//! push relay (`docs/push-relay.md`).
//!
//! The routes need a store that keeps push tokens (`PushRepo`), which `SqlStore` does and the
//! shared [`Store`] bound doesn't say, so they have a router of their own, like spaces:
//! [`router`] takes the [`Api`] and the push store, authenticates with the same DPoP-bound tokens,
//! and is merged beside the main router. It has no fallback.

use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::Router;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use kemlock_app::ports::TokenSigner;
use kemlock_app::push::{PushKind, PushRepo, RegisterPushToken};
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};

/// The router's state: the API's and the push store.
struct Env<S, P, K, R> {
    api: Api<S, P, K>,
    push: R,
}

impl<S, P, K, R: Clone> Clone for Env<S, P, K, R> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            push: self.push.clone(),
        }
    }
}

/// An authenticated request: `Authed`, extracted from this router's state.
struct Caller(Authed);

impl<S, P, K, R> FromRequestParts<Env<S, P, K, R>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, env: &Env<S, P, K, R>) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(Caller)
    }
}

/// The body of `POST /kem/v1/devices/push-token`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PushTokenRequest {
    /// `"apns"` (iOS) or `"unifiedpush"` (Android). `"fcm"` is no longer accepted.
    pub(crate) kind: String,
    /// The token the push service gave the app, 1 to 512 characters with no whitespace. For
    /// `"unifiedpush"` it is the endpoint URL the distributor gave: `https`, no user name or
    /// password. The server sends "sync now" to it itself.
    pub(crate) token: String,
}

fn registration<S, P, K, R>(env: &Env<S, P, K, R>) -> RegisterPushToken<S, R, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    RegisterPushToken {
        devices: env.api.store.clone(),
        push: env.push.clone(),
        clock: env.api.crypto.clone(),
    }
}

async fn put_token<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    let request: PushTokenRequest = body.json()?;
    let kind = PushKind::parse(&request.kind)
        .filter(|kind| kind.registrable())
        .ok_or_else(|| Problem::bad_request("the kind must be apns or unifiedpush"))?;
    registration(&env)
        .register(&caller.0.actor, kind, &request.token)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_token<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    registration(&env).unregister(&caller.0.actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The push-token routes. Merge it beside [`crate::router`]; it has no fallback.
///
/// ```text
/// POST    /kem/v1/devices/push-token   { "kind": "apns" | "unifiedpush", "token": "..." }   204
/// DELETE  /kem/v1/devices/push-token                                                 204
/// ```
pub fn router<S, P, K, R>(api: Api<S, P, K>, push: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PushRepo + Clone + 'static,
{
    let env = Env { api, push };
    Router::new()
        .route(
            "/kem/v1/devices/push-token",
            post(put_token::<S, P, K, R>).delete(delete_token::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    post, path = "/kem/v1/devices/push-token", tag = "devices",
    security(("dpop" = [])),
    request_body = PushTokenRequest,
    responses(
        (status = 204, description = "The token is kept for the signed-in device"),
        (status = 400, description = "Not apns or unifiedpush (fcm is no longer accepted), a token that isn't 1 to 512 characters with no whitespace, or a UnifiedPush endpoint that isn't an https URL", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Not signed in", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_push_token_put() {}

#[utoipa::path(
    delete, path = "/kem/v1/devices/push-token", tag = "devices",
    security(("dpop" = [])),
    responses(
        (status = 204, description = "The device's token is forgotten"),
        (status = 401, description = "Not signed in", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_push_token_delete() {}

/// The push-token routes' part of `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_push_token_put, doc_push_token_delete),
    components(schemas(PushTokenRequest))
)]
struct PushDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    PushDoc::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_refuses_unknown_fields() {
        let ok: Result<PushTokenRequest, _> =
            serde_json::from_str(r#"{"kind":"apns","token":"abc"}"#);
        assert!(ok.is_ok());
        let extra: Result<PushTokenRequest, _> =
            serde_json::from_str(r#"{"kind":"apns","token":"abc","user":"x"}"#);
        assert!(extra.is_err());
    }
}
