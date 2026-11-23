//! Signing a device in on a replica with its device key.
//!
//! When a federated vault's home is away, a Kemlock app moves to a replica. The replica holds the
//! account's members and device registrations (copied from the home, without an OPAQUE record), so
//! the device signs in with the key its tokens are bound to: a challenge from
//! `POST /kem/v1/auth/device-key/challenge`, sent back to `POST /kem/v1/auth/device-key/verify`
//! with a proof of the same key. No password is typed and no token key is shared between servers.
//!
//! The routes are for copied accounts only: an account that lives on this server signs in the
//! ordinary ways, so a challenge for it is refused. Both answer 404 when the server has no
//! federation wired.

use super::devices::{DeviceChallengeResponse, DeviceVerifyRequest, token_response};
use super::guard;
use super::view::MaybeView;
use crate::dto::{ResolveResponse, TokenResponse, decode};
use crate::extract::{Body, Proof};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::signlog::token_ids;
use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kemlock_app::devices::DeviceKeySignIn;
use kemlock_app::ports::TokenSigner;
use kemlock_app::sso::RequireSso;
use kemlock_app::{AppError, Sessions, b64url};
use kemlock_domain::DeviceId;
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceKeyChallengeRequest {
    /// The id of the device, as the home registered it.
    pub(crate) device_id: Uuid,
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    fn key_sign_in(&self) -> DeviceKeySignIn<S, P, S, S, K, P, S, S, S> {
        DeviceKeySignIn {
            users: self.store.clone(),
            seal: self.crypto.clone(),
            sessions: Sessions {
                devices: self.store.clone(),
                tokens: self.store.clone(),
                signer: self.signer.clone(),
                env: self.crypto.clone(),
                events: self.store.clone(),
                two_factor: self.store.clone(),
                config: self.auth_config(),
            },
            sso: RequireSso {
                membership: self.store.clone(),
            },
        }
    }

    /// `POST /kem/v1/auth/device-key/challenge`: a challenge for a device registered on this
    /// replica, asked for by a call signed with its key.
    pub(crate) async fn handle_device_key_challenge(
        State(api): State<Self>,
        proof: Proof,
        MaybeView(view): MaybeView,
        body: Body,
    ) -> Result<Json<DeviceChallengeResponse>, Problem> {
        guard(&api.limits.sign_in, &ip_key(proof.ip), api.now())?;
        let view = view.ok_or_else(Problem::not_found)?;
        let request: DeviceKeyChallengeRequest = body.json()?;
        let sign_in = api.key_sign_in();
        let device = sign_in
            .registered(DeviceId(request.device_id), &proof.jkt)
            .await?;
        // An account that lives here signs in the ordinary ways; this route is for copies.
        let copied = view
            .is_replica_account(device.user)
            .await
            .map_err(|e| Problem::from(AppError::from(e)))?;
        if !copied {
            return Err(AppError::Unauthorized.into());
        }
        let challenge = sign_in.challenge(device.id, &proof.jkt).await?;
        Ok(Json(DeviceChallengeResponse {
            challenge: b64url::encode(&challenge),
        }))
    }

    /// `POST /kem/v1/auth/device-key/verify`: the challenge back, with a proof of the same key,
    /// for tokens.
    pub(crate) async fn handle_device_key_verify(
        State(api): State<Self>,
        proof: Proof,
        MaybeView(view): MaybeView,
        body: Body,
    ) -> Result<Json<TokenResponse>, Problem> {
        let now = api.now();
        guard(&api.limits.sign_in, &ip_key(proof.ip), now)?;
        if view.is_none() {
            return Err(Problem::not_found());
        }
        let request: DeviceVerifyRequest = body.json()?;
        let challenge = decode("challenge", &request.challenge)?;
        let verified = api.key_sign_in().verify(&challenge, &proof.jkt).await;
        api.log_attempt(api.attempt("device-key", None, &verified, proof.ip, token_ids))
            .await;
        let tokens = verified?;
        Ok(Json(token_response(&tokens, now)))
    }
}

/// The routes of this module. Merged into the main router by `service::router`.
pub(crate) fn router<S, P, K>() -> Router<Api<S, P, K>>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    type A<S, P, K> = Api<S, P, K>;
    Router::new()
        .route(
            "/kem/v1/auth/device-key/challenge",
            post(A::<S, P, K>::handle_device_key_challenge),
        )
        .route(
            "/kem/v1/auth/device-key/verify",
            post(A::<S, P, K>::handle_device_key_verify),
        )
}

// ---------------------------------------------------------------------------------------------
// OpenAPI.

#[utoipa::path(
    post, path = "/kem/v1/auth/device-key/challenge", tag = "failover",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = DeviceKeyChallengeRequest,
    responses(
        (status = 200, description = "A challenge for a device registered on this replica", body = DeviceChallengeResponse),
        (status = 401, description = "Unknown device, another key, or an account that lives here", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "This server has no federation", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_key_challenge() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/device-key/verify", tag = "failover",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = DeviceVerifyRequest,
    responses(
        (status = 200, description = "Signed in with the device key; no password was involved", body = TokenResponse),
        (status = 401, description = "The challenge is wrong, expired, or for another key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_key_verify() {}

#[utoipa::path(
    post, path = "/kem/v1/items/{id}/siblings/resolve", tag = "failover",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The item id")),
    responses(
        (status = 200, description = "The siblings the item's head replaced", body = ResolveResponse),
        (status = 404, description = "Not an item of this account, or this server has no federation", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The head was already sent to another server: write a newer version", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_resolve_siblings() {}

/// The documented routes of this module.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_device_key_challenge, doc_device_key_verify, doc_resolve_siblings),
    components(schemas(DeviceKeyChallengeRequest, ResolveResponse))
)]
struct FailoverDoc;

/// The documented routes of this module, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    FailoverDoc::openapi()
}
