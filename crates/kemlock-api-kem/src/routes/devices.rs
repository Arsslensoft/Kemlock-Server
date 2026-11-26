//! Opening the vault on a new device without the password: approval requests, signing in as an
//! approved device, the trusted-device key copy, and signing a device out.
//!
//! A new device asks for approval with a DPoP proof (so the key it signs in with is known) and
//! the account's email; open devices list and answer requests with their access tokens; the new
//! device polls, then signs in through a challenge. The root key travels only as a `kx1` sealed
//! box the server relays without opening.

use super::guard;
use crate::dto::{DeviceDto, TokenResponse, decode};
use crate::extract::{Authed, Body, Proof};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::{Limiter, ip_key};
use crate::signlog::token_ids;
use crate::state::{Api, Crypto, Store};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use kemlock_app::devices::{
    Answer, AnswerApproval, ApprovalRequestInput, DeviceSignIn, DevicesStore, EndSession,
    KeyCopies, ListApprovals, PendingApproval, Poll, PollApproval, RequestApproval, SignOutDevice,
    UntrustDevice,
};
use kemlock_app::notices::Notices;
use kemlock_app::ports::TokenSigner;
use kemlock_app::sso::RequireSso;
use kemlock_app::{Sessions, TokenPair, b64url};
use kemlock_domain::unlock::{ApprovalId, DeviceKeyCopy, KeyProtection};
use kemlock_domain::{DeviceId, DeviceKind, Email};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// Requests per address an hour. The account's own limit (10 an hour) is in the use case; this one
/// stops one address spraying requests at many accounts.
const REQUESTS_PER_IP_PER_HOUR: u32 = 30;

/// Requests per address and email an hour, whether or not the email has an account: so one address
/// can't use up an account's 10 (and the owner's mailbox) alone, and the 429 it gets past this is
/// the same for every email.
const REQUESTS_PER_EMAIL_PER_IP_PER_HOUR: u32 = 3;

/// The limiter of this router, held in an extension so the shared `Api` state needn't know it.
#[derive(Debug)]
pub(crate) struct DeviceLimits {
    requests: Limiter,
    per_email: Limiter,
}

impl DeviceLimits {
    fn new() -> Self {
        DeviceLimits {
            requests: Limiter::new(REQUESTS_PER_IP_PER_HOUR, 3600),
            per_email: Limiter::new(REQUESTS_PER_EMAIL_PER_IP_PER_HOUR, 3600),
        }
    }
}

fn iso(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

fn approval_id(raw: &str) -> Result<ApprovalId, Problem> {
    raw.parse()
        .map_err(|_| Problem::bad_request("the request id isn't a UUID"))
}

pub(crate) fn token_response(tokens: &TokenPair, now: i64) -> TokenResponse {
    TokenResponse {
        token_type: "DPoP".to_owned(),
        access_token: tokens.access_token.clone(),
        expires_in: (tokens.access_expires_at.unix_timestamp() - now).max(0),
        refresh_token: tokens.refresh_token.clone(),
        refresh_expires_in: (tokens.refresh_expires_at.unix_timestamp() - now).max(0),
        user_id: tokens.user.0,
        device_id: tokens.device.0,
        admin: tokens.admin,
    }
}

// ---------------------------------------------------------------------------------------------
// Bodies.

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalRequestBody {
    /// The account the device wants to sign in to.
    pub(crate) email: String,
    /// The device's one-time `kx1` public key, 1,600 bytes, base64url.
    pub(crate) public_key: String,
    pub(crate) device: DeviceDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalRequestResponse {
    pub(crate) request_id: Uuid,
    /// Five words, shown beside the ones the approving device shows.
    pub(crate) phrase: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalPollResponse {
    /// `"pending"`, `"approved"`, `"denied"`, `"expired"` or `"used"`.
    pub(crate) status: String,
    pub(crate) expires_at: Option<String>,
    /// With `approved`: the root key sealed to the device's one-time key, base64url.
    pub(crate) sealed_key: Option<String>,
    /// With `approved` only: the account the key opens, which the box's aad binds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) account_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceChallengeRequest {
    pub(crate) request_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceChallengeResponse {
    /// Send it back to `/auth/device/verify` within five minutes, with a proof of the same key.
    pub(crate) challenge: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceVerifyRequest {
    pub(crate) challenge: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingApprovalDto {
    pub(crate) id: Uuid,
    pub(crate) device_name: String,
    #[schema(value_type = String)]
    pub(crate) device_kind: DeviceKind,
    /// The requester's address, cut to its /24 (IPv4) or /48 (IPv6).
    pub(crate) ip: String,
    /// The five words the new device shows; they must match.
    pub(crate) phrase: String,
    /// The request's one-time `kx1` public key, base64url (1,600 bytes). The open device works the
    /// phrase out from it itself and seals the root key to it.
    pub(crate) public_key: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: String,
    pub(crate) age_seconds: i64,
}

impl PendingApprovalDto {
    fn from_pending(p: PendingApproval, now: OffsetDateTime) -> Self {
        PendingApprovalDto {
            id: p.id.0,
            device_name: p.device_name,
            device_kind: p.device_kind,
            ip: p.ip,
            phrase: p.phrase,
            public_key: b64url::encode(&p.public_key),
            created_at: iso(p.created_at),
            expires_at: iso(p.expires_at),
            age_seconds: (now - p.created_at).whole_seconds().max(0),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalListResponse {
    pub(crate) approvals: Vec<PendingApprovalDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalAnswerRequest {
    /// `"approve"` or `"deny"`.
    pub(crate) decision: String,
    /// With `approve`: the root key sealed to the request's public key (docs/crypto.md, context
    /// `"device-approval"`), base64url. With `deny`: absent.
    pub(crate) sealed_key: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyCopyRequest {
    /// The root key wrapped by a key only this device holds, base64url, 1 to 1,024 bytes.
    pub(crate) wrapped_key: String,
    /// `"secure-enclave"`, `"keystore"`, `"web-crypto"`, `"browser"` or `"software"`.
    #[schema(value_type = String)]
    pub(crate) protection: KeyProtection,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyCopyResponse {
    pub(crate) device_id: Uuid,
    pub(crate) wrapped_key: String,
    #[schema(value_type = String)]
    pub(crate) protection: KeyProtection,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

impl KeyCopyResponse {
    fn from_copy(copy: &DeviceKeyCopy) -> Self {
        KeyCopyResponse {
            device_id: copy.device.0,
            wrapped_key: b64url::encode(&copy.wrapped_key),
            protection: copy.protection,
            created_at: iso(copy.created_at),
            updated_at: iso(copy.updated_at),
        }
    }
}

/// `POST /kem/v1/auth/sign-out`: an empty body ends this session; `{"others": true}` keeps it and ends
/// the device's other sessions.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EndSessionRequest {
    /// End the device's other sessions and keep this one.
    #[serde(default)]
    pub(crate) others: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignOutRequest {
    pub(crate) device_id: Uuid,
}

// ---------------------------------------------------------------------------------------------
// Use-case builders.

impl<S: Store + DevicesStore, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    fn device_sessions(&self) -> Sessions<S, S, K, P, S, S> {
        Sessions {
            devices: self.store.clone(),
            tokens: self.store.clone(),
            signer: self.signer.clone(),
            env: self.crypto.clone(),
            events: self.store.clone(),
            two_factor: self.store.clone(),
            config: self.auth_config(),
        }
    }

    fn request_approval(&self) -> RequestApproval<S, S, Notices, P> {
        RequestApproval {
            users: self.store.clone(),
            approvals: self.store.clone(),
            notices: self.hub.notices(),
            env: self.crypto.clone(),
        }
    }

    fn list_approvals(&self) -> ListApprovals<S, P> {
        ListApprovals {
            approvals: self.store.clone(),
            env: self.crypto.clone(),
        }
    }

    fn answer_approval(&self) -> AnswerApproval<S, P, S> {
        AnswerApproval {
            approvals: self.store.clone(),
            env: self.crypto.clone(),
            events: self.store.clone(),
        }
    }

    fn poll_approval(&self) -> PollApproval<S, P> {
        PollApproval {
            approvals: self.store.clone(),
            env: self.crypto.clone(),
        }
    }

    fn device_sign_in(&self) -> DeviceSignIn<S, S, P, S, S, K, P, S, S, S> {
        DeviceSignIn {
            users: self.store.clone(),
            approvals: self.store.clone(),
            seal: self.crypto.clone(),
            sessions: self.device_sessions(),
            sso: RequireSso {
                membership: self.store.clone(),
            },
        }
    }

    fn key_copies(&self) -> KeyCopies<S, S, P> {
        KeyCopies {
            devices: self.store.clone(),
            copies: self.store.clone(),
            clock: self.crypto.clone(),
        }
    }

    fn untrust_device(&self) -> UntrustDevice<S, S, P, S> {
        UntrustDevice {
            devices: self.store.clone(),
            copies: self.store.clone(),
            clock: self.crypto.clone(),
            events: self.store.clone(),
        }
    }

    fn end_session(&self) -> EndSession<S, S, P, S> {
        EndSession {
            devices: self.store.clone(),
            tokens: self.store.clone(),
            clock: self.crypto.clone(),
            events: self.store.clone(),
        }
    }

    fn sign_out_device(&self) -> SignOutDevice<S, S, S, P, S> {
        SignOutDevice {
            devices: self.store.clone(),
            copies: self.store.clone(),
            tokens: self.store.clone(),
            clock: self.crypto.clone(),
            events: self.store.clone(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers.

impl<S: Store + DevicesStore, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// `POST /kem/v1/auth/device/request`: a new device asks for approval.
    pub(crate) async fn handle_device_request(
        State(api): State<Self>,
        proof: Proof,
        Extension(limits): Extension<Arc<DeviceLimits>>,
        body: Body,
    ) -> Result<(StatusCode, Json<ApprovalRequestResponse>), Problem> {
        guard(&limits.requests, &ip_key(proof.ip), api.now())?;
        let request: ApprovalRequestBody = body.json()?;
        // A malformed request is refused before it counts against the address's requests for an
        // email: only a request that could be stored spends any of that.
        let device = request.device.into_info()?;
        let public_key = decode("publicKey", &request.public_key)?;
        // An email too long to be one is refused by the use case; it isn't counted here.
        if request.email.len() <= Email::MAX_LEN {
            let email = request.email.trim().to_lowercase();
            guard(
                &limits.per_email,
                &format!("{email}|{}", ip_key(proof.ip)),
                api.now(),
            )?;
        }
        let requested = api
            .request_approval()
            .execute(ApprovalRequestInput {
                email: request.email,
                device,
                public_key,
                jkt: proof.jkt,
                ip: proof.ip,
            })
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(ApprovalRequestResponse {
                request_id: requested.id.0,
                phrase: requested.phrase,
                expires_at: iso(requested.expires_at),
            }),
        ))
    }

    /// `GET /kem/v1/auth/device/request/{id}`: the new device polls for the answer.
    pub(crate) async fn handle_device_poll(
        State(api): State<Self>,
        proof: Proof,
        Path(id): Path<String>,
    ) -> Result<Json<ApprovalPollResponse>, Problem> {
        let polled = api
            .poll_approval()
            .execute(approval_id(&id)?, &proof.jkt)
            .await?;
        let (status, expires_at, sealed_key, account) = match polled {
            Poll::Pending { expires_at } => ("pending", expires_at, None, None),
            Poll::Approved {
                sealed_key,
                account,
            } => ("approved", None, Some(sealed_key), Some(account)),
            Poll::Denied => ("denied", None, None, None),
            Poll::Expired => ("expired", None, None, None),
            Poll::Used => ("used", None, None, None),
        };
        Ok(Json(ApprovalPollResponse {
            status: status.to_owned(),
            expires_at: expires_at.map(iso),
            sealed_key: sealed_key.map(|k| b64url::encode(&k)),
            account_id: account.map(|a| a.to_string()),
        }))
    }

    /// `POST /kem/v1/auth/device/challenge`: a challenge for an approved request.
    pub(crate) async fn handle_device_challenge(
        State(api): State<Self>,
        proof: Proof,
        body: Body,
    ) -> Result<Json<DeviceChallengeResponse>, Problem> {
        guard(&api.limits.sign_in, &ip_key(proof.ip), api.now())?;
        let request: DeviceChallengeRequest = body.json()?;
        let challenge = api
            .device_sign_in()
            .challenge(ApprovalId(request.request_id), &proof.jkt)
            .await?;
        Ok(Json(DeviceChallengeResponse {
            challenge: b64url::encode(&challenge),
        }))
    }

    /// `POST /kem/v1/auth/device/verify`: the challenge back, signed for by the registered key,
    /// for tokens.
    pub(crate) async fn handle_device_verify(
        State(api): State<Self>,
        proof: Proof,
        body: Body,
    ) -> Result<Json<TokenResponse>, Problem> {
        let now = api.now();
        guard(&api.limits.sign_in, &ip_key(proof.ip), now)?;
        let request: DeviceVerifyRequest = body.json()?;
        let challenge = decode("challenge", &request.challenge)?;
        let verified = api.device_sign_in().verify(&challenge, &proof.jkt).await;
        api.log_attempt(api.attempt("device-approval", None, &verified, proof.ip, token_ids))
            .await;
        let tokens = verified?;
        Ok(Json(token_response(&tokens, now)))
    }

    /// `GET /kem/v1/devices/approvals`: the account's pending requests.
    pub(crate) async fn handle_approvals_list(
        State(api): State<Self>,
        authed: Authed,
    ) -> Result<Json<ApprovalListResponse>, Problem> {
        let pending = api.list_approvals().execute(&authed.actor).await?;
        let now = api.crypto.now();
        Ok(Json(ApprovalListResponse {
            approvals: pending
                .into_iter()
                .map(|p| PendingApprovalDto::from_pending(p, now))
                .collect(),
        }))
    }

    /// `POST /kem/v1/devices/approvals/{id}`: approve with a sealed key, or deny.
    pub(crate) async fn handle_approval_answer(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let id = approval_id(&id)?;
        let request: ApprovalAnswerRequest = body.json()?;
        let answer = match (request.decision.as_str(), request.sealed_key) {
            ("approve", Some(sealed_key)) => Answer::Approve {
                sealed_key: decode("sealedKey", &sealed_key)?,
            },
            ("approve", None) => {
                return Err(Problem::bad_request("approve needs a sealedKey"));
            }
            ("deny", None) => Answer::Deny,
            ("deny", Some(_)) => {
                return Err(Problem::bad_request("deny sends no key"));
            }
            _ => return Err(Problem::bad_request("decision must be approve or deny")),
        };
        api.answer_approval()
            .execute(&authed.actor, id, answer)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `PUT /kem/v1/devices/key-copy`: this device's wrapped copy of the root key.
    pub(crate) async fn handle_key_copy_put(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<Json<KeyCopyResponse>, Problem> {
        let request: KeyCopyRequest = body.json()?;
        let copy = api
            .key_copies()
            .put(
                &authed.actor,
                decode("wrappedKey", &request.wrapped_key)?,
                request.protection,
            )
            .await?;
        Ok(Json(KeyCopyResponse::from_copy(&copy)))
    }

    /// `GET /kem/v1/devices/key-copy`: this device's copy, after sign-in.
    pub(crate) async fn handle_key_copy_get(
        State(api): State<Self>,
        authed: Authed,
    ) -> Result<Json<KeyCopyResponse>, Problem> {
        let copy = api.key_copies().get(&authed.actor).await?;
        Ok(Json(KeyCopyResponse::from_copy(&copy)))
    }

    /// `DELETE /kem/v1/devices/key-copy`: stop trusting this device.
    pub(crate) async fn handle_key_copy_delete(
        State(api): State<Self>,
        authed: Authed,
    ) -> Result<StatusCode, Problem> {
        api.key_copies().remove(&authed.actor).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `DELETE /kem/v1/devices/{id}/key-copy`: stop trusting one of the account's devices. Its
    /// session goes on; only the copy of the root key goes.
    pub(crate) async fn handle_device_untrust(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<StatusCode, Problem> {
        let device = id
            .parse::<Uuid>()
            .map_err(|_| Problem::bad_request("the device id isn't a UUID"))?;
        api.untrust_device()
            .execute(&authed.actor, DeviceId(device))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /kem/v1/auth/sign-out`: ends this device's session only, or, with `{"others": true}`, its
    /// other sessions and not this one. The key copy stays either way.
    pub(crate) async fn handle_auth_sign_out(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let others = if body.is_empty() {
            false
        } else {
            body.json::<EndSessionRequest>()?.others
        };
        if others {
            api.end_session()
                .execute_others(&authed.actor, authed.auth_time)
                .await?;
        } else {
            api.end_session().execute(&authed.actor).await?;
        }
        Ok(StatusCode::NO_CONTENT)
    }

    /// `POST /kem/v1/devices/sign-out`: ends a device's session and deletes its key copy.
    pub(crate) async fn handle_device_sign_out(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<StatusCode, Problem> {
        let request: SignOutRequest = body.json()?;
        api.sign_out_device()
            .execute(&authed.actor, DeviceId(request.device_id))
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// The routes of this module. Merged into the main router by `service::router`.
pub(crate) fn router<S, P, K>() -> Router<Api<S, P, K>>
where
    S: Store + DevicesStore,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    type A<S, P, K> = Api<S, P, K>;
    Router::new()
        .route(
            "/kem/v1/auth/device/request",
            post(A::<S, P, K>::handle_device_request),
        )
        .route(
            "/kem/v1/auth/device/request/{id}",
            get(A::<S, P, K>::handle_device_poll),
        )
        .route(
            "/kem/v1/auth/device/challenge",
            post(A::<S, P, K>::handle_device_challenge),
        )
        .route(
            "/kem/v1/auth/device/verify",
            post(A::<S, P, K>::handle_device_verify),
        )
        .route(
            "/kem/v1/devices/approvals",
            get(A::<S, P, K>::handle_approvals_list),
        )
        .route(
            "/kem/v1/devices/approvals/{id}",
            post(A::<S, P, K>::handle_approval_answer),
        )
        .route(
            "/kem/v1/devices/key-copy",
            get(A::<S, P, K>::handle_key_copy_get)
                .put(A::<S, P, K>::handle_key_copy_put)
                .delete(A::<S, P, K>::handle_key_copy_delete),
        )
        .route(
            "/kem/v1/devices/{id}/key-copy",
            delete(A::<S, P, K>::handle_device_untrust),
        )
        .route(
            "/kem/v1/auth/sign-out",
            post(A::<S, P, K>::handle_auth_sign_out),
        )
        .route(
            "/kem/v1/devices/sign-out",
            post(A::<S, P, K>::handle_device_sign_out),
        )
        .layer(Extension(Arc::new(DeviceLimits::new())))
}

// ---------------------------------------------------------------------------------------------
// OpenAPI.

#[utoipa::path(
    post, path = "/kem/v1/auth/device/request", tag = "device-approval",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = ApprovalRequestBody,
    responses(
        (status = 201, description = "The request exists (the same answer for an unknown email). Show `phrase` and poll", body = ApprovalRequestResponse),
        (status = 429, description = "Ten requests an hour per account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_request() {}

#[utoipa::path(
    get, path = "/kem/v1/auth/device/request/{id}", tag = "device-approval",
    params(
        ("id" = String, Path, description = "The request id"),
        ("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key"),
    ),
    responses((status = 200, description = "The answer so far; only the key that made the request sees it", body = ApprovalPollResponse))
)]
#[allow(dead_code)]
fn doc_device_poll() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/device/challenge", tag = "device-approval",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = DeviceChallengeRequest,
    responses(
        (status = 200, description = "A challenge for the approved request", body = DeviceChallengeResponse),
        (status = 401, description = "Not approved, expired, or another key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_challenge() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/device/verify", tag = "device-approval",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = DeviceVerifyRequest,
    responses(
        (status = 200, description = "Signed in; the approval is used up", body = TokenResponse),
        (status = 401, description = "The challenge is wrong, expired or used", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_verify() {}

#[utoipa::path(
    get, path = "/kem/v1/devices/approvals", tag = "device-approval",
    security(("dpop" = [])),
    responses((status = 200, description = "Pending requests, newest first", body = ApprovalListResponse))
)]
#[allow(dead_code)]
fn doc_approvals_list() {}

#[utoipa::path(
    post, path = "/kem/v1/devices/approvals/{id}", tag = "device-approval",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The request id")),
    request_body = ApprovalAnswerRequest,
    responses(
        (status = 204, description = "Answered"),
        (status = 400, description = "Expired, already answered, or a box of the wrong shape", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such request for this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_approval_answer() {}

#[utoipa::path(
    put, path = "/kem/v1/devices/key-copy", tag = "trusted-device",
    security(("dpop" = [])),
    request_body = KeyCopyRequest,
    responses((status = 200, description = "Stored", body = KeyCopyResponse))
)]
#[allow(dead_code)]
fn doc_key_copy_put() {}

#[utoipa::path(
    get, path = "/kem/v1/devices/key-copy", tag = "trusted-device",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "This device's copy", body = KeyCopyResponse),
        (status = 404, description = "This device holds none", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key_copy_get() {}

#[utoipa::path(
    delete, path = "/kem/v1/devices/key-copy", tag = "trusted-device",
    security(("dpop" = [])),
    responses((status = 204, description = "Removed; the session goes on"))
)]
#[allow(dead_code)]
fn doc_key_copy_delete() {}

#[utoipa::path(
    delete, path = "/kem/v1/devices/{id}/key-copy", tag = "trusted-device",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The device's id, from the device list")),
    responses(
        (status = 204, description = "That device's copy of the root key is gone; its session goes on"),
        (status = 400, description = "The id isn't a UUID", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such device on this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_untrust() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/sign-out", tag = "trusted-device",
    security(("dpop" = [])),
    request_body = Option<EndSessionRequest>,
    responses(
        (status = 204, description = "With no body: this device's refresh tokens are revoked and its DPoP key unbound. With {\"others\": true}: its other sessions end and this one goes on. The device and its key copy stay either way"),
        (status = 401, description = "Not signed in", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_auth_sign_out() {}

#[utoipa::path(
    post, path = "/kem/v1/devices/sign-out", tag = "trusted-device",
    security(("dpop" = [])),
    request_body = SignOutRequest,
    responses(
        (status = 204, description = "The device's tokens, key copy and row are gone"),
        (status = 404, description = "No such device on this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_device_sign_out() {}

/// The documented routes of this module.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_device_request,
        doc_device_poll,
        doc_device_challenge,
        doc_device_verify,
        doc_approvals_list,
        doc_approval_answer,
        doc_key_copy_put,
        doc_key_copy_get,
        doc_key_copy_delete,
        doc_device_untrust,
        doc_auth_sign_out,
        doc_device_sign_out
    ),
    components(schemas(
        ApprovalRequestBody,
        ApprovalRequestResponse,
        ApprovalPollResponse,
        DeviceChallengeRequest,
        DeviceChallengeResponse,
        DeviceVerifyRequest,
        PendingApprovalDto,
        ApprovalListResponse,
        ApprovalAnswerRequest,
        KeyCopyRequest,
        KeyCopyResponse,
        EndSessionRequest,
        SignOutRequest
    ))
)]
struct DevicesDoc;

/// The documented routes of this module and of `emergency`, for `/kem/v1/openapi.json`.
pub(crate) fn document() -> utoipa::openapi::OpenApi {
    DevicesDoc::openapi()
        .merge_from(super::emergency::document())
        .merge_from(super::contract::document())
        .merge_from(super::failover::document())
}
