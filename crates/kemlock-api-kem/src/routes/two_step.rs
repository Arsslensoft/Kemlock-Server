//! Emailed codes, YubiKeys and Duo as the second step of a Kemlock sign-in.
//!
//! - `POST /kem/v1/auth/two-factor/email/send` mails a code to the address the account set up.
//! - `POST /kem/v1/auth/two-factor/duo/start` starts a Duo prompt and answers the address to send
//!   the person to; Duo's redirect brings back a code and a state.
//! - `POST /kem/v1/auth/two-factor/email`, `.../yubikey` and `.../duo` answer the second step with
//!   the emailed code, a YubiKey OTP, or `<code>|<state>` from Duo, and answer tokens.
//! - `POST /kem/v1/auth/two-factor/recovery` answers the second step with the account's recovery
//!   code (shown at `GET /kem/v1/account/two-factor/recovery-code`): every method goes off, the code
//!   is spent, and the answer is tokens.
//!
//! `GET /kem/v1/account/two-step` lists the signed-in account's own second steps: each method it
//! has set up with whether it is on, and whether it holds a recovery code.
//!
//! An authenticator app answers at `/kem/v1/auth/two-factor` and a security key at
//! `.../webauthn`. The routes need ports the rest of the API doesn't (the mail sender, Yubico,
//! Duo and the stored challenges), so the router is built apart, from the API state and a
//! [`TwoStepRuntime`], and merged into the main router by the server: see [`two_step_router`].
//! Setting a method up is the Bitwarden API's (`/api/two-factor/...`), where the web vault does it.

use super::auth::token_response;
use super::guard;
use super::new_device::announce;
use crate::dto::{TokenResponse, decode};
use crate::extract::{Authed, Body, DPOP_NONCE, Proof};
use crate::openapi::ProblemDoc;
use crate::problem::{Problem, rate_limited};
use crate::ratelimit::ip_key;
use crate::signlog::token_ids;
use crate::state::{Api, Crypto, Store};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use kemlock_app::notices::Notices;
use kemlock_app::passkeys::ChallengeRepo;
use kemlock_app::ports::{TokenSigner, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{Duo, TwoStep, TwoStepInput, TwoStepSettings, TwoStepSignIn, Yubico};
use kemlock_app::{AppError, Sessions, b64url};
use kemlock_crypto::hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};

/// The ports the second-step routes need beyond the rest of the API.
pub struct TwoStepRuntime<R> {
    /// Where a Duo prompt keeps its state until its answer comes (`ChallengeKind::DuoPrompt`).
    pub challenges: R,
    /// Sends the emailed codes.
    pub notices: Notices,
    pub yubico: Arc<dyn Yubico>,
    pub duo: Arc<dyn Duo>,
    pub settings: TwoStepSettings,
}

impl<R> std::fmt::Debug for TwoStepRuntime<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoStepRuntime")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// Bodies

/// Asks for something of a sign-in that is waiting for its second step.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StepChallengeRequest {
    /// The sealed challenge the password step answered with.
    pub(crate) challenge: String,
    /// The client's kind, which Duo's redirect page needs: `web` (the default), `browser`,
    /// `desktop`, `mobile` or `cli`. Send the same when the prompt is answered.
    pub(crate) client: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DuoStartResponse {
    /// Where to send the person: Duo's prompt. Duo's redirect comes back with a `code` and a
    /// `state`; answer with `<code>|<state>`.
    pub(crate) auth_url: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StepCodeRequest {
    pub(crate) challenge: String,
    /// The emailed code, the YubiKey OTP, or `<code>|<state>` from Duo.
    pub(crate) code: String,
    /// As in the request that started the prompt.
    pub(crate) client: Option<String>,
}

/// One second step the account has set up.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TwoStepMethodEntry {
    /// `totp`, `webauthn`, `email`, `yubikey` or `duo`.
    pub(crate) method: String,
    /// Whether the method is on: it is asked for at sign-in.
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TwoStepListResponse {
    /// The methods the account has set up, by name; none for an account without a second step.
    pub(crate) methods: Vec<TwoStepMethodEntry>,
    /// Whether the account holds a recovery code.
    pub(crate) recovery_codes: bool,
}

/// The client kinds Duo's redirect page tells apart.
fn client_kind(raw: Option<&str>) -> Result<&'static str, Problem> {
    match raw.map(str::trim) {
        None | Some("" | "web") => Ok("web"),
        Some("browser") => Ok("browser"),
        Some("desktop") => Ok("desktop"),
        Some("mobile") => Ok("mobile"),
        Some("cli") => Ok("cli"),
        Some(_) => Err(Problem::bad_request(
            "client must be web, browser, desktop, mobile or cli",
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Use-case builder

type Step<S, P, K, R> = TwoStepSignIn<S, S, P, P, R, S, S, K, S>;

fn step<S, P, K, R>(api: &Api<S, P, K>, runtime: &TwoStepRuntime<R>) -> Step<S, P, K, R>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    TwoStepSignIn {
        users: api.store.clone(),
        two_step: TwoStep {
            two_factor: api.store.clone(),
            seal: api.crypto.clone(),
            env: api.crypto.clone(),
            challenges: runtime.challenges.clone(),
            notices: runtime.notices.clone(),
            yubico: runtime.yubico.clone(),
            duo: runtime.duo.clone(),
            settings: runtime.settings.clone(),
        },
        sessions: Sessions {
            devices: api.store.clone(),
            tokens: api.store.clone(),
            signer: api.signer.clone(),
            env: api.crypto.clone(),
            events: api.store.clone(),
            two_factor: api.store.clone(),
            config: api.config.auth,
        },
    }
}

/// The limits every second-step call passes: per address, and per challenge.
fn limit_second_step<S, P, K>(
    api: &Api<S, P, K>,
    ip: std::net::IpAddr,
    challenge: &[u8],
    now: i64,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(ip), now)?;
    let digest = hash::sha256(challenge);
    guard(
        &api.limits.sign_in,
        &format!("challenge:{}", b64url::encode(&digest[..12])),
        now,
    )
}

// ---------------------------------------------------------------------------------------------
// Handlers

/// `POST /kem/v1/auth/two-factor/email/send`: mails a code. Limited per address, per challenge
/// and per account, so the route can't be used to fill a mailbox.
async fn handle_email_send<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    proof: Proof,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: StepChallengeRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    let now = api.now();
    limit_second_step(&api, proof.ip, &challenge, now)?;
    let step = step(&api, &runtime);
    let user = step.challenge_user(&challenge)?;
    guard(&api.limits.sign_in, &format!("email-code:{user}"), now)?;
    step.send_email_code(&challenge, &proof.jkt).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /kem/v1/auth/two-factor/duo/start`: the address of Duo's prompt.
async fn handle_duo_start<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<DuoStartResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: StepChallengeRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    let client = client_kind(request.client.as_deref())?;
    limit_second_step(&api, proof.ip, &challenge, api.now())?;
    let auth_url = step(&api, &runtime)
        .duo_url(&challenge, &proof.jkt, client)
        .await?;
    Ok(Json(DuoStartResponse { auth_url }))
}

/// The answer to a second step, for tokens. A wrong code counts against the account (5 in 15
/// minutes, then doubling delays), whichever challenge or address it comes from.
async fn answer<S, P, K, R>(
    api: &Api<S, P, K>,
    runtime: &TwoStepRuntime<R>,
    proof: Proof,
    body: Body,
    method: TwoFactorMethod,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: StepCodeRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    let client = client_kind(request.client.as_deref())?;
    let now = api.now();
    limit_second_step(api, proof.ip, &challenge, now)?;
    let step = step(api, runtime);
    // A genuine, fresh challenge names the account its failures count against.
    let user = step.challenge_user(&challenge)?;
    let account = format!("2fa:{user}");
    api.limits
        .second_step
        .blocked(&account, now)
        .map_err(rate_limited)?;
    let finished = step
        .verify(TwoStepInput {
            challenge,
            method,
            code: request.code,
            jkt: proof.jkt,
            client: client.to_owned(),
        })
        .await;
    match &finished {
        Err(AppError::Unauthorized) => api.limits.second_step.fail(&account, now),
        Ok(_) => api.limits.second_step.clear(&account),
        Err(_) => {}
    }
    api.log_attempt(api.attempt("two-factor", Some(user), &finished, proof.ip, token_ids))
        .await;
    let tokens = finished?;
    announce(api, &tokens, proof.ip).await;
    Ok(Json(token_response(&tokens, now)))
}

/// `POST /kem/v1/auth/two-factor/email`.
async fn handle_email<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    answer(&api, &runtime, proof, body, TwoFactorMethod::Email).await
}

/// `POST /kem/v1/auth/two-factor/yubikey`.
async fn handle_yubikey<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    answer(&api, &runtime, proof, body, TwoFactorMethod::YubiKey).await
}

/// `POST /kem/v1/auth/two-factor/duo`.
async fn handle_duo<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    answer(&api, &runtime, proof, body, TwoFactorMethod::Duo).await
}

/// `POST /kem/v1/auth/two-factor/recovery`: the account's recovery code as the second step. It
/// switches every method off, is spent, and answers tokens. Counted against the account like any
/// other second-step answer.
async fn handle_recovery<S, P, K>(
    State(api): State<Api<S, P, K>>,
    proof: Proof,
    body: Body,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let request: StepCodeRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    let now = api.now();
    limit_second_step(&api, proof.ip, &challenge, now)?;
    let step = api.recovery_sign_in();
    // A genuine, fresh challenge names the account its failures count against.
    let user = step.challenge_user(&challenge)?;
    let account = format!("2fa:{user}");
    api.limits
        .second_step
        .blocked(&account, now)
        .map_err(rate_limited)?;
    let finished = step.recover(&challenge, &request.code, &proof.jkt).await;
    match &finished {
        Err(AppError::Unauthorized) => api.limits.second_step.fail(&account, now),
        Ok(_) => api.limits.second_step.clear(&account),
        Err(_) => {}
    }
    Ok(Json(token_response(&finished?, now)))
}

/// `GET /kem/v1/account/two-step`: the caller's own second steps. Never shows a secret, only
/// which methods exist and whether they are on.
async fn handle_list<S, P, K>(
    State(api): State<Api<S, P, K>>,
    authed: Authed,
) -> Result<Json<TwoStepListResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let user = authed.actor.user;
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
    guard(&api.limits.sign_in, &format!("two-step-list:{user}"), now)?;
    let mut methods: Vec<TwoStepMethodEntry> = TwoFactorRepo::list(&api.store, user)
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|row| TwoStepMethodEntry {
            method: row.method.as_str().to_owned(),
            enabled: row.enabled,
        })
        .collect();
    methods.sort_by(|a, b| a.method.cmp(&b.method));
    let recovery_codes = api
        .store
        .recovery_code(user)
        .await
        .map_err(AppError::from)?
        .is_some()
        || api
            .store
            .legacy_recovery_code(user)
            .await
            .map_err(AppError::from)?
            .is_some();
    Ok(Json(TwoStepListResponse {
        methods,
        recovery_codes,
    }))
}

/// The same `DPoP-Nonce` header every other `/kem/v1` response carries.
async fn nonce_header<S, P, K>(
    State(api): State<Api<S, P, K>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&api.dpop.current_nonce(api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The second-step routes for emailed codes, YubiKeys and Duo. Merge the result into the main
/// router:
///
/// ```ignore
/// router(api.clone()).merge(two_step_router(api, TwoStepRuntime { challenges, notices, yubico, duo, settings }))
/// ```
pub fn two_step_router<S, P, K, R>(api: Api<S, P, K>, runtime: TwoStepRuntime<R>) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/auth/two-factor/email/send",
            post(handle_email_send::<S, P, K, R>),
        )
        .route(
            "/kem/v1/auth/two-factor/duo/start",
            post(handle_duo_start::<S, P, K, R>),
        )
        .route(
            "/kem/v1/auth/two-factor/email",
            post(handle_email::<S, P, K, R>),
        )
        .route(
            "/kem/v1/auth/two-factor/yubikey",
            post(handle_yubikey::<S, P, K, R>),
        )
        .route(
            "/kem/v1/auth/two-factor/duo",
            post(handle_duo::<S, P, K, R>),
        )
        .route(
            "/kem/v1/auth/two-factor/recovery",
            post(handle_recovery::<S, P, K>),
        )
        .route("/kem/v1/account/two-step", get(handle_list::<S, P, K>))
        .layer(Extension(Arc::new(runtime)))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---------------------------------------------------------------------------------------------
// OpenAPI

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/email/send", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepChallengeRequest,
    responses(
        (status = 204, description = "A code was mailed to the address the account set up"),
        (status = 400, description = "The server can't mail codes", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Another device key, or the account has no email method", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many codes asked for", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_email_send() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/duo/start", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepChallengeRequest,
    responses(
        (status = 200, description = "Where to send the person for Duo's prompt", body = DuoStartResponse),
        (status = 400, description = "The account has no usable Duo setup, or Duo can't be reached", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Another device key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_duo_start() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/email", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepCodeRequest,
    responses(
        (status = 200, description = "Signed in", body = TokenResponse),
        (status = 401, description = "Wrong, used or expired code", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong codes", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_email() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/yubikey", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepCodeRequest,
    responses(
        (status = 200, description = "Signed in", body = TokenResponse),
        (status = 401, description = "An OTP from a key that isn't registered, or Yubico didn't accept it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong OTPs", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_yubikey() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/duo", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepCodeRequest,
    responses(
        (status = 200, description = "Signed in", body = TokenResponse),
        (status = 401, description = "Wrong state, or Duo didn't accept the code: a prompt is answered once", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong answers", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_duo() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/recovery", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = StepCodeRequest,
    responses(
        (status = 200, description = "Signed in; every two-step method of the account is off and the code is spent", body = TokenResponse),
        (status = 401, description = "Wrong or spent code, or another device key", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong answers", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_recovery() {}

#[utoipa::path(
    get, path = "/kem/v1/account/two-step", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The caller's own second steps, and whether it holds a recovery code", body = TwoStepListResponse),
        (status = 401, description = "No valid access token", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many calls", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_list() {}

/// The OpenAPI paths of the emailed-code, YubiKey and Duo routes, for the server to merge into
/// `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_email_send,
        doc_duo_start,
        doc_email,
        doc_yubikey,
        doc_duo,
        doc_recovery,
        doc_list
    ),
    components(schemas(
        ProblemDoc,
        StepChallengeRequest,
        DuoStartResponse,
        StepCodeRequest,
        TwoStepMethodEntry,
        TwoStepListResponse,
        TokenResponse
    ))
)]
pub struct TwoStepApiDoc;
