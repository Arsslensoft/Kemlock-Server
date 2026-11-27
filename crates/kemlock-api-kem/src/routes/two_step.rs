//! Emailed codes, YubiKeys and Duo as the second step of a Kemlock sign-in.
//!
//! - `POST /kem/v1/auth/two-factor/email/send` mails a code to the address the account set up.
//! - `POST /kem/v1/auth/two-factor/duo/start` starts a Duo prompt and answers the address to send
//!   the person to; Duo's redirect brings back a code and a state.
//! - `POST /kem/v1/auth/two-factor/email`, `.../yubikey` and `.../duo` answer the second step with
//!   the emailed code, a YubiKey OTP, or `<code>|<state>` from Duo, and answer tokens.
//! - `POST /kem/v1/auth/two-factor/recovery` answers the second step with the account's recovery
//!   code (shown at `POST /kem/v1/account/two-factor/recovery-code`, behind a fresh proof): every method goes off, the code
//!   is spent, and the answer is tokens.
//!
//! `GET /kem/v1/account/two-step` lists the signed-in account's own second steps: each method it
//! has set up with whether it is on, and whether it holds a recovery code.
//!
//! An authenticator app answers at `/kem/v1/auth/two-factor` and a security key at
//! `.../webauthn`. The routes need ports the rest of the API doesn't (the mail sender, Yubico,
//! Duo and the stored challenges), so the router is built apart, from the API state and a
//! [`TwoStepRuntime`], and merged into the main router by the server: see [`two_step_router`].
//! A signed-in device sets a method up at `/kem/v1/account/two-factor/{email,yubikey,duo}` and
//! reads what it set up at `GET /kem/v1/account/two-step/setup`. A session alone may add the first
//! step; beside one that is on, the request that turns the method on carries a fresh `proof`, the
//! one a removal takes, and a method that is on already is refused (remove it, then add it) The Bitwarden API's `/api/two-factor/...` does the same
//! for its clients, behind the master password.

use super::attempts;
use super::auth::token_response;
use super::guard;
use super::new_device::announce;
use crate::dto::{FreshProof, TokenResponse, decode};
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
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use kemlock_app::notices::{Notice, Notices, TwoStepChangedNotice};

use kemlock_app::passkeys::ChallengeRepo;
use kemlock_app::ports::{Clock, TokenSigner, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    Duo, DuoKeys, DuoStatus, NoDuo, NoYubico, ProtectedError, TwoStep, TwoStepInput,
    TwoStepSettings, TwoStepSignIn, Yubico,
};
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
    /// The client's kind, which Duo's redirect page needs: `web` (the default), `b.any(|row| row.enabled)ser`,
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
    // A genuine, fresh challenge names the account its failures count against; the attempt is
    // reserved before the code is looked at.
    let user = step.challenge_user(&challenge)?;
    api.sign_in().check_second_step_allowed(&challenge).await?;
    attempts::reserve_second_step(api, user, now).await?;
    let finished = step
        .verify(TwoStepInput {
            challenge,
            method,
            code: request.code,
            jkt: proof.jkt,
            client: client.to_owned(),
        })
        .await;
    attempts::settle_second_step(api, user, &finished).await;
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
    // A genuine, fresh challenge names the account its failures count against; the attempt is
    // reserved before the code is looked at.
    let user = step.challenge_user(&challenge)?;
    api.sign_in().check_second_step_allowed(&challenge).await?;
    attempts::reserve_second_step(&api, user, now).await?;
    let finished = step.recover(&challenge, &request.code, &proof.jkt).await;
    attempts::settle_second_step(&api, user, &finished).await;
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

// ---------------------------------------------------------------------------------------------
// Setting a method up, from a signed-in device

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmailBeginRequest {
    /// Where the codes go; a first one is mailed to it.
    pub(crate) address: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmailConfirmRequest {
    pub(crate) address: String,
    /// The code that was mailed.
    pub(crate) code: String,
    /// A fresh proof, as a removal takes: needed when another second step is on already.
    pub(crate) proof: Option<FreshProof>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct YubikeySetRequest {
    /// One OTP per key (or, for a key already checked, its 12-character public id); at most five.
    pub(crate) otps: Vec<String>,
    /// Whether the keys are read over NFC.
    #[serde(default)]
    pub(crate) nfc: bool,
    /// A fresh proof, as a removal takes: needed when another second step is on already.
    pub(crate) proof: Option<FreshProof>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DuoSetRequest {
    /// The account's own Duo integration; leave out all three to use the server's.
    pub(crate) host: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    /// A fresh proof, as a removal takes: needed when another second step is on already.
    pub(crate) proof: Option<FreshProof>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct YubikeyShown {
    /// The public ids of the registered keys.
    pub(crate) keys: Vec<String>,
    pub(crate) nfc: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DuoShown {
    /// `own` for the account's keys, `server` for the server's integration.
    pub(crate) integration: &'static str,
    /// The Duo host, when the account uses its own keys.
    pub(crate) host: Option<String>,
}

/// What the account has set up beyond the list: never a secret. The address, the public ids of
/// YubiKeys and the host of a Duo integration.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TwoStepSetupResponse {
    /// The address codes go to, when the method is on.
    pub(crate) email: Option<String>,
    pub(crate) yubikey: Option<YubikeyShown>,
    pub(crate) duo: Option<DuoShown>,
    /// Whether this server can mail a code.
    pub(crate) email_offered: bool,
    /// Whether this server can check a YubiKey OTP.
    pub(crate) yubikey_offered: bool,
    /// Whether this server has a Duo integration an account can use without keys of its own.
    pub(crate) duo_server_keys: bool,
}

fn two_step_of<S, P, K, R>(api: &Api<S, P, K>, runtime: &TwoStepRuntime<R>) -> TwoStep<S, P, P, R>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    step(api, runtime).two_step
}

/// Replacing a method that is on is removing it (with a fresh proof) and then adding it, so
/// asking for it again is refused (409): a stolen session can't swap a Duo integration, a YubiKey
/// id or an address for ones it controls.
async fn refuse_if_on<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    method: TwoFactorMethod,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let own = TwoFactorRepo::list(&api.store, user)
        .await
        .map_err(AppError::from)?
        .iter()
        .any(|row| row.enabled && row.method == method);
    if own {
        return Err(AppError::Duplicate.into());
    }
    Ok(())
}

/// The methods that are on, and whether `own` is one of them.
async fn methods_on<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
) -> Result<Vec<TwoFactorMethod>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    Ok(TwoFactorRepo::list(&api.store, user)
        .await
        .map_err(AppError::from)?
        .into_iter()
        .filter(|row| row.enabled)
        .map(|row| row.method)
        .collect())
}

const PROOF_NEEDED: &str = "a fresh proof is needed to add a second step beside one that is on";

/// Turning on the first second step takes no proof (there is none to give), so a session alone
/// could do it: it asks for a sign-in from the last 15 minutes instead. With a step already on,
/// the fresh proof of [`require_proof_to_add`] is what asks.
pub(crate) async fn require_fresh_for_first_step<S, P, K>(
    api: &Api<S, P, K>,
    authed: &Authed,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    if methods_on(api, authed.actor.user).await?.is_empty() {
        authed.require_fresh_sign_in(api.now())?;
    }
    Ok(())
}

/// What lets a method be turned on. With no method on, a session alone may add the first step.
/// With one or more on, the request must carry a fresh proof, the one a removal takes (a mailed
/// code, a current code of the authenticator app, or the recovery code), so a stolen session
/// can't add a step it controls beside the owner's. `own`, when it is on, is refused first (409).
///
/// Call it after the request is checked and last before the change: a proof is spent here.
pub(crate) async fn require_proof_to_add<S, P, K, R>(
    api: &Api<S, P, K>,
    steps: &TwoStep<S, P, P, R>,
    user: kemlock_domain::UserId,
    own: Option<TwoFactorMethod>,
    proof: Option<&FreshProof>,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let on = methods_on(api, user).await?;
    if on.is_empty() {
        return Ok(());
    }
    if own.is_some_and(|method| on.contains(&method)) {
        return Err(AppError::Duplicate.into());
    }
    let proof = proof
        .filter(|p| !p.is_blank())
        .ok_or(AppError::Invalid(PROOF_NEEDED))?;
    require_proof(api, steps, user, proof).await
}

/// How a route on the main router checks a mailed proof: [`two_step_router`] registers the store of
/// codes it holds with the API state.
pub(crate) trait MailedProof: std::fmt::Debug + Send + Sync {
    fn check(
        &self,
        user: kemlock_domain::UserId,
        proof: FreshProof,
        recovery: bool,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<(), Problem>>;
}

/// How a route checks a security key's or passkey's answer as a proof: [`passkeys_router`]
/// registers the relying party and the stored keys with the API state, as [`two_step_router`] does
/// the mailed codes.
///
/// [`passkeys_router`]: super::passkeys::passkeys_router
pub(crate) trait AssertionChecker: std::fmt::Debug + Send + Sync {
    /// The request options for the account's security keys and passkeys; `NotFound` with none.
    fn options(
        &self,
        user: kemlock_domain::UserId,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<serde_json::Value, Problem>>;

    /// Whether the answer proves it (the challenge is spent whatever it is).
    fn verify(
        &self,
        user: kemlock_domain::UserId,
        response: Vec<u8>,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<(), kemlock_app::passkeys::SecurityKeyError>>;
}

/// Checks the answer of a security key or passkey as a proof. A refused answer counts against the
/// account like a wrong code.
async fn check_assertion<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    assertion: &crate::dto::KeyAssertion,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let Some(checker) = api.assertions.get() else {
        return Err(AppError::Invalid("this server can't check a security key proof").into());
    };
    let response = serde_json::to_vec(&assertion.webauthn)
        .map_err(|_| AppError::Invalid("the security key's answer isn't valid"))?;
    // Reserved before the answer is looked at; only a right answer gives the attempt back.
    attempts::reserve_step_up(api, user, api.now()).await?;
    match checker.verify(user, response).await {
        Ok(()) => {
            attempts::forget_step_up(api, user).await;
            Ok(())
        }
        Err(kemlock_app::passkeys::SecurityKeyError::NoChallenge) => Err(AppError::Invalid(
            "no security key proof is in progress, or it expired: ask for options again",
        )
        .into()),
        Err(kemlock_app::passkeys::SecurityKeyError::Refused) => {
            Err(AppError::Invalid("the security key's answer wasn't accepted").into())
        }
        Err(other) => Err(AppError::from(other).into()),
    }
}

struct Mailed<S, P, K, R> {
    api: std::sync::Weak<crate::state::Inner<S, P, K>>,
    challenges: R,
}

impl<S, P, K, R> std::fmt::Debug for Mailed<S, P, K, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailed").finish_non_exhaustive()
    }
}

impl<S, P, K, R> MailedProof for Mailed<S, P, K, R>
where
    S: Store + Send + Sync,
    P: Crypto + Send + Sync,
    K: TokenSigner + Clone + Send + Sync + 'static,
    R: ChallengeRepo + Clone + Send + Sync + 'static,
{
    fn check(
        &self,
        user: kemlock_domain::UserId,
        proof: FreshProof,
        recovery: bool,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<(), Problem>> {
        Box::pin(async move {
            let Some(api) = Api::upgrade(&self.api) else {
                return Err(AppError::Unauthorized.into());
            };
            let steps = proof_steps(&api, self.challenges.clone());
            check_proof(&api, &steps, user, &proof, recovery).await
        })
    }
}

/// Checks a proof from a route that has no store of mailed codes of its own: through the one
/// [`two_step_router`] registered when it is merged, else only an authenticator code (and the
/// recovery code, when `recovery`) proves it.
pub(crate) async fn require_proof_via_api<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    proof: &FreshProof,
    recovery: bool,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    if let Some(mailed) = api.proofs.get() {
        return mailed.check(user, proof.clone(), recovery).await;
    }
    let proof = match proof {
        FreshProof::Code(code) => code.as_str(),
        FreshProof::Assertion(assertion) => return check_assertion(api, user, assertion).await,
    };
    // Reserved before the code is looked at; only a right code gives the attempt back.
    attempts::reserve_step_up(api, user, api.now()).await?;
    if second_step_proof(api, user, proof, recovery).await {
        attempts::forget_step_up(api, user).await;
        return Ok(());
    }
    Err(AppError::Invalid("the code is wrong or has run out: ask for another").into())
}

/// [`require_proof_to_add`] for the authenticator app, which is confirmed on the main router.
pub(crate) async fn require_proof_to_add_via_api<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    own: Option<TwoFactorMethod>,
    proof: Option<&FreshProof>,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let on = methods_on(api, user).await?;
    if on.is_empty() {
        return Ok(());
    }
    if own.is_some_and(|method| on.contains(&method)) {
        return Err(AppError::Duplicate.into());
    }
    let proof = proof
        .filter(|p| !p.is_blank())
        .ok_or(AppError::Invalid(PROOF_NEEDED))?;
    require_proof_via_api(api, user, proof, true).await
}

/// Showing the recovery code takes a proof that is not the recovery code.
pub(crate) async fn require_proof_for_recovery_code<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    proof: Option<&FreshProof>,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let proof = proof.filter(|p| !p.is_blank()).ok_or(AppError::Invalid(
        "a fresh proof is needed to show the recovery code",
    ))?;
    require_proof_via_api(api, user, proof, false).await
}

fn limit_setup<S, P, K>(api: &Api<S, P, K>, authed: &Authed, what: &str) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
    guard(
        &api.limits.sign_in,
        &format!("{what}:{}", authed.actor.user),
        now,
    )
}

/// What proves it is the account's owner at a keyboard who turns a second step off, not only a
/// session: the one-time code mailed by `POST /kem/v1/account/two-factor/proof`, as Vaultwarden
/// takes a mailed code for the master password (`PasswordOrOtpData`).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProofRequest {
    /// The code that was mailed (it works once), a current code of the authenticator app, the
    /// recovery code where the route takes it, or `{"webauthn": ...}`, the answer of a security key
    /// or passkey to the options at `POST /kem/v1/account/two-factor/proof/webauthn/options`.
    pub(crate) proof: FreshProof,
}

fn proof_error(e: ProtectedError) -> Problem {
    match e {
        ProtectedError::App(error) => error.into(),
        ProtectedError::Disabled => AppError::Invalid("this server can't mail a code").into(),
        ProtectedError::Wait(_) => AppError::Invalid(
            "a code was sent a moment ago: wait 30 seconds before asking for another",
        )
        .into(),
        _ => AppError::Invalid("the code is wrong or has run out: ask for another").into(),
    }
}

/// The steps a proof is checked with where the router holds no [`TwoStepRuntime`] (the security
/// keys'): the code's state is the same, the limits are the defaults.
pub(crate) fn proof_steps<S, P, K, R>(api: &Api<S, P, K>, challenges: R) -> TwoStep<S, P, P, R>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    TwoStep {
        two_factor: api.store.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        challenges,
        notices: Notices::default(),
        yubico: Arc::new(NoYubico),
        duo: Arc::new(NoDuo),
        settings: TwoStepSettings::default(),
    }
}

/// Whether `proof` is a current, unused code of the account's authenticator app (spent by this
/// call), or, when `recovery`, the account's recovery code (kept, not spent: it is a proof here,
/// not a recovery). Reading the recovery code itself must not accept the recovery code.
async fn second_step_proof<S, P, K>(
    api: &Api<S, P, K>,
    user: kemlock_domain::UserId,
    proof: &str,
    recovery: bool,
) -> bool
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let entered = proof.replace(' ', "");
    if entered.is_empty() {
        return false;
    }
    if let Ok(factors) = TwoFactorRepo::list(&api.store, user).await {
        let totp = factors
            .into_iter()
            .find(|f| f.method == TwoFactorMethod::Totp && f.enabled);
        if let Some(factor) = totp
            && let Ok(secret) = kemlock_app::sealed::open_bound(
                &api.crypto,
                kemlock_app::sealed::PURPOSE_TOTP,
                user,
                &factor.sealed_secret,
            )
            && let Some(step) = u64::try_from(api.now())
                .ok()
                .and_then(|now| kemlock_crypto::totp::verify_step(&secret.value, &entered, now))
        {
            // A code works once, as at sign-in: the step is kept per account, so a code seen
            // over a shoulder or in a log proves nothing for the rest of its window.
            if TwoFactorRepo::accept_totp_step(&api.store, user, step)
                .await
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    if recovery && let Ok(Some(held)) = api.recovery_codes().show(user).await {
        return hash::ct_eq(
            entered.to_lowercase().as_bytes(),
            held.to_lowercase().as_bytes(),
        );
    }
    false
}

/// Checks the proof, and uses a mailed code up. A wrong proof counts against the account.
pub(crate) async fn require_proof<S, P, K, R>(
    api: &Api<S, P, K>,
    steps: &TwoStep<S, P, P, R>,
    user: kemlock_domain::UserId,
    proof: &FreshProof,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    check_proof(api, steps, user, proof, true).await
}

/// [`require_proof`], with the recovery code accepted or not (`recovery`).
async fn check_proof<S, P, K, R>(
    api: &Api<S, P, K>,
    steps: &TwoStep<S, P, P, R>,
    user: kemlock_domain::UserId,
    proof: &FreshProof,
    recovery: bool,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let code = match proof {
        FreshProof::Code(code) => code.trim(),
        FreshProof::Assertion(assertion) => return check_assertion(api, user, assertion).await,
    };
    // Reserved before the code is looked at; only a right code gives the attempt back.
    attempts::reserve_step_up(api, user, api.now()).await?;
    // Without mail, a current code of the authenticator app or the account's recovery code proves
    // it just as well. A TOTP code is spent here (it works once); the recovery code is kept. Neither
    // needs the mail to work.
    if second_step_proof(api, user, code, recovery).await {
        attempts::forget_step_up(api, user).await;
        return Ok(());
    }
    match steps.protected_validate(user, code, true).await {
        Ok(()) => {
            attempts::forget_step_up(api, user).await;
            Ok(())
        }
        Err(error) => Err(proof_error(error)),
    }
}

/// `POST /kem/v1/account/two-factor/proof`: mails the code that proves the owner, for turning a
/// second step off.
async fn handle_proof_request<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    limit_setup(&api, &authed, "proof")?;
    let user = api
        .store
        .by_id(authed.actor.user)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;
    two_step_of(&api, &runtime)
        .protected_request(&user)
        .await
        .map_err(proof_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Records that a second step was turned on or off, or a passkey added or removed (`method` is
/// `"passkey"`), and tells the owner by mail. Neither can fail the call: what they describe has
/// happened.
pub(crate) async fn announce_change<S, P, K>(
    api: &Api<S, P, K>,
    authed: &Authed,
    method: &'static str,
    on: bool,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let sessions = api.sessions();
    sessions
        .record(
            match (method, on) {
                ("passkey", true) => "account.passkey_added",
                ("passkey", false) => "account.passkey_removed",
                (_, true) => "account.two_step_added",
                (_, false) => "account.two_step_removed",
            },
            authed.actor.user,
            Some(authed.actor.device),
        )
        .await;
    if let Ok(Some(user)) = api.store.by_id(authed.actor.user).await {
        api.hub
            .notices()
            .send(Notice::TwoStepChanged(TwoStepChangedNotice {
                to: user.email,
                at: Clock::now(&sessions.env),
                method,
                on,
            }))
            .await;
    }
}

/// `GET /kem/v1/account/two-step/setup`.
async fn handle_setup_show<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
) -> Result<Json<TwoStepSetupResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    limit_setup(&api, &authed, "two-step-setup")?;
    let user = authed.actor.user;
    let steps = two_step_of(&api, &runtime);
    let email = steps.email_address(user).await?;
    let yubikey = steps.yubikey_keys(user).await?.map(|data| YubikeyShown {
        keys: data.keys,
        nfc: data.nfc,
    });
    let duo = match steps.duo_status(user).await? {
        DuoStatus::Global(_) => Some(DuoShown {
            integration: "server",
            host: None,
        }),
        DuoStatus::User(keys) => Some(DuoShown {
            integration: "own",
            host: Some(keys.host),
        }),
        DuoStatus::Disabled { .. } => None,
    };
    Ok(Json(TwoStepSetupResponse {
        email,
        yubikey,
        duo,
        email_offered: runtime.settings.email_enabled,
        yubikey_offered: runtime.settings.yubico_enabled,
        duo_server_keys: runtime.settings.duo_global.is_some(),
    }))
}

/// `POST /kem/v1/account/two-factor/email`: mails a first code to the address.
async fn handle_email_begin<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: EmailBeginRequest = body.json()?;
    limit_setup(&api, &authed, "email-setup")?;
    // Mailing a code turns nothing on: the proof is asked for when the code is entered.
    refuse_if_on(&api, authed.actor.user, TwoFactorMethod::Email).await?;
    // Each code mailed counts, 5 in 15 minutes: the route can't be used to fill a mailbox.
    let issued = format!("email-setup-codes:{}", authed.actor.user);
    api.limits
        .second_step
        .reserve(&issued, api.now())
        .map_err(rate_limited)?;
    two_step_of(&api, &runtime)
        .email_begin(authed.actor.user, &request.address)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /kem/v1/account/two-factor/email/confirm`: turns the method on with the mailed code.
async fn handle_email_confirm<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: EmailConfirmRequest = body.json()?;
    limit_setup(&api, &authed, "email-setup")?;
    require_fresh_for_first_step(&api, &authed).await?;
    // The setup code is checked first, then the proof is spent, then the method is turned on. A
    // refused proof puts the right setup code back, so it needn't be mailed again.
    let steps = two_step_of(&api, &runtime);
    let checked = steps
        .email_check(authed.actor.user, &request.address, &request.code)
        .await?;
    if let Err(refused) = require_proof_to_add(
        &api,
        &steps,
        authed.actor.user,
        Some(TwoFactorMethod::Email),
        request.proof.as_ref(),
    )
    .await
    {
        steps.email_retry(authed.actor.user, &checked).await?;
        return Err(refused);
    }
    steps.email_store(authed.actor.user, checked).await?;
    api.recovery_codes().ensure(authed.actor.user).await?;
    announce_change(&api, &authed, "email", true).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /kem/v1/account/two-factor/email`.
async fn handle_email_off<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    limit_setup(&api, &authed, "email-setup")?;
    let request: ProofRequest = body.json()?;
    require_proof(
        &api,
        &two_step_of(&api, &runtime),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    two_step_of(&api, &runtime)
        .email_disable(authed.actor.user)
        .await?;
    announce_change(&api, &authed, "email", false).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /kem/v1/account/two-factor/yubikey`: the account's keys, replacing any it had.
async fn handle_yubikey_set<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<YubikeyShown>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: YubikeySetRequest = body.json()?;
    limit_setup(&api, &authed, "yubikey-setup")?;
    require_fresh_for_first_step(&api, &authed).await?;
    if request.otps.iter().all(|otp| otp.trim().is_empty()) {
        return Err(AppError::Invalid("A key is required.").into());
    }
    // Yubico checks the OTPs first, then the proof is spent, then the keys are stored.
    let steps = two_step_of(&api, &runtime);
    let checked = steps.yubikey_check(&request.otps, request.nfc).await?;
    require_proof_to_add(
        &api,
        &steps,
        authed.actor.user,
        Some(TwoFactorMethod::YubiKey),
        request.proof.as_ref(),
    )
    .await?;
    let data = steps.yubikey_store(authed.actor.user, checked).await?;
    api.recovery_codes().ensure(authed.actor.user).await?;
    announce_change(&api, &authed, "yubikey", true).await;
    Ok(Json(YubikeyShown {
        keys: data.keys,
        nfc: data.nfc,
    }))
}

/// `DELETE /kem/v1/account/two-factor/yubikey`: the method and all its keys.
async fn handle_yubikey_off<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    limit_setup(&api, &authed, "yubikey-setup")?;
    let request: ProofRequest = body.json()?;
    require_proof(
        &api,
        &two_step_of(&api, &runtime),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    two_step_of(&api, &runtime)
        .yubikey_remove(authed.actor.user)
        .await?;
    announce_change(&api, &authed, "yubikey", false).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /kem/v1/account/two-factor/duo`: Duo on, with the keys given (checked with Duo) or the
/// server's.
async fn handle_duo_set<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<DuoShown>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    let request: DuoSetRequest = body.json()?;
    limit_setup(&api, &authed, "duo-setup")?;
    require_fresh_for_first_step(&api, &authed).await?;
    let custom = match (request.host, request.client_id, request.client_secret) {
        (None, None, None) => None,
        (host, ik, sk) => Some(DuoKeys {
            host: host.unwrap_or_default(),
            ik: ik.unwrap_or_default(),
            sk: sk.unwrap_or_default(),
        }),
    };
    // Duo checks the keys first, then the proof is spent, then the method is turned on.
    let steps = two_step_of(&api, &runtime);
    let plain = steps.duo_check(custom.as_ref()).await?;
    require_proof_to_add(
        &api,
        &steps,
        authed.actor.user,
        Some(TwoFactorMethod::Duo),
        request.proof.as_ref(),
    )
    .await?;
    let status = steps.duo_store(authed.actor.user, &plain).await?;
    api.recovery_codes().ensure(authed.actor.user).await?;
    announce_change(&api, &authed, "duo", true).await;
    Ok(Json(match status {
        DuoStatus::User(keys) => DuoShown {
            integration: "own",
            host: Some(keys.host),
        },
        _ => DuoShown {
            integration: "server",
            host: None,
        },
    }))
}

/// `DELETE /kem/v1/account/two-factor/duo`.
async fn handle_duo_off<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<TwoStepRuntime<R>>>,
    authed: Authed,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ChallengeRepo + Clone + 'static,
{
    limit_setup(&api, &authed, "duo-setup")?;
    let request: ProofRequest = body.json()?;
    require_proof(
        &api,
        &two_step_of(&api, &runtime),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    two_step_of(&api, &runtime)
        .duo_remove(authed.actor.user)
        .await?;
    announce_change(&api, &authed, "duo", false).await;
    Ok(StatusCode::NO_CONTENT)
}

/// The same `DPoP-Nonce` header every other `/kem/v1` response carries.
pub(crate) async fn nonce_header<S, P, K>(
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
    S: Store + Send + Sync,
    P: Crypto + Send + Sync,
    K: TokenSigner + Clone + Send + Sync + 'static,
    R: ChallengeRepo + Clone + Send + Sync + 'static,
{
    // The authenticator app and the recovery code are on the main router, which has no store of
    // mailed codes: they check one through this.
    let _ = api.proofs.set(Arc::new(Mailed {
        api: api.downgrade(),
        challenges: runtime.challenges.clone(),
    }));
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
        .route(
            "/kem/v1/account/two-step/setup",
            get(handle_setup_show::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/two-factor/proof",
            post(handle_proof_request::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/two-factor/email",
            post(handle_email_begin::<S, P, K, R>).delete(handle_email_off::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/two-factor/email/confirm",
            post(handle_email_confirm::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/two-factor/yubikey",
            put(handle_yubikey_set::<S, P, K, R>).delete(handle_yubikey_off::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/two-factor/duo",
            put(handle_duo_set::<S, P, K, R>).delete(handle_duo_off::<S, P, K, R>),
        )
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

#[utoipa::path(
    get, path = "/kem/v1/account/two-step/setup", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "What the account set up: the address, the YubiKey ids, the Duo integration, and what the server offers", body = TwoStepSetupResponse),
        (status = 401, description = "No valid access token", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_setup_show() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/email", tag = "account",
    security(("dpop" = [])),
    request_body = EmailBeginRequest,
    responses(
        (status = 204, description = "A first code was mailed to the address"),
        (status = 400, description = "Not an address, or the server can't mail codes", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The email method is on already: remove it (with a proof), then add it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_email_begin() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/email/confirm", tag = "account",
    security(("dpop" = [])),
    request_body = EmailConfirmRequest,
    responses(
        (status = 204, description = "The method is on. With another second step on, the request carries a fresh `proof` (a mailed code, a current code of the authenticator app, or the recovery code)"),
        (status = 400, description = "A second step is on and no proof came, or the proof is wrong or has run out", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The email method is on already", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong address or code", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_email_confirm() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/proof", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 204, description = "A one-time code was mailed to the account's address"),
        (status = 400, description = "The server can't mail, or a code was sent a moment ago", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_proof_request() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/two-factor/email", tag = "account",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses((status = 204, description = "The method is off"))
)]
#[allow(dead_code)]
fn doc_email_off() {}

#[utoipa::path(
    put, path = "/kem/v1/account/two-factor/yubikey", tag = "account",
    security(("dpop" = [])),
    request_body = YubikeySetRequest,
    responses(
        (status = 200, description = "The keys, replacing any the account had", body = YubikeyShown),
        (status = 400, description = "An OTP Yubico did not accept, Yubico is not set up, or a second step is on and the fresh proof is missing or wrong", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The YubiKey method is on already: remove it (with a proof), then add it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_yubikey_set() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/two-factor/yubikey", tag = "account",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses((status = 204, description = "The method and its keys are gone"))
)]
#[allow(dead_code)]
fn doc_yubikey_off() {}

#[utoipa::path(
    put, path = "/kem/v1/account/two-factor/duo", tag = "account",
    security(("dpop" = [])),
    request_body = DuoSetRequest,
    responses(
        (status = 200, description = "Duo is on", body = DuoShown),
        (status = 400, description = "Keys Duo did not accept, no server keys to use, or a second step is on and the fresh proof is missing or wrong", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The Duo method is on already: remove it (with a proof), then add it", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_duo_set() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/two-factor/duo", tag = "account",
    security(("dpop" = [])),
    request_body = ProofRequest,
    responses((status = 204, description = "The method is off"))
)]
#[allow(dead_code)]
fn doc_duo_off() {}

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
        doc_list,
        doc_setup_show,
        doc_proof_request,
        doc_email_begin,
        doc_email_confirm,
        doc_email_off,
        doc_yubikey_set,
        doc_yubikey_off,
        doc_duo_set,
        doc_duo_off
    ),
    components(schemas(
        ProblemDoc,
        StepChallengeRequest,
        DuoStartResponse,
        StepCodeRequest,
        TwoStepMethodEntry,
        TwoStepListResponse,
        TokenResponse,
        TwoStepSetupResponse,
        ProofRequest,
        crate::dto::FreshProof,
        crate::dto::KeyAssertion,
        YubikeyShown,
        DuoShown,
        EmailBeginRequest,
        EmailConfirmRequest,
        YubikeySetRequest,
        DuoSetRequest
    ))
)]
pub struct TwoStepApiDoc;
