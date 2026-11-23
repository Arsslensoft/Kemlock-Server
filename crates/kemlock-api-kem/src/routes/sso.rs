//! Single sign-on: `POST /kem/v1/auth/sso/start`, `GET /kem/v1/auth/sso/callback`,
//! `POST /kem/v1/auth/sso/finish` and `POST /kem/v1/auth/sso/backchannel-logout`.
//!
//! The flow is the Kemlock app's plan (decision 9 of `add-kemlock-server-sync`): the phone sends
//! a PKCE challenge, a state of its own and a DPoP proof to `start` and opens the provider's
//! address in the system browser; the provider redirects to `callback`, which ends the browser's
//! trip at `kemlock://sso` with a one-time code; the phone sends the code, its PKCE verifier and a
//! DPoP proof to `finish` and gets the same tokens a password sign-in gives. SSO never hands out
//! a vault key.
//!
//! The router needs ports the rest of the API doesn't, so it is built apart, from the API state
//! and an [`SsoRuntime`], and merged into the main router by the server: see [`sso_router`].

use super::guard;
use super::new_device::announce;
use crate::dto::{DeviceDto, TokenResponse};
use crate::extract::{Body, ClientIp, DPOP_NONCE, Proof};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::{Limiter, ip_key};
use crate::signlog::signed_in_ids;
use crate::state::{Api, Crypto, Store};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use kemlock_app::ports::{TokenSigner, TwoFactorMethod};
use kemlock_app::sso::config::APP_REDIRECT;
use kemlock_app::sso::{
    CallbackInput, FinishInput, GroupSync, OidcProvider, SsoCallback, SsoConfig, SsoError,
    SsoFinish, SsoLogout, SsoRepos, SsoStart, StartInput,
};
use kemlock_app::{Sessions, SignedIn, TokenPair};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};

/// How many back-channel logout posts one address may make in a minute. A provider posts one per
/// ended session, from one address.
const LOGOUT_PER_MINUTE: u32 = 120;

/// The ports SSO needs beyond the rest of the API: the SSO repositories, the OpenID Connect
/// provider and the spaces' group mapping.
#[derive(Debug)]
pub struct SsoRuntime<R, O, G> {
    pub repos: R,
    pub provider: O,
    pub groups: G,
    logout_limit: Limiter,
}

impl<R, O, G> SsoRuntime<R, O, G> {
    pub fn new(repos: R, provider: O, groups: G) -> Self {
        SsoRuntime {
            repos,
            provider,
            groups,
            logout_limit: Limiter::new(LOGOUT_PER_MINUTE, 60),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Bodies

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartRequest {
    /// The unpadded base64url SHA-256 of a PKCE verifier the device keeps.
    pub challenge: String,
    /// The device's own `state`: 16 to 256 URL-safe characters, handed back on the redirect.
    pub state: String,
    /// Where the browser trip ends: `kemlock://sso` (the default), or a path on this server.
    pub redirect: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartResponse {
    /// Open this in the system browser.
    pub authorization_url: String,
    /// What the provider is called, for the sign-in sheet.
    pub provider_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinishRequest {
    /// The one-time code from the redirect.
    pub code: String,
    /// The PKCE verifier whose SHA-256 was sent to `start`.
    pub verifier: String,
    pub device: DeviceDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FinishResponse {
    /// `"signed_in"` or `"two_factor_required"`.
    pub status: String,
    pub tokens: Option<TokenResponse>,
    /// With `two_factor_required`: send it to `/auth/two-factor` with the code.
    pub challenge: Option<String>,
    /// With `two_factor_required`: the account's methods, such as `"totp"`.
    pub methods: Option<Vec<String>>,
    /// This sign-in made the account. Its device makes its keys now.
    pub new_account: bool,
    /// The provider did multi-factor authentication, so Kemlock's own second step was skipped:
    /// show "Via SSO".
    pub mfa_via_sso: bool,
}

// ---------------------------------------------------------------------------------------------
// Errors

impl From<SsoError> for Problem {
    fn from(e: SsoError) -> Self {
        let forbidden = |slug: &'static str, title: &'static str| {
            Problem::new(StatusCode::FORBIDDEN, slug, title)
        };
        match e {
            SsoError::NotConfigured => Problem::new(
                StatusCode::NOT_FOUND,
                "sso-not-configured",
                "Single sign-on isn't set up",
            ),
            SsoError::Invalid(why) => Problem::bad_request(why),
            SsoError::BadState => Problem::new(
                StatusCode::BAD_REQUEST,
                "sso-state-invalid",
                "The sign-in has expired or isn't valid",
            )
            .detail("Start the sign-in again."),
            SsoError::Provider(message) => {
                tracing::warn!(%message, "the identity provider failed");
                Problem::new(
                    StatusCode::BAD_GATEWAY,
                    "sso-provider-failed",
                    "The identity provider couldn't complete the sign-in",
                )
            }
            SsoError::Token(message) => {
                tracing::warn!(%message, "a token from the identity provider was refused");
                Problem::new(
                    StatusCode::UNAUTHORIZED,
                    "sso-token-refused",
                    "The identity provider's token was refused",
                )
            }
            SsoError::EmailNotVerified => forbidden(
                "sso-email-not-verified",
                "The identity provider hasn't verified this email address",
            ),
            SsoError::DomainNotVerified => forbidden(
                "sso-domain-not-verified",
                "This email address's domain hasn't been proven by DNS",
            ),
            SsoError::LinkingNotAllowed => forbidden(
                "sso-linking-off",
                "An account with this email exists and linking by email is off",
            ),
            SsoError::NoAccount => forbidden(
                "sso-no-account",
                "There is no account for this sign-in, and accounts aren't made automatically",
            ),
            SsoError::SsoRequired { space } => forbidden(
                "sso-required",
                "A space this account belongs to requires single sign-on",
            )
            .with("spaceId", json!(space.to_string())),
            SsoError::Unauthorized => Problem::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "The credentials are wrong or have expired",
            ),
            SsoError::DomainProofMissing => Problem::new(
                StatusCode::CONFLICT,
                "domain-proof-missing",
                "The DNS record isn't there yet",
            ),
            SsoError::App(e) => Problem::from(e),
        }
    }
}

fn token_response(tokens: &TokenPair, now: i64) -> TokenResponse {
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

fn method_name(method: TwoFactorMethod) -> &'static str {
    method.as_str()
}

// ---------------------------------------------------------------------------------------------
// Handlers

fn config<S: Store, P: Crypto, K: TokenSigner + Clone + 'static>(api: &Api<S, P, K>) -> SsoConfig {
    SsoConfig::new(&api.config.domain)
}

/// `POST /kem/v1/auth/sso/start`: the provider's address for a device to open in the system
/// browser, with a state bound to the device's DPoP key and PKCE challenge.
async fn handle_start<S, P, K, R, O, G>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<SsoRuntime<R, O, G>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<StartResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SsoRepos,
    O: OidcProvider + Clone + 'static,
    G: GroupSync + Clone + 'static,
{
    let request: StartRequest = body.json()?;
    guard(&api.limits.sign_in, &ip_key(proof.ip), api.now())?;
    let started = SsoStart {
        repos: runtime.repos.clone(),
        provider: runtime.provider.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        config: config(&api),
    }
    .execute(StartInput {
        challenge: request.challenge,
        app_state: request.state,
        redirect: request.redirect.unwrap_or_else(|| APP_REDIRECT.to_owned()),
        jkt: proof.jkt,
    })
    .await?;
    Ok(Json(StartResponse {
        authorization_url: started.authorization_url,
        provider_name: started.provider_name,
    }))
}

/// `GET /kem/v1/auth/sso/callback`: where the provider sends the browser. Redirects on to the
/// app with a one-time code (or the provider's error); it signs nobody in.
async fn handle_callback<S, P, K>(
    State(api): State<Api<S, P, K>>,
    ClientIp(ip): ClientIp,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(ip), api.now())?;
    let Query(query) = query.map_err(|_| Problem::bad_request("the query string isn't valid"))?;
    let redirect = SsoCallback {
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        config: config(&api),
    }
    .execute(CallbackInput {
        state: query.get("state").cloned().unwrap_or_default(),
        code: query.get("code").cloned(),
        error: query.get("error").cloned(),
    })?;
    let location = HeaderValue::from_str(&redirect)
        .map_err(|_| Problem::bad_request("the redirect isn't valid"))?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, location);
    // The code is in the URL: keep it out of caches and referrers.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}

/// `POST /kem/v1/auth/sso/finish`: exchanges the one-time code, with the PKCE verifier and the
/// device's DPoP key, for tokens, or for the second step the account owes.
async fn handle_finish<S, P, K, R, O, G>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<SsoRuntime<R, O, G>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<FinishResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SsoRepos,
    O: OidcProvider + Clone + 'static,
    G: GroupSync + Clone + 'static,
{
    let request: FinishRequest = body.json()?;
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(proof.ip), now)?;
    let finished = SsoFinish {
        users: api.store.clone(),
        two_factor: api.store.clone(),
        repos: runtime.repos.clone(),
        provider: runtime.provider.clone(),
        groups: runtime.groups.clone(),
        seal: api.crypto.clone(),
        sessions: Sessions {
            devices: api.store.clone(),
            tokens: api.store.clone(),
            signer: api.signer.clone(),
            env: api.crypto.clone(),
            events: api.store.clone(),
            two_factor: api.store.clone(),
            config: api.config.auth,
        },
        config: config(&api),
    }
    .execute(FinishInput {
        code: request.code,
        verifier: request.verifier,
        device: request.device.into_info()?,
        jkt: proof.jkt,
    })
    .await;
    api.log_attempt(api.attempt("sso", None, &finished, proof.ip, |signed| {
        signed_in_ids(&signed.outcome)
    }))
    .await;
    let signed_in = finished?;
    let (new_account, mfa_via_sso) = (signed_in.new_account, signed_in.mfa_via_sso);
    if let SignedIn::Tokens(tokens) = &signed_in.outcome {
        announce(&api, tokens, proof.ip).await;
    }
    Ok(Json(match signed_in.outcome {
        SignedIn::Tokens(tokens) => FinishResponse {
            status: "signed_in".to_owned(),
            tokens: Some(token_response(&tokens, now)),
            challenge: None,
            methods: None,
            new_account,
            mfa_via_sso,
        },
        SignedIn::SecondStep(step) => FinishResponse {
            status: "two_factor_required".to_owned(),
            tokens: None,
            challenge: Some(kemlock_app::b64url::encode(&step.challenge)),
            methods: Some(
                step.methods
                    .into_iter()
                    .map(|m| method_name(m).to_owned())
                    .collect(),
            ),
            new_account,
            mfa_via_sso,
        },
    }))
}

/// `POST /kem/v1/auth/sso/backchannel-logout`: the provider tells the server a person's session
/// there ended (OpenID Connect Back-Channel Logout 1.0). The form body's `logout_token` is signed
/// by the provider and checked against its keys; there is no DPoP here, the token is the
/// authentication. Answers 200 when it was valid, 400 when it wasn't.
async fn handle_backchannel_logout<S, P, K, R, O, G>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<SsoRuntime<R, O, G>>>,
    ClientIp(ip): ClientIp,
    body: Body,
) -> Result<Response, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SsoRepos,
    O: OidcProvider + Clone + 'static,
    G: GroupSync + Clone + 'static,
{
    guard(&runtime.logout_limit, &ip_key(ip), api.now())?;
    let invalid = |why: &str| {
        Problem::bad_request(why.to_owned())
            .with("error", json!("invalid_request"))
            .with("error_description", json!(why))
    };
    let token = url::form_urlencoded::parse(&body.0)
        .find(|(name, _)| name == "logout_token")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| invalid("logout_token is required"))?;
    SsoLogout {
        users: api.store.clone(),
        devices: api.store.clone(),
        tokens: api.store.clone(),
        repos: runtime.repos.clone(),
        provider: runtime.provider.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        events: api.store.clone(),
    }
    .execute(&token)
    .await
    .map_err(|e| match e {
        SsoError::Token(_) | SsoError::Invalid(_) => {
            tracing::warn!(error = %e, "a back-channel logout token was refused");
            invalid("the logout token isn't valid")
        }
        other => Problem::from(other),
    })?;
    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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

/// The four SSO routes. Merge the result into the main router:
///
/// ```ignore
/// router(api.clone()).merge(sso_router(api, SsoRuntime::new(repos, provider, groups)))
/// ```
pub fn sso_router<S, P, K, R, O, G>(api: Api<S, P, K>, runtime: SsoRuntime<R, O, G>) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SsoRepos,
    O: OidcProvider + Clone + 'static,
    G: GroupSync + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/auth/sso/start",
            post(handle_start::<S, P, K, R, O, G>),
        )
        .route("/kem/v1/auth/sso/callback", get(handle_callback::<S, P, K>))
        .route(
            "/kem/v1/auth/sso/finish",
            post(handle_finish::<S, P, K, R, O, G>),
        )
        .route(
            "/kem/v1/auth/sso/backchannel-logout",
            post(handle_backchannel_logout::<S, P, K, R, O, G>),
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
    post, path = "/kem/v1/auth/sso/start", tag = "sso",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    request_body = StartRequest,
    responses(
        (status = 200, description = "Where to open the system browser", body = StartResponse),
        (status = 404, description = "Single sign-on isn't set up", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 502, description = "The identity provider couldn't be reached", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sso_start() {}

#[utoipa::path(
    get, path = "/kem/v1/auth/sso/callback", tag = "sso",
    params(
        ("state" = String, Query, description = "The sealed state `start` sent to the provider"),
        ("code" = Option<String>, Query, description = "The provider's authorization code"),
        ("error" = Option<String>, Query, description = "The provider's error code, when sign-in failed"),
    ),
    responses(
        (status = 303, description = "Redirects to the app's redirect with `code` and `state`, or `error` and `state`"),
        (status = 400, description = "The state has expired or isn't valid", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sso_callback() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/sso/finish", tag = "sso",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that made `start`'s request")),
    request_body = FinishRequest,
    responses(
        (status = 200, description = "Signed in, or a second step is needed", body = FinishResponse),
        (status = 401, description = "The verifier or the device key isn't the one that started, or the provider's token was refused", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "The email isn't verified, or no account may be made", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sso_finish() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/sso/backchannel-logout", tag = "sso",
    request_body(content = String, description = "`logout_token=<JWT>`, form encoded", content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "The token was valid; the subject's sessions are revoked"),
        (status = 400, description = "The token isn't a valid logout token", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_sso_backchannel_logout() {}

/// The OpenAPI paths of the SSO routes, for the server to merge into `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_sso_start,
        doc_sso_callback,
        doc_sso_finish,
        doc_sso_backchannel_logout
    ),
    components(schemas(
        ProblemDoc,
        StartRequest,
        StartResponse,
        FinishRequest,
        FinishResponse,
        DeviceDto,
        TokenResponse
    ))
)]
pub struct SsoApiDoc;
