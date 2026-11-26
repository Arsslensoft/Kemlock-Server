//! The profile: the name, the master password and the sign-in address (docs/crypto.md, "Changing
//! the master password and the sign-in address").
//!
//! ```text
//! GET    /kem/v1/account/profile            name, address and what may change
//! PATCH  /kem/v1/account/profile            {name}
//! POST   /kem/v1/account/credentials/start  {request, email?}: OPAQUE registration, first message,
//!                                            answered with {response, ticket}
//! PUT    /kem/v1/account/password           the new password's records and the ticket, after the
//!                                            password again; answers {tokens}
//! POST   /kem/v1/account/email              a new address, its records and the ticket; mails the
//!                                            link to it
//! DELETE /kem/v1/account/email              takes that ask back
//! POST   /kem/v1/account/email/confirm      {token}: opens the link; no session needed
//! ```
//!
//! The browser makes everything secret: the root key stays, and is wrapped again under the new
//! master key, with a new OPAQUE record for the password (or for the new address, which OPAQUE
//! binds the record to). The server checks the password again before it writes, the way erasing
//! the account does (`reauth.rs`), and with a second step on a fresh proof of it beside the
//! password, as erasing does too; it validates what it can without opening anything, and writes the
//! records in one conditional step. The registration's ticket (sealed, from `credentials/start`)
//! binds it to the account, the DPoP key, the address and the next few minutes, and must come
//! back with the change. A new address takes effect only when the link mailed to it is opened, and
//! then every session ends; asking for one never says whether another account has it. A new
//! password with "Sign out my other devices" replaces the security stamp in the same write, so
//! every other session ends at once, and the device that asked gets new tokens in the answer. The
//! routes need the store of pending changes, so they have a router of their own: see
//! [`profile_router`].

use super::devices::token_response;
use super::guard;
use super::reauth::reauthenticate;
use super::two_step::{nonce_header, require_proof_via_api};
use crate::dto::{FreshProof, KdfDto, TokenResponse, decode};
use crate::extract::{Authed, Body, ClientIp};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router, middleware};
use kemlock_app::AppError;
use kemlock_app::devices::{KeyCopyRepo, SignOutDevice};
use kemlock_app::ports::{Event, EventLog, TokenSigner, TwoFactorRepo, UserRepo};
use kemlock_app::profile::{
    ConfirmEmailChange, Credentials, EmailChanges, NewCredentials, OtherDevices, Profile,
    ProfileError, ProfileRepo, ProfileView,
};
use kemlock_domain::{DeviceId, UserId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The store of pending changes of address and single sign-on links, `SqlStore` in the server.
struct Repos<R>(R);

// ---- problems ----

impl From<ProfileError> for Problem {
    fn from(e: ProfileError) -> Self {
        let forbidden = |slug, title| Problem::new(StatusCode::FORBIDDEN, slug, title);
        match e {
            ProfileError::SsoManaged => forbidden(
                "sso-managed",
                "The name and the address come from the identity provider",
            ),
            ProfileError::CompatibleAccount => forbidden(
                "compatible-account",
                "This account is shared with Bitwarden apps: change it there",
            ),
            ProfileError::NoPassword => {
                forbidden("no-password", "This account has no master password")
            }
            // Only opening a link says this: asking for an address never does.
            ProfileError::EmailTaken => Problem::new(
                StatusCode::CONFLICT,
                "email-taken",
                "That address belongs to another account",
            ),
            ProfileError::AccountChanged => Problem::new(
                StatusCode::CONFLICT,
                "account-changed",
                "The account changed while this was being saved: nothing was written, try again",
            ),
            ProfileError::EmailChangeInvalid => Problem::new(
                StatusCode::BAD_REQUEST,
                "email-change-invalid",
                "The link is not valid or has run out",
            ),
            ProfileError::MailOff => Problem::new(
                StatusCode::CONFLICT,
                "mail-off",
                "This server sends no mail, so a new address can't be checked",
            ),
            ProfileError::MailFailed => Problem::new(
                StatusCode::BAD_GATEWAY,
                "mail-failed",
                "The mail with the link could not be sent",
            ),
            ProfileError::App(e) => Problem::from(e),
        }
    }
}

// ---- wire types ----

/// The profile: what it holds and which parts may change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileDto {
    user_id: Uuid,
    /// The address the account signs in with.
    email: String,
    /// The display name, or null when the account has none.
    name: Option<String>,
    /// A single sign-on identity is linked: the name and the address are the identity provider's.
    sso: bool,
    /// The account has a master password to change.
    has_password: bool,
    /// The account is shared with the Bitwarden apps, which hold its password: it is changed there.
    compatible: bool,
    /// The address a link was mailed to, while it can still be opened.
    pending_email: Option<String>,
    /// The account has a second step on: changing the master password or the address asks a fresh
    /// proof of it (a code, a security key or a passkey) beside the password.
    two_step: bool,
}

impl ProfileDto {
    fn of(view: &ProfileView, two_step: bool) -> Self {
        Self {
            user_id: view.user.0,
            email: view.email.as_str().to_owned(),
            name: view.name.clone(),
            sso: view.sso,
            has_password: view.has_password,
            compatible: view.compatible,
            pending_email: view.pending_email.as_ref().map(|e| e.as_str().to_owned()),
            two_step,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RenameProfileRequest {
    /// The new name; blank clears it. At most 100 characters.
    name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialsStartRequest {
    /// OPAQUE's `RegistrationRequest`, base64url.
    request: String,
    /// The new address, when the registration is for one: the record is bound to it.
    email: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialsStartResponse {
    /// OPAQUE's `RegistrationResponse`, base64url.
    response: String,
    /// Binds the registration to the account, the DPoP key that asked, the address asked for (if
    /// any) and the next few minutes: base64url, opaque. `PUT /account/password` and
    /// `POST /account/email` need it back, with the last registration message made from
    /// `response`.
    ticket: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ChangePasswordRequest {
    /// What `POST /auth/opaque/start` answered, unread.
    login_state: String,
    /// The client's OPAQUE `CredentialFinalization`, with the current password.
    finalization: String,
    /// OPAQUE's `RegistrationUpload` for the new password, base64url.
    upload: String,
    /// The settings and salt of the new master key: the defaults and a new 16-byte salt.
    kdf: KdfDto,
    /// The root key wrapped under the new master key and export key, base64url, 92 bytes.
    wrapped_root_key: String,
    /// What `POST /account/credentials/start` answered as `ticket`, for a registration made with no
    /// `email`, unread.
    ticket: String,
    /// A fresh proof of the second step, needed beside the password when the account has one on:
    /// the code mailed by `POST /kem/v1/account/two-factor/proof`, a current code of the
    /// authenticator app, the recovery code, or a security key's or passkey's answer. Works once.
    proof: Option<FreshProof>,
    /// End the sessions of every other device at once, and get new tokens for this one in the
    /// answer. Defaults to false.
    #[serde(default)]
    sign_out_others: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangedPasswordDto {
    /// New tokens for the device that asked, bound to its DPoP key, present exactly when
    /// `signOutOthers` was true: the change replaced the security stamp, so the tokens it held
    /// stopped working with it. Null otherwise, and the tokens it holds go on.
    tokens: Option<TokenResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ChangeEmailRequest {
    /// The new sign-in address.
    email: String,
    /// What `POST /auth/opaque/start` answered, unread.
    login_state: String,
    /// The client's OPAQUE `CredentialFinalization`, with the current password.
    finalization: String,
    /// OPAQUE's `RegistrationUpload`, registered under the new address, base64url.
    upload: String,
    /// The settings and salt of the master key the record and the wrap were made with.
    kdf: KdfDto,
    /// The root key wrapped under that master key and the new record's export key, base64url.
    wrapped_root_key: String,
    /// What `POST /account/credentials/start` answered as `ticket` for this `email`, unread.
    ticket: String,
    /// A fresh proof of the second step, needed beside the password when the account has one on,
    /// of the same kinds as for changing the password. Works once.
    proof: Option<FreshProof>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailChangeAskedDto {
    /// The address the link was mailed to.
    pending_email: String,
    /// When the link runs out, RFC 3339.
    expires_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfirmEmailRequest {
    /// The token in the mailed link.
    token: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmedEmailDto {
    /// The address the account signs in with now.
    email: String,
}

// ---- wiring ----

fn profile<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> Profile<S, R, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    Profile {
        users: api.store.clone(),
        repo: repos.0.clone(),
        clock: api.crypto.clone(),
    }
}

fn credentials<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> Credentials<S, R, P, P, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    Credentials {
        users: api.store.clone(),
        repo: repos.0.clone(),
        auth: api.crypto.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        notices: api.hub.notices(),
        config: api.auth_config(),
    }
}

fn email_changes<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> EmailChanges<S, R, P, P, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    EmailChanges {
        users: api.store.clone(),
        repo: repos.0.clone(),
        auth: api.crypto.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        notices: api.hub.notices(),
        config: api.auth_config(),
    }
}

pub(super) fn other_devices<S, P, K>(api: &Api<S, P, K>) -> OtherDevices<S, S, S, K, P, S, S>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    OtherDevices {
        sign_out: SignOutDevice {
            devices: api.store.clone(),
            copies: api.store.clone(),
            tokens: api.store.clone(),
            clock: api.crypto.clone(),
            events: api.store.clone(),
        },
        sessions: api.sessions(),
    }
}

fn confirm<S, P, K, R>(api: &Api<S, P, K>, repos: &Repos<R>) -> ConfirmEmailChange<S, R, S, S, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    ConfirmEmailChange {
        users: api.store.clone(),
        repo: repos.0.clone(),
        devices: api.store.clone(),
        tokens: api.store.clone(),
        env: api.crypto.clone(),
        notices: api.hub.notices(),
    }
}

/// What the browser made with the new master key, decoded.
fn new_credentials(
    upload: &str,
    kdf: &KdfDto,
    wrapped_root_key: &str,
) -> Result<NewCredentials, Problem> {
    Ok(NewCredentials {
        upload: decode("upload", upload)?,
        kdf: kdf.to_params()?,
        wrapped_root_key: decode("wrappedRootKey", wrapped_root_key)?,
    })
}

/// Writes an event; what it describes has happened, so a failure is logged and not raised. Events
/// carry no address and no name: only what changed.
pub(super) async fn record<S, P, K>(
    api: &Api<S, P, K>,
    actor: UserId,
    device: Option<DeviceId>,
    action: &'static str,
    target: Option<String>,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let event = Event {
        actor: Some(actor),
        device,
        action,
        target,
        at: api.crypto.now(),
    };
    if let Err(e) = EventLog::record(&api.store, event).await {
        tracing::warn!(action, error = %e, "couldn't record an event");
    }
}

/// The account that asks.
pub(super) async fn account_of<S, P, K>(
    api: &Api<S, P, K>,
    authed: &Authed,
) -> Result<kemlock_domain::User, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    UserRepo::by_id(&api.store, authed.actor.user)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| Problem::from(AppError::Unauthorized))
}

/// Whether the account has a second step on.
async fn second_step_on<S, P, K>(api: &Api<S, P, K>, user: UserId) -> Result<bool, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    Ok(TwoFactorRepo::list(&api.store, user)
        .await
        .map_err(AppError::from)?
        .iter()
        .any(|row| row.enabled))
}

/// The fresh proof a second step asks beside the password, as erasing the account asks it: with a
/// second step on, the request must carry one (said before the password is spent, so a refusal that
/// can be known costs the person nothing) and `Some` gives it back to be checked once the password
/// has been; with none on, whatever was sent is not needed and nothing is asked.
pub(super) async fn proof_needed<'a, S, P, K>(
    api: &Api<S, P, K>,
    user: UserId,
    given: Option<&'a FreshProof>,
) -> Result<Option<&'a FreshProof>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    if !second_step_on(api, user).await? {
        return Ok(None);
    }
    match given.filter(|proof| !proof.is_blank()) {
        Some(proof) => Ok(Some(proof)),
        None => Err(AppError::Invalid(
            "a fresh proof of the second step is needed beside the password",
        )
        .into()),
    }
}

// ---- handlers ----

async fn handle_show<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<Json<ProfileDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    guard(&api.limits.proof, &ip_key(authed.ip), api.now())?;
    let view = profile(&api, &repos).show(authed.actor.user).await?;
    let two_step = second_step_on(&api, authed.actor.user).await?;
    Ok(Json(ProfileDto::of(&view, two_step)))
}

async fn handle_rename<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<ProfileDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    guard(&api.limits.proof, &ip_key(authed.ip), api.now())?;
    let request: RenameProfileRequest = body.json()?;
    let view = profile(&api, &repos)
        .rename(authed.actor.user, &request.name)
        .await?;
    record(
        &api,
        authed.actor.user,
        Some(authed.actor.device),
        "account.name_changed",
        None,
    )
    .await;
    let two_step = second_step_on(&api, authed.actor.user).await?;
    Ok(Json(ProfileDto::of(&view, two_step)))
}

async fn handle_credentials_start<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<CredentialsStartResponse>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: CredentialsStartRequest = body.json()?;
    let started = credentials(&api, &repos)
        .start(
            authed.actor.user,
            request.email.as_deref(),
            &decode("request", &request.request)?,
            &authed.jkt,
        )
        .await?;
    Ok(Json(CredentialsStartResponse {
        response: kemlock_app::b64url::encode(&started.response),
        ticket: kemlock_app::b64url::encode(&started.ticket),
    }))
}

async fn handle_change_password<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<ChangedPasswordDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    let request: ChangePasswordRequest = body.json()?;
    let new = new_credentials(&request.upload, &request.kdf, &request.wrapped_root_key)?;
    let ticket = decode("ticket", &request.ticket)?;
    let user = authed.actor.user;
    let credentials = credentials(&api, &repos);
    // What can be known to be wrong is said before the password is spent.
    credentials.check(user, &ticket, &authed.jkt).await?;
    let proof = proof_needed(&api, user, request.proof.as_ref()).await?;
    let account = account_of(&api, &authed).await?;
    reauthenticate(
        &api,
        &authed,
        &account,
        &request.login_state,
        &request.finalization,
    )
    .await?;
    // With a second step on, the password alone is not enough: a stolen session and a guessed
    // password must not change it.
    if let Some(proof) = proof {
        require_proof_via_api(&api, user, proof, true).await?;
    }
    let changed = credentials
        .change_password(user, new, &ticket, &authed.jkt, request.sign_out_others)
        .await?;
    // The password is changed: nothing from here on can say it was not. With the other devices
    // signed out the stamp is new, so this device's own tokens ended with the write too, and the
    // answer carries new ones; if they can't be made it signs in again with the new password.
    let tokens = if changed.others_signed_out {
        other_devices(&api)
            .renew(&authed.actor, &changed.account, &authed.jkt)
            .await
    } else {
        None
    };
    record(
        &api,
        user,
        Some(authed.actor.device),
        "account.password_changed",
        request
            .sign_out_others
            .then(|| "other devices signed out".to_owned()),
    )
    .await;
    Ok(Json(ChangedPasswordDto {
        tokens: tokens.map(|tokens| token_response(&tokens, api.now())),
    }))
}

async fn handle_request_email<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<(StatusCode, Json<EmailChangeAskedDto>), Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    let request: ChangeEmailRequest = body.json()?;
    let new = new_credentials(&request.upload, &request.kdf, &request.wrapped_root_key)?;
    let ticket = decode("ticket", &request.ticket)?;
    let user = authed.actor.user;
    // What can be known to be wrong is said before the password is spent.
    let changes = email_changes(&api, &repos);
    changes
        .check(user, &request.email, &ticket, &authed.jkt)
        .await?;
    let proof = proof_needed(&api, user, request.proof.as_ref()).await?;
    // Three asks an hour per account, whether the address is free or not: asking is how a person
    // would try addresses, and each ask mails someone.
    guard(&api.limits.email_change, &user.to_string(), api.now())?;
    let account = account_of(&api, &authed).await?;
    reauthenticate(
        &api,
        &authed,
        &account,
        &request.login_state,
        &request.finalization,
    )
    .await?;
    if let Some(proof) = proof {
        require_proof_via_api(&api, user, proof, true).await?;
    }
    let asked = changes
        .request(user, &request.email, new, &ticket, &authed.jkt)
        .await?;
    record(
        &api,
        user,
        Some(authed.actor.device),
        "account.email_change_requested",
        None,
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(EmailChangeAskedDto {
            pending_email: asked.email.as_str().to_owned(),
            expires_at: asked.expires_at.format(&Rfc3339).unwrap_or_default(),
        }),
    ))
}

async fn handle_cancel_email<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<StatusCode, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    guard(&api.limits.proof, &ip_key(authed.ip), api.now())?;
    email_changes(&api, &repos)
        .cancel(authed.actor.user)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_confirm_email<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    ClientIp(ip): ClientIp,
    body: Body,
) -> Result<Json<ConfirmedEmailDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    // Nobody is signed in: the token is all there is, so guesses are limited per IP.
    guard(
        &api.limits.sign_in,
        &format!("confirm-email:{}", ip_key(ip)),
        api.now(),
    )?;
    let request: ConfirmEmailRequest = body.json()?;
    let done = confirm(&api, &repos).confirm(&request.token).await?;
    record(&api, done.user, None, "account.email_changed", None).await;
    Ok(Json(ConfirmedEmailDto {
        email: done.email.as_str().to_owned(),
    }))
}

/// The profile routes. Merge the result into the main router, with the store of pending changes:
///
/// ```ignore
/// router(api.clone()).merge(profile_router(api, store))
/// ```
pub fn profile_router<S, P, K, R>(api: Api<S, P, K>, repo: R) -> Router
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: ProfileRepo + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/account/profile",
            get(handle_show::<S, P, K, R>).patch(handle_rename::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/credentials/start",
            post(handle_credentials_start::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/password",
            put(handle_change_password::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/email",
            post(handle_request_email::<S, P, K, R>).delete(handle_cancel_email::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/email/confirm",
            post(handle_confirm_email::<S, P, K, R>),
        )
        .layer(Extension(Arc::new(Repos(repo))))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/account/profile", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "The profile: name, address and what may change", body = ProfileDto),
    )
)]
#[allow(dead_code)]
fn doc_profile_show() {}

#[utoipa::path(
    patch, path = "/kem/v1/account/profile", tag = "account",
    security(("dpop" = [])),
    request_body = RenameProfileRequest,
    responses(
        (status = 200, description = "The profile, with the new name", body = ProfileDto),
        (status = 400, description = "The name is longer than 100 characters or holds control characters", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`sso-managed`: the name comes from the identity provider", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_profile_rename() {}

#[utoipa::path(
    post, path = "/kem/v1/account/credentials/start", tag = "account",
    security(("dpop" = [])),
    request_body = CredentialsStartRequest,
    responses(
        (status = 200, description = "OPAQUE's registration response, bound to the new address when one was given, else to the account's own, and the ticket that goes with it. An address another account has is answered exactly as a free one is", body = CredentialsStartResponse),
        (status = 400, description = "The request or the address is malformed, or the address is the account's own", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`sso-managed` (a new address for an identity provider's account), `compatible-account` or `no-password`", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_credentials_start() {}

#[utoipa::path(
    put, path = "/kem/v1/account/password", tag = "account",
    security(("dpop" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "The password's records are replaced; the root key and its version stay. With `signOutOthers` the security stamp is replaced in the same write, every other session ends at once, and `tokens` are the device's new ones; without it the stamp stays and `tokens` is null", body = ChangedPasswordDto),
        (status = 400, description = "The login state was used before, or isn't well formed; the ticket is missing, unreadable, run out, or for another account, key or address; a second step is on and the proof is missing, wrong or spent; the settings, the wrap or the upload are malformed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong password, or not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`compatible-account` or `no-password`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "`account-changed`: the account was written meanwhile and nothing was; ask again", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_change_password() {}

#[utoipa::path(
    post, path = "/kem/v1/account/email", tag = "account",
    security(("dpop" = [])),
    request_body = ChangeEmailRequest,
    responses(
        (status = 202, description = "The link is mailed to the new address; nothing changes until it is opened. The same answer whether or not another account has the address: that address is mailed a notice that says so instead of the link", body = EmailChangeAskedDto),
        (status = 400, description = "The login state was used before, or isn't well formed; the ticket is missing, unreadable, run out, or for another account, key or address; a second step is on and the proof is missing, wrong or spent; the address, the settings, the wrap or the upload are malformed, or the address is the account's own", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong password, or not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`sso-managed`, `compatible-account` or `no-password`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "`mail-off`: the server sends no mail", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Three asks an hour per account, and the limits of every password check", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 502, description = "`mail-failed`: the mail with the link could not be sent", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_request_email() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/email", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 204, description = "No change of address is waiting: there was none, or its link no longer works"),
    )
)]
#[allow(dead_code)]
fn doc_cancel_email() {}

#[utoipa::path(
    post, path = "/kem/v1/account/email/confirm", tag = "account",
    request_body = ConfirmEmailRequest,
    responses(
        (status = 200, description = "The address is the account's now, and every session has ended: sign in again with it", body = ConfirmedEmailDto),
        (status = 400, description = "`email-change-invalid`: the token is unknown, used or out of time, or the account is disabled or being deleted", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`sso-managed`, `compatible-account` or `no-password`: the account became one that can't change its address; the ask is dropped", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "`email-taken`: someone took the address meanwhile, the ask is dropped; or `account-changed`: the account was written meanwhile, nothing was, and the link still works", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_confirm_email() {}

/// The profile routes' part of `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_profile_show,
        doc_profile_rename,
        doc_credentials_start,
        doc_change_password,
        doc_request_email,
        doc_cancel_email,
        doc_confirm_email
    ),
    components(schemas(
        ProfileDto,
        RenameProfileRequest,
        CredentialsStartRequest,
        CredentialsStartResponse,
        ChangePasswordRequest,
        ChangedPasswordDto,
        ChangeEmailRequest,
        EmailChangeAskedDto,
        ConfirmEmailRequest,
        ConfirmedEmailDto
    ))
)]
pub struct ProfileApiDoc;
