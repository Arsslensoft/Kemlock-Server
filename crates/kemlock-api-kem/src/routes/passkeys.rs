//! Passkeys and WebAuthn security keys.
//!
//! - `POST /kem/v1/auth/passkey/options` and `/verify` sign in with a passkey. The challenge is a
//!   sealed value the device sends back; it names no account, so the options say nothing about who
//!   has passkeys. A passkey with the PRF extension gets its copy of the root key back, to open
//!   the vault; one without only signs in. "Require SSO" blocks the sign-in for the members it
//!   binds.
//! - `GET`, `POST`, `PATCH` and `DELETE` under `/kem/v1/account/passkeys` register, list, rename
//!   and delete an account's passkeys (at most five), and `PUT .../{id}/prf` stores the PRF copy
//!   of the root key.
//! - `POST /kem/v1/account/two-factor/webauthn` and `.../confirm` enrol a security key as a
//!   second step, as the TOTP routes enrol an authenticator app; `GET .../webauthn` lists the keys
//!   and `DELETE .../webauthn/{slot}` removes one.
//! - `POST /kem/v1/auth/two-factor/webauthn/options` and `.../webauthn` answer the second step of
//!   a sign-in with that key.
//!
//! The routes need ports the rest of the API doesn't (the WebAuthn relying party, the passkey
//! store, the space membership `Require SSO` reads), so the router is built apart, from the API
//! state and a [`PasskeyRuntime`], and merged into the main router by the server: see
//! [`passkeys_router`].

use super::attempts;
use super::guard;
use super::new_device::announce;
use super::two_step::{
    ProofRequest, announce_change, proof_steps, require_proof, require_proof_to_add,
};
use crate::dto::{DeviceDto, FreshProof, KeyAssertion, TokenResponse, decode};
use crate::extract::{Authed, Body, DPOP_NONCE, Proof};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::ratelimit::ip_key;
use crate::replay::Full;
use crate::signlog::token_ids;
use crate::state::{Api, Crypto, Store};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use kemlock_app::passkeys::{
    FinishRegistration, KeyList, ManagePasskeys, PasskeySignIn, PasskeyStore, PasskeyVerifyInput,
    SecurityKeyStep, SecurityKeys, WebAuthn,
};
use kemlock_app::ports::TokenSigner;
use kemlock_app::sso::{MembershipFacts, RequireSso};
use kemlock_app::{AppError, DeviceInfo, Sessions, TokenPair, b64url};
use kemlock_crypto::hash;
use kemlock_domain::{Passkey, PasskeyId, PrfWrap};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The ports the passkey routes need beyond the rest of the API: the passkey store, the WebAuthn
/// relying party and the space membership `Require SSO` reads.
#[derive(Debug)]
pub struct PasskeyRuntime<R, W, M> {
    pub repos: R,
    pub webauthn: W,
    pub membership: M,
}

impl<R, W, M> PasskeyRuntime<R, W, M> {
    pub fn new(repos: R, webauthn: W, membership: M) -> Self {
        PasskeyRuntime {
            repos,
            webauthn,
            membership,
        }
    }
}

fn iso(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Bodies

/// The WebAuthn answer is the browser's `PublicKeyCredential.toJSON()`: an object, whose members
/// the relying party reads.
fn credential_bytes(credential: &Value) -> Result<Vec<u8>, Problem> {
    if !credential.is_object() {
        return Err(Problem::bad_request("credential must be a JSON object"));
    }
    serde_json::to_vec(credential).map_err(|_| Problem::bad_request("credential can't be read"))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasskeyOptionsResponse {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`: a discoverable
    /// credential, so `allowCredentials` is empty. Ask for the PRF extension with
    /// `extensions.prf.eval.first` = SHA-256 of `"kemlock/v1/prf-salt"`.
    #[schema(value_type = Object)]
    pub(crate) options: Value,
    /// Send it back to `/auth/passkey/verify` within five minutes, with a proof of the same key.
    pub(crate) challenge: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasskeyVerifyRequest {
    pub(crate) challenge: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub(crate) credential: Value,
    pub(crate) device: DeviceDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrfDto {
    /// The root key wrapped under the passkey's PRF output (docs/crypto.md), base64url.
    pub(crate) wrapped_key: String,
    /// The account key version the wrap is for.
    pub(crate) key_version: u32,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasskeySignInResponse {
    pub(crate) tokens: TokenResponse,
    pub(crate) passkey_id: Uuid,
    /// The PRF copy of the root key, when the passkey has one for the account's current key
    /// version: it opens the vault. Absent, the sign-in opens no vault.
    pub(crate) prf: Option<PrfDto>,
    /// The account's key version now.
    pub(crate) key_version: u32,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreationOptionsResponse {
    /// `PublicKeyCredentialCreationOptions` for `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub(crate) options: Value,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasskeyDto {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    /// Whether the passkey holds a PRF copy of the root key, so it can open the vault.
    pub(crate) prf: bool,
    /// The key version of that copy.
    pub(crate) prf_key_version: Option<u32>,
    pub(crate) created_at: String,
    pub(crate) last_used_at: Option<String>,
}

impl PasskeyDto {
    fn from_passkey(passkey: &Passkey) -> Self {
        PasskeyDto {
            id: passkey.id.0,
            name: passkey.name.clone(),
            prf: passkey.prf_wrap.is_some(),
            prf_key_version: passkey.prf_wrap.as_ref().map(|w| w.key_version),
            created_at: iso(passkey.created_at),
            last_used_at: passkey.last_used_at.map(iso),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasskeyListResponse {
    pub(crate) passkeys: Vec<PasskeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrfBody {
    /// The root key wrapped under the PRF output, base64url, 92 bytes.
    pub(crate) wrapped_key: String,
    /// Must be the account's current key version.
    pub(crate) key_version: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegisterPasskeyRequest {
    /// What the person calls it.
    pub(crate) name: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub(crate) credential: Value,
    /// The PRF copy of the root key, when the client already has the PRF output.
    pub(crate) prf: Option<PrfBody>,
    /// A fresh proof, as adding a second step takes: needed when the account has one on already,
    /// since a passkey signs in without the password or the second step.
    pub(crate) proof: Option<FreshProof>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RenameRequest {
    pub(crate) name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecurityKeyConfirmRequest {
    pub(crate) name: String,
    /// A fresh proof, as a removal takes: needed when a second step is on already.
    pub(crate) proof: Option<FreshProof>,
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub(crate) credential: Value,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecurityKeyDto {
    /// The slot, 1 to 5.
    pub(crate) id: u8,
    pub(crate) name: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecurityKeysResponse {
    pub(crate) enabled: bool,
    pub(crate) keys: Vec<SecurityKeyDto>,
}

impl SecurityKeysResponse {
    fn from_list(list: KeyList) -> Self {
        SecurityKeysResponse {
            enabled: list.enabled,
            keys: list
                .keys
                .into_iter()
                .map(|k| SecurityKeyDto {
                    id: k.id,
                    name: k.name,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyStepOptionsRequest {
    /// The sealed challenge `opaque/finish` or `sso/finish` gave when it asked for a second step.
    pub(crate) challenge: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestOptionsResponse {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`, listing the account's
    /// security keys.
    #[schema(value_type = Object)]
    pub(crate) options: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyStepRequest {
    pub(crate) challenge: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub(crate) credential: Value,
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

fn passkey_id(raw: &str) -> Result<PasskeyId, Problem> {
    raw.parse()
        .map_err(|_| Problem::bad_request("the passkey id isn't a UUID"))
}

// ---------------------------------------------------------------------------------------------
// Use-case builders

type Manage<S, P, R, W> = ManagePasskeys<S, R, R, W, P, S>;
type PasskeyIn<S, P, K, R, W, M> = PasskeySignIn<S, R, W, P, S, S, K, P, S, S, M>;
type Keys<S, P, R, W> = SecurityKeys<S, S, R, W, P, P>;
type KeyStep<S, P, K, R, W> = SecurityKeyStep<S, S, R, W, P, S, S, K, P, S>;

fn sessions<S, P, K>(api: &Api<S, P, K>) -> Sessions<S, S, K, P, S, S>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    Sessions {
        devices: api.store.clone(),
        tokens: api.store.clone(),
        signer: api.signer.clone(),
        env: api.crypto.clone(),
        events: api.store.clone(),
        two_factor: api.store.clone(),
        config: api.config.auth,
    }
}

fn manage<S, P, K, R, W, M>(
    api: &Api<S, P, K>,
    runtime: &PasskeyRuntime<R, W, M>,
) -> Manage<S, P, R, W>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
{
    ManagePasskeys {
        users: api.store.clone(),
        passkeys: runtime.repos.clone(),
        challenges: runtime.repos.clone(),
        webauthn: runtime.webauthn.clone(),
        env: api.crypto.clone(),
        events: api.store.clone(),
        config: api.config.auth,
    }
}

fn passkey_sign_in<S, P, K, R, W, M>(
    api: &Api<S, P, K>,
    runtime: &PasskeyRuntime<R, W, M>,
) -> PasskeyIn<S, P, K, R, W, M>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: MembershipFacts + Clone + 'static,
{
    PasskeySignIn {
        users: api.store.clone(),
        passkeys: runtime.repos.clone(),
        webauthn: runtime.webauthn.clone(),
        seal: api.crypto.clone(),
        sso: RequireSso {
            membership: runtime.membership.clone(),
        },
        sessions: sessions(api),
    }
}

fn security_keys<S, P, K, R, W, M>(
    api: &Api<S, P, K>,
    runtime: &PasskeyRuntime<R, W, M>,
) -> Keys<S, P, R, W>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
{
    SecurityKeys {
        users: api.store.clone(),
        two_factor: api.store.clone(),
        challenges: runtime.repos.clone(),
        webauthn: runtime.webauthn.clone(),
        seal: api.crypto.clone(),
        env: api.crypto.clone(),
        config: api.config.auth,
    }
}

fn key_step<S, P, K, R, W, M>(
    api: &Api<S, P, K>,
    runtime: &PasskeyRuntime<R, W, M>,
) -> KeyStep<S, P, K, R, W>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
{
    SecurityKeyStep {
        keys: security_keys(api, runtime),
        sessions: sessions(api),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers: signing in with a passkey

/// `POST /kem/v1/auth/passkey/options`: the options for a sign-in, and the sealed challenge. Rate
/// limited per address, like every sign-in start.
async fn handle_passkey_options<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    proof: Proof,
) -> Result<Json<PasskeyOptionsResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: MembershipFacts + Clone + 'static,
{
    guard(&api.limits.sign_in, &ip_key(proof.ip), api.now())?;
    // The challenge is bound to the DPoP key that asks: only that key may answer.
    let started = passkey_sign_in(&api, &runtime).options(&proof.jkt)?;
    Ok(Json(PasskeyOptionsResponse {
        options: started.options,
        challenge: b64url::encode(&started.challenge),
    }))
}

/// `POST /kem/v1/auth/passkey/verify`: the authenticator's answer, for tokens. A challenge is good
/// once, right answer or wrong. Require SSO answers 403 `sso-required` for a member it binds.
async fn handle_passkey_verify<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<PasskeySignInResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: MembershipFacts + Clone + 'static,
{
    let request: PasskeyVerifyRequest = body.json()?;
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(proof.ip), now)?;
    let challenge = decode("challenge", &request.challenge)?;
    let response = credential_bytes(&request.credential)?;
    let flow = passkey_sign_in(&api, &runtime);
    // Only a genuine, fresh challenge is remembered as used, so made-up ones take no room.
    flow.check_challenge(&challenge)?;
    match api.spend_open_state(proof.ip, &challenge, now) {
        Ok(true) => {}
        Ok(false) => {
            return Err(Problem::bad_request(
                "the passkey challenge was already used",
            ));
        }
        Err(Full) => return Err(Problem::overloaded()),
    }
    let verified = flow
        .verify(PasskeyVerifyInput {
            challenge,
            response,
            device: DeviceInfo {
                bitwarden_identifier: None,
                ..request.device.into_info()?
            },
            jkt: proof.jkt,
        })
        .await;
    api.log_attempt(api.attempt("passkey", None, &verified, proof.ip, |signed| {
        token_ids(&signed.tokens)
    }))
    .await;
    let signed = verified?;
    announce(&api, &signed.tokens, proof.ip).await;
    Ok(Json(PasskeySignInResponse {
        tokens: token_response(&signed.tokens, now),
        passkey_id: signed.passkey.0,
        prf: signed.prf_wrap.map(|wrap| PrfDto {
            wrapped_key: b64url::encode(&wrap.wrapped_key),
            key_version: wrap.key_version,
        }),
        key_version: signed.key_version,
    }))
}

// ---------------------------------------------------------------------------------------------
// Handlers: an account's passkeys

/// `GET /kem/v1/account/passkeys`.
async fn handle_passkeys_list<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
) -> Result<Json<PasskeyListResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let passkeys = manage(&api, &runtime).list(authed.actor.user).await?;
    Ok(Json(PasskeyListResponse {
        passkeys: passkeys.iter().map(PasskeyDto::from_passkey).collect(),
    }))
}

/// `POST /kem/v1/account/passkeys/options`: the creation options for a new passkey.
async fn handle_passkey_registration_options<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
) -> Result<Json<CreationOptionsResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let options = manage(&api, &runtime)
        .start_registration(authed.actor.user)
        .await?;
    Ok(Json(CreationOptionsResponse { options }))
}

/// `POST /kem/v1/account/passkeys`: the browser's answer, and the passkey's name.
async fn handle_passkey_register<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    body: Body,
) -> Result<(StatusCode, Json<PasskeyDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let request: RegisterPasskeyRequest = body.json()?;
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
    guard(
        &api.limits.sign_in,
        &format!("passkey:{}", authed.actor.user),
        now,
    )?;
    let prf = match request.prf {
        Some(prf) => Some(PrfWrap {
            wrapped_key: decode("prf.wrappedKey", &prf.wrapped_key)?,
            key_version: prf.key_version,
        }),
        None => None,
    };
    // A passkey signs in without the password or the second step and outlives a password change,
    // so with a second step on it is added on a fresh proof, as a security key or an
    // authenticator is. The proof is spent here, last before the change.
    require_proof_to_add(
        &api,
        &proof_steps(&api, runtime.repos.clone()),
        authed.actor.user,
        None,
        request.proof.as_ref(),
    )
    .await?;
    let passkey = manage(&api, &runtime)
        .finish_registration(FinishRegistration {
            user: authed.actor.user,
            name: request.name,
            response: credential_bytes(&request.credential)?,
            prf,
        })
        .await?;
    announce_change(&api, &authed, "passkey", true).await;
    Ok((
        StatusCode::CREATED,
        Json(PasskeyDto::from_passkey(&passkey)),
    ))
}

/// `PATCH /kem/v1/account/passkeys/{id}`.
async fn handle_passkey_rename<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let request: RenameRequest = body.json()?;
    manage(&api, &runtime)
        .rename(authed.actor.user, passkey_id(&id)?, &request.name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /kem/v1/account/passkeys/{id}`: the passkey and its PRF copy of the root key go.
async fn handle_passkey_delete<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    authed.require_fresh_sign_in(api.now())?;
    manage(&api, &runtime)
        .delete(authed.actor.user, passkey_id(&id)?)
        .await?;
    announce_change(&api, &authed, "passkey", false).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /kem/v1/account/passkeys/{id}/prf`: the PRF copy of the root key of a passkey that was made
/// without one.
async fn handle_passkey_prf<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Body,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    authed.require_fresh_sign_in(api.now())?;
    let request: PrfBody = body.json()?;
    manage(&api, &runtime)
        .set_wrap(
            authed.actor.user,
            passkey_id(&id)?,
            PrfWrap {
                wrapped_key: decode("wrappedKey", &request.wrapped_key)?,
                key_version: request.key_version,
            },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Handlers: security keys

/// `POST /kem/v1/account/two-factor/webauthn`: the creation options for a security key. Refused
/// Nothing is turned on yet: a fresh proof, when a second step is on already, is asked for when
/// the key is confirmed.
async fn handle_key_enrol<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
) -> Result<Json<CreationOptionsResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let options = security_keys(&api, &runtime)
        .start_registration(authed.actor.user)
        .await?;
    Ok(Json(CreationOptionsResponse { options }))
}

/// `POST /kem/v1/account/two-factor/webauthn/confirm`: the browser's answer; the method is on.
async fn handle_key_confirm<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<SecurityKeysResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let request: SecurityKeyConfirmRequest = body.json()?;
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
    guard(
        &api.limits.sign_in,
        &format!("webauthn:{}", authed.actor.user),
        now,
    )?;
    let credential = credential_bytes(&request.credential)?;
    super::two_step::require_fresh_for_first_step(&api, &authed).await?;
    require_proof_to_add(
        &api,
        &proof_steps(&api, runtime.repos.clone()),
        authed.actor.user,
        None,
        request.proof.as_ref(),
    )
    .await?;
    let list = security_keys(&api, &runtime)
        .finish_registration(authed.actor.user, None, &request.name, &credential)
        .await
        .map_err(AppError::from)?;
    announce_change(&api, &authed, "security-key", true).await;
    Ok(Json(SecurityKeysResponse::from_list(list)))
}

/// `GET /kem/v1/account/two-factor/webauthn`: the account's security keys.
async fn handle_keys_list<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
) -> Result<Json<SecurityKeysResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let list = security_keys(&api, &runtime)
        .keys(authed.actor.user)
        .await?;
    Ok(Json(SecurityKeysResponse::from_list(list)))
}

/// `DELETE /kem/v1/account/two-factor/webauthn/{slot}`: removes the key in a slot (1 to 5); with
/// the last one gone the method is off.
async fn handle_key_remove<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    authed: Authed,
    Path(slot): Path<u8>,
    body: Body,
) -> Result<Json<SecurityKeysResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    guard(&api.limits.sign_in, &ip_key(authed.ip), api.now())?;
    let request: ProofRequest = body.json()?;
    require_proof(
        &api,
        &proof_steps(&api, runtime.repos.clone()),
        authed.actor.user,
        &request.proof,
    )
    .await?;
    let list = security_keys(&api, &runtime)
        .remove(authed.actor.user, slot)
        .await?;
    announce_change(&api, &authed, "security-key", false).await;
    Ok(Json(SecurityKeysResponse::from_list(list)))
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

/// `POST /kem/v1/auth/two-factor/webauthn/options`: the request options for the account's
/// security keys, for a sign-in that asked for its second step.
async fn handle_key_step_options<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<RequestOptionsResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let request: KeyStepOptionsRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    limit_second_step(&api, proof.ip, &challenge, api.now())?;
    let options = key_step(&api, &runtime)
        .options(&challenge, &proof.jkt)
        .await?;
    Ok(Json(RequestOptionsResponse { options }))
}

/// `POST /kem/v1/auth/two-factor/webauthn`: the key's answer, for tokens. Like a wrong code, a
/// wrong answer counts against the account (5 in 15 minutes, then doubling delays), whichever
/// challenge or address it comes from.
async fn handle_key_step<S, P, K, R, W, M>(
    State(api): State<Api<S, P, K>>,
    Extension(runtime): Extension<Arc<PasskeyRuntime<R, W, M>>>,
    proof: Proof,
    body: Body,
) -> Result<Json<TokenResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: Send + Sync + 'static,
{
    let request: KeyStepRequest = body.json()?;
    let challenge = decode("challenge", &request.challenge)?;
    let response = credential_bytes(&request.credential)?;
    let now = api.now();
    limit_second_step(&api, proof.ip, &challenge, now)?;
    let step = key_step(&api, &runtime);
    // A genuine, fresh challenge names the account its failures count against; the attempt is
    // reserved before the answer is looked at.
    let user = step.challenge_user(&challenge)?;
    api.sign_in().check_second_step_allowed(&challenge).await?;
    attempts::reserve_second_step(&api, user, now).await?;
    let finished = step.verify(&challenge, &response, &proof.jkt).await;
    attempts::settle_second_step(&api, user, &finished).await;
    api.log_attempt(api.attempt("two-factor", Some(user), &finished, proof.ip, token_ids))
        .await;
    let tokens = finished?;
    announce(&api, &tokens, proof.ip).await;
    Ok(Json(token_response(&tokens, now)))
}

// ---------------------------------------------------------------------------------------------
// A security key or passkey as a fresh proof

/// What [`passkeys_router`] registers with the API state, so every route that takes a fresh proof
/// can check an assertion: the stored keys and the relying party, without the route's own types.
struct Asserting<S, P, K, R, W> {
    api: std::sync::Weak<crate::state::Inner<S, P, K>>,
    repos: R,
    webauthn: W,
}

impl<S, P, K, R, W> std::fmt::Debug for Asserting<S, P, K, R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asserting").finish_non_exhaustive()
    }
}

type Proving<S, P, R, W> = kemlock_app::passkeys::AssertionProof<S, S, R, W, P, P, R>;

impl<S, P, K, R, W> Asserting<S, P, K, R, W>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
{
    fn proving(&self, api: &Api<S, P, K>) -> Proving<S, P, R, W> {
        kemlock_app::passkeys::AssertionProof {
            keys: SecurityKeys {
                users: api.store.clone(),
                two_factor: api.store.clone(),
                challenges: self.repos.clone(),
                webauthn: self.webauthn.clone(),
                seal: api.crypto.clone(),
                env: api.crypto.clone(),
                config: api.config.auth,
            },
            passkeys: self.repos.clone(),
        }
    }
}

impl<S, P, K, R, W> super::two_step::AssertionChecker for Asserting<S, P, K, R, W>
where
    S: Store + Send + Sync,
    P: Crypto + Send + Sync,
    K: TokenSigner + Clone + Send + Sync + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
{
    fn options(
        &self,
        user: kemlock_domain::UserId,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<Value, Problem>> {
        Box::pin(async move {
            let Some(api) = Api::upgrade(&self.api) else {
                return Err(AppError::Unauthorized.into());
            };
            Ok(self.proving(&api).options(user).await?)
        })
    }

    fn verify(
        &self,
        user: kemlock_domain::UserId,
        response: Vec<u8>,
    ) -> kemlock_app::notices::BoxFuture<'_, Result<(), kemlock_app::passkeys::SecurityKeyError>>
    {
        Box::pin(async move {
            let Some(api) = Api::upgrade(&self.api) else {
                return Err(AppError::Unauthorized.into());
            };
            self.proving(&api).verify(user, &response).await
        })
    }
}

/// `POST /kem/v1/account/two-factor/proof/webauthn/options`: the request options for answering a
/// fresh proof with a security key or passkey of the signed-in account. `404` when it has none.
/// A new challenge replaces the older one; it is good once and for two minutes.
async fn handle_proof_options<S, P, K>(
    State(api): State<Api<S, P, K>>,
    authed: Authed,
) -> Result<Json<RequestOptionsResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let now = api.now();
    guard(&api.limits.sign_in, &ip_key(authed.ip), now)?;
    guard(
        &api.limits.sign_in,
        &format!("proof-options:{}", authed.actor.user),
        now,
    )?;
    let Some(checker) = api.assertions.get() else {
        return Err(AppError::NotFound.into());
    };
    let options = checker.options(authed.actor.user).await?;
    Ok(Json(RequestOptionsResponse { options }))
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

/// The passkey and security key routes. Merge the result into the main router:
///
/// ```ignore
/// router(api.clone()).merge(passkeys_router(api, PasskeyRuntime::new(repos, webauthn, membership)))
/// ```
pub fn passkeys_router<S, P, K, R, W, M>(
    api: Api<S, P, K>,
    runtime: PasskeyRuntime<R, W, M>,
) -> Router
where
    S: Store + Send + Sync,
    P: Crypto + Send + Sync,
    K: TokenSigner + Clone + Send + Sync + 'static,
    R: PasskeyStore,
    W: WebAuthn + Clone + 'static,
    M: MembershipFacts + Clone + 'static,
{
    let runtime = Arc::new(runtime);
    let _ = api.assertions.set(Arc::new(Asserting {
        api: api.downgrade(),
        repos: runtime.repos.clone(),
        webauthn: runtime.webauthn.clone(),
    }));
    Router::new()
        .route(
            "/kem/v1/auth/passkey/options",
            post(handle_passkey_options::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/auth/passkey/verify",
            post(handle_passkey_verify::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/passkeys",
            get(handle_passkeys_list::<S, P, K, R, W, M>)
                .post(handle_passkey_register::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/passkeys/options",
            post(handle_passkey_registration_options::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/passkeys/{id}",
            axum::routing::patch(handle_passkey_rename::<S, P, K, R, W, M>)
                .delete(handle_passkey_delete::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/passkeys/{id}/prf",
            put(handle_passkey_prf::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/two-factor/webauthn",
            get(handle_keys_list::<S, P, K, R, W, M>).post(handle_key_enrol::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/two-factor/webauthn/{slot}",
            axum::routing::delete(handle_key_remove::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/two-factor/webauthn/confirm",
            post(handle_key_confirm::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/account/two-factor/proof/webauthn/options",
            post(handle_proof_options::<S, P, K>),
        )
        .route(
            "/kem/v1/auth/two-factor/webauthn/options",
            post(handle_key_step_options::<S, P, K, R, W, M>),
        )
        .route(
            "/kem/v1/auth/two-factor/webauthn",
            post(handle_key_step::<S, P, K, R, W, M>),
        )
        .layer(Extension(runtime))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---------------------------------------------------------------------------------------------
// OpenAPI

#[utoipa::path(
    post, path = "/kem/v1/auth/passkey/options", tag = "passkeys",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    responses(
        (status = 200, description = "Options for `navigator.credentials.get` and the sealed challenge. The same answer whoever asks", body = PasskeyOptionsResponse),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_options() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/passkey/verify", tag = "passkeys",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that asked for the options")),
    request_body = PasskeyVerifyRequest,
    responses(
        (status = 200, description = "Signed in. `prf` is the root key wrapped under the PRF output, when the passkey has a copy for the account's key version", body = PasskeySignInResponse),
        (status = 401, description = "The challenge, key, credential, signature or counter is wrong", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "A space the account belongs to requires single sign-on (`sso-required`)", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_verify() {}

#[utoipa::path(
    get, path = "/kem/v1/account/passkeys", tag = "passkeys",
    security(("dpop" = [])),
    responses((status = 200, description = "The account's passkeys, oldest first", body = PasskeyListResponse))
)]
#[allow(dead_code)]
fn doc_passkeys_list() {}

#[utoipa::path(
    post, path = "/kem/v1/account/passkeys/options", tag = "passkeys",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "Options for `navigator.credentials.create`: a discoverable credential with user verification required. Add the PRF extension", body = CreationOptionsResponse),
        (status = 400, description = "The account has five passkeys", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_registration_options() {}

#[utoipa::path(
    post, path = "/kem/v1/account/passkeys", tag = "passkeys",
    security(("dpop" = [])),
    request_body = RegisterPasskeyRequest,
    responses(
        (status = 201, description = "The passkey is registered", body = PasskeyDto),
        (status = 400, description = "The answer wasn't accepted, no registration is in progress, the PRF copy doesn't fit, or a second step is on and the fresh `proof` (a mailed code, a current code of the authenticator app, the recovery code, or `{\"webauthn\": ...}`) is missing or wrong", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "The credential is registered already", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_register() {}

#[utoipa::path(
    patch, path = "/kem/v1/account/passkeys/{id}", tag = "passkeys",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The passkey's id")),
    request_body = RenameRequest,
    responses(
        (status = 204, description = "Renamed"),
        (status = 404, description = "No such passkey on this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_rename() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/passkeys/{id}", tag = "passkeys",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The passkey's id")),
    responses(
        (status = 204, description = "Deleted, with its PRF copy of the root key"),
        (status = 404, description = "No such passkey on this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_delete() {}

#[utoipa::path(
    put, path = "/kem/v1/account/passkeys/{id}/prf", tag = "passkeys",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The passkey's id")),
    request_body = PrfBody,
    responses(
        (status = 204, description = "Stored"),
        (status = 400, description = "Not 92 bytes, or for another key version than the account's", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such passkey on this account", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_passkey_prf() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/webauthn", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "Options for `navigator.credentials.create`", body = CreationOptionsResponse),
    )
)]
#[allow(dead_code)]
fn doc_key_enrol() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/webauthn/confirm", tag = "account",
    security(("dpop" = [])),
    request_body = SecurityKeyConfirmRequest,
    responses(
        (status = 200, description = "The key is registered and the method is on. With a second step on already, the request carries a fresh `proof` (a mailed code, a current code of the authenticator app, or the recovery code), or the answer of a security key or passkey as `{\"webauthn\": ...}`", body = SecurityKeysResponse),
        (status = 400, description = "The answer wasn't accepted, no registration is in progress, or a second step is on and the fresh proof is missing or wrong", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key_confirm() {}

#[utoipa::path(
    get, path = "/kem/v1/account/two-factor/webauthn", tag = "account",
    security(("dpop" = [])),
    responses((status = 200, description = "The account's security keys", body = SecurityKeysResponse))
)]
#[allow(dead_code)]
fn doc_keys_list() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/two-factor/webauthn/{slot}", tag = "account",
    security(("dpop" = [])),
    request_body = ProofRequest,
    params(("slot" = u8, Path, description = "The key's slot, 1 to 5")),
    responses(
        (status = 200, description = "The key is removed; the keys left", body = SecurityKeysResponse),
        (status = 404, description = "No key in that slot", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key_remove() {}

#[utoipa::path(
    post, path = "/kem/v1/account/two-factor/proof/webauthn/options", tag = "account",
    params(("DPoP" = String, Header, description = "A DPoP proof (RFC 9449) signed by the device key")),
    responses(
        (status = 200, description = "Options for `navigator.credentials.get`, listing the account's security keys and passkeys. Send the answer as `{\"webauthn\": <PublicKeyCredential.toJSON()>}` in the `proof` of any request that takes a fresh proof. The challenge is good once and for two minutes; asking again replaces it", body = RequestOptionsResponse),
        (status = 404, description = "The account has no security key or passkey", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many tries", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_proof_options() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/webauthn/options", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = KeyStepOptionsRequest,
    responses(
        (status = 200, description = "Options for `navigator.credentials.get`; asking again replaces the challenge", body = RequestOptionsResponse),
        (status = 401, description = "Another device key, or the account has no security key", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key_step_options() {}

#[utoipa::path(
    post, path = "/kem/v1/auth/two-factor/webauthn", tag = "auth",
    params(("DPoP" = String, Header, description = "A DPoP proof signed by the key that passed the first step")),
    request_body = KeyStepRequest,
    responses(
        (status = 200, description = "Signed in", body = TokenResponse),
        (status = 401, description = "Wrong, repeated or stale answer: a wrong one uses its challenge up", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong answers", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key_step() {}

/// The OpenAPI paths of the passkey and security key routes, for the server to merge into
/// `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_passkey_options,
        doc_passkey_verify,
        doc_passkeys_list,
        doc_passkey_registration_options,
        doc_passkey_register,
        doc_passkey_rename,
        doc_passkey_delete,
        doc_passkey_prf,
        doc_key_enrol,
        doc_key_confirm,
        doc_keys_list,
        doc_key_remove,
        doc_proof_options,
        doc_key_step_options,
        doc_key_step
    ),
    components(schemas(
        ProblemDoc,
        PasskeyOptionsResponse,
        PasskeyVerifyRequest,
        PasskeySignInResponse,
        PrfDto,
        PrfBody,
        CreationOptionsResponse,
        PasskeyDto,
        PasskeyListResponse,
        RegisterPasskeyRequest,
        RenameRequest,
        SecurityKeyConfirmRequest,
        SecurityKeyDto,
        SecurityKeysResponse,
        ProofRequest,
        FreshProof,
        KeyAssertion,
        KeyStepOptionsRequest,
        RequestOptionsResponse,
        KeyStepRequest,
        DeviceDto,
        TokenResponse
    ))
)]
pub struct PasskeysApiDoc;
