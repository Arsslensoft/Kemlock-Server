//! Step-up with a passkey or a security key: the admin proves it is them with a fresh assertion
//! from one of their own passkeys or security keys, and gets the same step-up token the password
//! and the authenticator code give.
//!
//! It runs on the passkeys use cases' ports and rules ([`WebAuthn`], [`PasskeyRepo`], and the
//! account's security keys through [`StepUpKeys`]). A passkey's answer must carry user
//! verification, as at sign-in; a security key's need not, as when it is the second step at
//! sign-in. The challenge is sealed under `server.key` and names the account and the device it was
//! made for, so it can't be answered from another account or another signed-in device; it expires
//! after [`CHALLENGE_TTL`], and the API remembers a returned challenge as used, so it is good once.
//! The challenge lists the admin's own credentials, so an authenticator holding any other has
//! nothing to offer.

use super::error::AdminError;
use super::step_up::{Issued, issue_token};
use crate::authenticate::Actor;
use crate::b64url;
use crate::error::AppError;
use crate::notices::BoxFuture;
use crate::passkeys::{CredentialKind, KeyCredentials, PasskeyRepo, WebAuthn, ceremony_error};
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactorRepo};
use kemlock_domain::{PasskeyId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use subtle::ConstantTimeEq;
use time::Duration;
use uuid::Uuid;

/// `SecretSeal` purpose of the sealed challenge.
pub const PURPOSE_CHALLENGE: &str = "admin-step-up-passkey";
/// How long a challenge may take to be answered.
pub const CHALLENGE_TTL: Duration = Duration::minutes(2);

const CHALLENGE_VERSION: u8 = 1;

/// What a sealed challenge remembers.
#[derive(Serialize, Deserialize)]
struct Challenge {
    v: u8,
    /// Unix seconds.
    exp: i64,
    /// The account and device the challenge was made for.
    user: Uuid,
    device: Uuid,
    /// The WebAuthn state, base64url.
    state: String,
    /// Whether the ceremony listed security keys too (it then started as a security-key one).
    #[serde(default)]
    keys: bool,
}

/// The first half of a passkey step-up.
#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyStepUpChallenge {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`.
    pub options: Value,
    /// The sealed state; sent back unread with the authenticator's answer.
    pub challenge: Vec<u8>,
}

/// Each security key's credential id and credential.
pub type KeyCredentialList = Vec<(Vec<u8>, Vec<u8>)>;

/// The account's security keys, as the step-up reads and answers them.
pub trait StepUpKeys: Send + Sync {
    /// Each key's credential id and credential.
    fn credentials_of(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<KeyCredentialList, AppError>> + Send;
    /// Stores the credential after an answer (its counter moved).
    fn record_use(
        &self,
        user: UserId,
        credential_id: &[u8],
        credential: &[u8],
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

impl<F: TwoFactorRepo, S: SecretSeal, E: Platform> StepUpKeys for KeyCredentials<F, S, E> {
    async fn credentials_of(&self, user: UserId) -> Result<KeyCredentialList, AppError> {
        KeyCredentials::credentials_of(self, user).await
    }
    async fn record_use(
        &self,
        user: UserId,
        credential_id: &[u8],
        credential: &[u8],
    ) -> Result<(), AppError> {
        KeyCredentials::record_use(self, user, credential_id, credential).await
    }
}

/// No security keys: a step-up over passkeys alone.
impl StepUpKeys for () {
    async fn credentials_of(&self, _user: UserId) -> Result<KeyCredentialList, AppError> {
        Ok(Vec::new())
    }
    async fn record_use(&self, _: UserId, _: &[u8], _: &[u8]) -> Result<(), AppError> {
        Ok(())
    }
}

/// Passkey and security-key step-up over its ports.
#[derive(Debug)]
pub struct PasskeyStepUp<P, W, S, E, K = ()> {
    pub passkeys: P,
    pub webauthn: W,
    pub seal: S,
    pub env: E,
    /// The account's security keys.
    pub keys: K,
}

/// What the admin API holds: [`PasskeyStepUp`] without its port types.
pub trait PasskeyStepper: Send + Sync {
    /// The options for a step-up by `actor`, over the credentials of their own passkeys and
    /// security keys. `State` when the account has none.
    fn options<'a>(
        &'a self,
        actor: &'a Actor,
    ) -> BoxFuture<'a, Result<PasskeyStepUpChallenge, AdminError>>;

    /// Whether `challenge` is genuine, fresh and made for `actor`'s account and device. The API
    /// checks this before it remembers the challenge as used, so made-up ones take no room.
    fn check_challenge(&self, actor: &Actor, challenge: &[u8]) -> Result<(), AdminError>;

    /// The second half: a step-up token when the authenticator's answer checks out.
    fn finish<'a>(
        &'a self,
        actor: &'a Actor,
        challenge: &'a [u8],
        response: &'a [u8],
    ) -> BoxFuture<'a, Result<Issued, AdminError>>;
}

/// A credential the admin may answer with.
struct Held {
    credential_id: Vec<u8>,
    credential: Vec<u8>,
    /// The passkey it is, when it is one; a security key otherwise.
    passkey: Option<PasskeyId>,
}

impl<P, W, S, E, K> PasskeyStepUp<P, W, S, E, K>
where
    P: PasskeyRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
    K: StepUpKeys,
{
    /// The challenge, when it is for `actor`, genuine and fresh.
    fn open_challenge(&self, actor: &Actor, sealed: &[u8]) -> Result<Challenge, AdminError> {
        let invalid = || AdminError::Invalid("the passkey challenge isn't valid".to_owned());
        let plain = self
            .seal
            .open(PURPOSE_CHALLENGE, sealed)
            .map_err(|_| invalid())?;
        let challenge: Challenge = serde_json::from_slice(&plain).map_err(|_| invalid())?;
        if challenge.v != CHALLENGE_VERSION {
            return Err(invalid());
        }
        if self.env.now().unix_timestamp() >= challenge.exp {
            return Err(AdminError::Invalid(
                "the passkey challenge has expired".to_owned(),
            ));
        }
        // Another account, or another device of this one, can't answer it.
        if challenge.user != actor.user.0 || challenge.device != actor.device.0 {
            return Err(AdminError::StepUpFailed);
        }
        Ok(challenge)
    }

    /// The admin's own security keys, then their passkeys.
    async fn held(&self, user: UserId) -> Result<Vec<Held>, AdminError> {
        let mut held: Vec<Held> = self
            .keys
            .credentials_of(user)
            .await?
            .into_iter()
            .map(|(credential_id, credential)| Held {
                credential_id,
                credential,
                passkey: None,
            })
            .collect();
        held.extend(
            self.passkeys
                .passkeys_of(user)
                .await?
                .into_iter()
                .map(|p| Held {
                    credential_id: p.credential_id,
                    credential: p.credential,
                    passkey: Some(p.id),
                }),
        );
        Ok(held)
    }

    async fn make_options(&self, actor: &Actor) -> Result<PasskeyStepUpChallenge, AdminError> {
        let held = self.held(actor.user).await?;
        if held.is_empty() {
            return Err(AdminError::State(
                "this account has no passkey or security key; use the password check or a code",
            ));
        }
        let keys = held.iter().any(|h| h.passkey.is_none());
        // Passkeys alone: a passkey ceremony, user verification required. With a security key
        // listed, a security-key ceremony, which a touch-only key can answer.
        let kind = if keys {
            CredentialKind::SecurityKey
        } else {
            CredentialKind::Passkey
        };
        let credentials: Vec<&[u8]> = held.iter().map(|h| h.credential.as_slice()).collect();
        let started = self
            .webauthn
            .start_authentication(kind, &credentials)
            .map_err(|e| AdminError::App(ceremony_error(e)))?;
        let mut options = started.options;
        // A passkey's answer must carry user verification, so the browser is told to verify when
        // one is listed beside a key; the answer is checked for it either way.
        if keys && held.iter().any(|h| h.passkey.is_some()) {
            let inner = if options.get("publicKey").is_some() {
                &mut options["publicKey"]
            } else {
                &mut options
            };
            inner["userVerification"] = Value::from("required");
        }
        let exp = (self.env.now() + CHALLENGE_TTL).unix_timestamp();
        let plain = serde_json::to_vec(&Challenge {
            v: CHALLENGE_VERSION,
            exp,
            user: actor.user.0,
            device: actor.device.0,
            state: b64url::encode(&started.state),
            keys,
        })
        .map_err(|_| {
            AdminError::App(AppError::Store(
                "couldn't encode a passkey challenge".to_owned(),
            ))
        })?;
        Ok(PasskeyStepUpChallenge {
            options,
            challenge: self.seal.seal(PURPOSE_CHALLENGE, &plain),
        })
    }

    async fn make_token(
        &self,
        actor: &Actor,
        challenge: &[u8],
        response: &[u8],
    ) -> Result<Issued, AdminError> {
        let opened = self.open_challenge(actor, challenge)?;
        let state = b64url::decode(&opened.state)
            .ok_or_else(|| AdminError::Invalid("the passkey challenge isn't valid".to_owned()))?;
        let ids = self
            .webauthn
            .response_ids(response)
            .map_err(|_| AdminError::StepUpFailed)?;
        // One of the admin's own passkeys or security keys, and no one else's.
        let own = self
            .held(actor.user)
            .await?
            .into_iter()
            .find(|h| h.credential_id == ids.credential_id)
            .ok_or(AdminError::StepUpFailed)?;
        if let Some(handle) = &ids.user_handle
            && !bool::from(handle.as_slice().ct_eq(actor.user.as_bytes()))
        {
            return Err(AdminError::StepUpFailed);
        }
        let kind = if opened.keys {
            CredentialKind::SecurityKey
        } else {
            CredentialKind::Passkey
        };
        let assertion = self
            .webauthn
            .finish_authentication(kind, &state, response, &[own.credential.as_slice()])
            .map_err(|e| {
                tracing::debug!(error = %e, "a passkey step-up was refused");
                AdminError::StepUpFailed
            })?;
        // A passkey is possession plus a PIN or a body check: without the second, it is no more
        // than a key someone picked up. A security key is the second step it is at sign-in.
        if own.passkey.is_some() && !assertion.user_verified {
            return Err(AdminError::StepUpFailed);
        }
        // The authenticator's counter moved whatever happens next, so keep it.
        match own.passkey {
            Some(id) => {
                self.passkeys
                    .record_passkey_use(id, &assertion.credential, self.env.now())
                    .await?;
            }
            None => {
                self.keys
                    .record_use(actor.user, &assertion.credential_id, &assertion.credential)
                    .await?;
            }
        }
        Ok(issue_token(&self.seal, &self.env, actor))
    }
}

impl<P, W, S, E, K> PasskeyStepper for PasskeyStepUp<P, W, S, E, K>
where
    P: PasskeyRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
    K: StepUpKeys,
{
    fn options<'a>(
        &'a self,
        actor: &'a Actor,
    ) -> BoxFuture<'a, Result<PasskeyStepUpChallenge, AdminError>> {
        Box::pin(self.make_options(actor))
    }

    fn check_challenge(&self, actor: &Actor, challenge: &[u8]) -> Result<(), AdminError> {
        self.open_challenge(actor, challenge).map(|_| ())
    }

    fn finish<'a>(
        &'a self,
        actor: &'a Actor,
        challenge: &'a [u8],
        response: &'a [u8],
    ) -> BoxFuture<'a, Result<Issued, AdminError>> {
        Box::pin(self.make_token(actor, challenge, response))
    }
}
