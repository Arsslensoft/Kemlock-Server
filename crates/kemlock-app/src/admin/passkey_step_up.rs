//! Step-up with a passkey: the admin proves it is them with a fresh assertion from one of their
//! own passkeys, with user verification required, and gets the same step-up token the password
//! and the authenticator code give.
//!
//! It runs on the passkeys use cases' ports and rules ([`WebAuthn`], [`PasskeyRepo`], the
//! `Passkey` credential kind that demands user verification). The challenge is sealed under
//! `server.key` and names the account and the device it was made for, so it can't be answered
//! from another account or another signed-in device; it expires after [`CHALLENGE_TTL`], and the
//! API remembers a returned challenge as used, so it is good once. The challenge lists the
//! admin's own credentials, so an authenticator holding any other passkey has nothing to offer.

use super::error::AdminError;
use super::step_up::{Issued, issue_token};
use crate::authenticate::Actor;
use crate::b64url;
use crate::notices::BoxFuture;
use crate::passkeys::{CredentialKind, PasskeyRepo, WebAuthn, ceremony_error};
use crate::platform::Platform;
use crate::ports::SecretSeal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
}

/// The first half of a passkey step-up.
#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyStepUpChallenge {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`.
    pub options: Value,
    /// The sealed state; sent back unread with the authenticator's answer.
    pub challenge: Vec<u8>,
}

/// Passkey step-up over its ports.
#[derive(Debug)]
pub struct PasskeyStepUp<P, W, S, E> {
    pub passkeys: P,
    pub webauthn: W,
    pub seal: S,
    pub env: E,
}

/// What the admin API holds: [`PasskeyStepUp`] without its port types.
pub trait PasskeyStepper: Send + Sync {
    /// The options for a step-up by `actor`, over the credentials of their own passkeys.
    /// `State` when the account has none.
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

impl<P, W, S, E> PasskeyStepUp<P, W, S, E>
where
    P: PasskeyRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
{
    /// The WebAuthn state of a challenge that is for `actor`, genuine and fresh.
    fn open_challenge(&self, actor: &Actor, sealed: &[u8]) -> Result<Vec<u8>, AdminError> {
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
        b64url::decode(&challenge.state).ok_or_else(invalid)
    }

    async fn make_options(&self, actor: &Actor) -> Result<PasskeyStepUpChallenge, AdminError> {
        let passkeys = self.passkeys.passkeys_of(actor.user).await?;
        if passkeys.is_empty() {
            return Err(AdminError::State(
                "this account has no passkey; use the password check or a code",
            ));
        }
        let credentials: Vec<&[u8]> = passkeys.iter().map(|p| p.credential.as_slice()).collect();
        let started = self
            .webauthn
            .start_authentication(CredentialKind::Passkey, &credentials)
            .map_err(|e| AdminError::App(ceremony_error(e)))?;
        let exp = (self.env.now() + CHALLENGE_TTL).unix_timestamp();
        let plain = serde_json::to_vec(&Challenge {
            v: CHALLENGE_VERSION,
            exp,
            user: actor.user.0,
            device: actor.device.0,
            state: b64url::encode(&started.state),
        })
        .map_err(|_| {
            AdminError::App(crate::AppError::Store(
                "couldn't encode a passkey challenge".to_owned(),
            ))
        })?;
        Ok(PasskeyStepUpChallenge {
            options: started.options,
            challenge: self.seal.seal(PURPOSE_CHALLENGE, &plain),
        })
    }

    async fn make_token(
        &self,
        actor: &Actor,
        challenge: &[u8],
        response: &[u8],
    ) -> Result<Issued, AdminError> {
        let state = self.open_challenge(actor, challenge)?;
        let ids = self
            .webauthn
            .response_ids(response)
            .map_err(|_| AdminError::StepUpFailed)?;
        // One of the admin's own passkeys, and no one else's.
        let passkey = self
            .passkeys
            .passkeys_of(actor.user)
            .await?
            .into_iter()
            .find(|p| p.credential_id == ids.credential_id)
            .ok_or(AdminError::StepUpFailed)?;
        if let Some(handle) = &ids.user_handle
            && !bool::from(handle.as_slice().ct_eq(actor.user.as_bytes()))
        {
            return Err(AdminError::StepUpFailed);
        }
        let assertion = self
            .webauthn
            .finish_authentication(
                CredentialKind::Passkey,
                &state,
                response,
                &[passkey.credential.as_slice()],
            )
            .map_err(|e| {
                tracing::debug!(error = %e, "a passkey step-up was refused");
                AdminError::StepUpFailed
            })?;
        // A passkey is possession plus a PIN or a body check: without the second, it is no more
        // than a key someone picked up.
        if !assertion.user_verified {
            return Err(AdminError::StepUpFailed);
        }
        // The authenticator's counter moved whatever happens next, so keep it.
        self.passkeys
            .record_passkey_use(passkey.id, &assertion.credential, self.env.now())
            .await?;
        Ok(issue_token(&self.seal, &self.env, actor))
    }
}

impl<P, W, S, E> PasskeyStepper for PasskeyStepUp<P, W, S, E>
where
    P: PasskeyRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
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
