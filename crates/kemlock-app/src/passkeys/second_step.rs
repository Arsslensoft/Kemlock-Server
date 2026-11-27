//! The security key as the second step of a Kemlock sign-in.
//!
//! The first step (OPAQUE, or an identity provider) ended in a sealed two-step challenge that names
//! the account, the device and the DPoP key (`sign_in`). Here that challenge asks for the key's
//! options, then takes the key's answer and registers the device and issues the tokens, as
//! `SignIn::second_step` does for an authenticator code.

use super::ports::ChallengeRepo;
use super::security_keys::{SecurityKeyError, SecurityKeys};
use super::webauthn::WebAuthn;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, TokenRepo, TokenSigner, TwoFactorRepo, UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::sealed::{Challenge, PURPOSE_CHALLENGE};
use crate::session::{DeviceInfo, Sessions, TokenPair};
use kemlock_domain::UserId;
use serde_json::Value;
use subtle::ConstantTimeEq;

/// The second step with a security key.
#[derive(Debug)]
pub struct SecurityKeyStep<U, F, C, W, S, D, T, K, E, V> {
    pub keys: SecurityKeys<U, F, C, W, S, E>,
    pub sessions: Sessions<D, T, K, E, V, F>,
}

impl<U, F, C, W, S, D, T, K, E, V> SecurityKeyStep<U, F, C, W, S, D, T, K, E, V>
where
    U: UserRepo,
    F: TwoFactorRepo,
    C: ChallengeRepo,
    W: WebAuthn,
    S: SecretSeal,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
{
    fn open_challenge(&self, challenge: &[u8]) -> Result<Challenge, AppError> {
        let plain = self
            .keys
            .seal
            .open(PURPOSE_CHALLENGE, challenge)
            .map_err(|_| AppError::Invalid("the challenge is invalid"))?;
        let challenge =
            Challenge::decode(&plain).ok_or(AppError::Invalid("the challenge is invalid"))?;
        if self.sessions.env.now().unix_timestamp() >= challenge.expires_at {
            return Err(AppError::Invalid("the challenge has expired"));
        }
        Ok(challenge)
    }

    /// The account a two-step challenge is for, if the challenge is genuine and fresh. The API
    /// counts second-step failures against it.
    pub fn challenge_user(&self, challenge: &[u8]) -> Result<UserId, AppError> {
        Ok(self.open_challenge(challenge)?.user)
    }

    /// Opens the challenge and checks it is for the DPoP key that asks.
    fn bound(&self, challenge: &[u8], jkt: &str) -> Result<Challenge, AppError> {
        let challenge = self.open_challenge(challenge)?;
        if !bool::from(challenge.jkt.as_bytes().ct_eq(jkt.as_bytes())) {
            return Err(AppError::Unauthorized);
        }
        Ok(challenge)
    }

    /// The options for `navigator.credentials.get`, listing the account's security keys. Asking
    /// again replaces the challenge. An account with no key is `Unauthorized`, like any wrong
    /// answer to a second step.
    pub async fn options(&self, challenge: &[u8], jkt: &str) -> Result<Value, AppError> {
        let challenge = self.bound(challenge, jkt)?;
        self.keys
            .start_login(challenge.user)
            .await
            .map_err(|e| match e {
                AppError::NotFound => AppError::Unauthorized,
                other => other,
            })
    }

    /// Checks the key's answer (`PublicKeyCredential.toJSON()`) and signs the device in. A wrong,
    /// repeated or stale answer is `Unauthorized`.
    pub async fn verify(
        &self,
        challenge: &[u8],
        response: &[u8],
        jkt: &str,
    ) -> Result<TokenPair, AppError> {
        let challenge = self.bound(challenge, jkt)?;
        let user = self
            .keys
            .users
            .by_id(challenge.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.keys
            .finish_login(user.id, response)
            .await
            .map_err(|e| match e {
                SecurityKeyError::App(e) => e,
                _ => AppError::Unauthorized,
            })?;
        // The key is proved, so the account may be told it is disabled.
        if self.keys.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        ensure_not_pending(&self.keys.users, user.id).await?;
        let device = self
            .sessions
            .register_device(
                user.id,
                &DeviceInfo {
                    id: Some(challenge.device),
                    name: challenge.device_name,
                    kind: challenge.device_kind,
                    bitwarden_identifier: None,
                },
                jkt,
            )
            .await?;
        self.sessions
            .start_sso_session(challenge.sso.as_ref(), user.id, &device)
            .await?;
        let tokens = self.sessions.issue(&user, &device, jkt, None).await?;
        self.sessions
            .record("auth.sign_in", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }
}
