//! An emailed code, a YubiKey OTP or Duo as the second step of a Kemlock sign-in.
//!
//! The first step (OPAQUE, or an identity provider) ended in a sealed two-step challenge that names
//! the account, the device and the DPoP key. Here that challenge asks for an emailed code or a
//! Duo prompt, then takes the answer, registers the device and issues the tokens, as
//! `SignIn::second_step` does for an authenticator code.

use super::TwoStep;
use super::recovery::{RecoveryCodeRepo, RecoveryCodes};
use crate::error::AppError;
use crate::notices::{Notice, Notices, TwoStepRecoveredNotice};
use crate::passkeys::ChallengeRepo;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, TokenRepo, TokenSigner, TwoFactorMethod, TwoFactorRepo,
    UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::sealed::{Challenge, PURPOSE_CHALLENGE};
use crate::session::{DeviceInfo, Sessions, TokenPair};
use kemlock_domain::UserId;
use subtle::ConstantTimeEq;

/// The Kemlock API's second step for the methods beyond an authenticator app and a security key.
#[derive(Debug)]
pub struct TwoStepSignIn<U, F, S, E, C, D, T, K, V> {
    pub users: U,
    pub two_step: TwoStep<F, S, E, C>,
    pub sessions: Sessions<D, T, K, E, V, F>,
}

/// An answer to a second step.
#[derive(Clone, Debug)]
pub struct TwoStepInput {
    pub challenge: Vec<u8>,
    /// `Email`, `YubiKey` or `Duo`.
    pub method: TwoFactorMethod,
    /// The emailed code, the YubiKey OTP, or what Duo's redirect brought back (`<code>|<state>`).
    pub code: String,
    /// The thumbprint of the DPoP key that signed this request; must be the one that passed the
    /// password.
    pub jkt: String,
    /// The client's kind (`web`, `desktop`, `mobile`, `cli`), which Duo's redirect needs; it is
    /// the one given when the prompt was started.
    pub client: String,
}

impl<U, F, S, E, C, D, T, K, V> TwoStepSignIn<U, F, S, E, C, D, T, K, V>
where
    U: UserRepo,
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    V: EventLog,
{
    fn open_challenge(&self, challenge: &[u8]) -> Result<Challenge, AppError> {
        let plain = self
            .two_step
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

    /// Sends a code to the address the account set up. An account without the method gets
    /// `Unauthorized`, like any wrong answer to a second step.
    pub async fn send_email_code(&self, challenge: &[u8], jkt: &str) -> Result<(), AppError> {
        let challenge = self.bound(challenge, jkt)?;
        let user = self
            .users
            .by_id(challenge.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.two_step
            .email_send_login_code(&user)
            .await
            .map_err(|e| match e {
                AppError::NotFound => AppError::Unauthorized,
                other => other,
            })
    }

    /// Starts a Duo prompt: the address to send the person to. `client` is the client's kind.
    pub async fn duo_url(
        &self,
        challenge: &[u8],
        jkt: &str,
        client: &str,
    ) -> Result<String, AppError> {
        let challenge = self.bound(challenge, jkt)?;
        let user = self
            .users
            .by_id(challenge.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.two_step
            .duo_start(&user, client, &challenge.device.0.to_string())
            .await
    }

    /// Checks the answer and signs the device in. A wrong, repeated or stale answer is
    /// `Unauthorized`.
    pub async fn verify(&self, input: TwoStepInput) -> Result<TokenPair, AppError> {
        if !matches!(
            input.method,
            TwoFactorMethod::Email | TwoFactorMethod::YubiKey | TwoFactorMethod::Duo
        ) {
            return Err(AppError::Invalid(
                "this method is answered at its own endpoint",
            ));
        }
        let challenge = self.bound(&input.challenge, &input.jkt)?;
        let user = self
            .users
            .by_id(challenge.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        // The password was proved with the challenge, so saying why is safe; an account disabled
        // since then gets no code looked at.
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        ensure_not_pending(&self.users, user.id).await?;
        let factor = self
            .two_step
            .two_factor
            .list(user.id)
            .await?
            .into_iter()
            .find(|t| t.method == input.method)
            .filter(|t| self.two_step.usable(t))
            .ok_or(AppError::Unauthorized)?;
        self.two_step
            .verify_login(
                &user,
                factor.method,
                &input.code,
                &input.client,
                &challenge.device.0.to_string(),
            )
            .await?;
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
                &input.jkt,
            )
            .await?;
        self.sessions
            .start_sso_session(challenge.sso.as_ref(), user.id, &device)
            .await?;
        let tokens = self
            .sessions
            .issue(&user, &device, &input.jkt, None)
            .await?;
        self.sessions
            .record("auth.sign_in", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }
}

/// The Kemlock API's second step answered with the recovery code: it switches every method off,
/// is spent, and signs the device in.
#[derive(Debug)]
pub struct RecoverySignIn<U, R, F, S, E, D, T, K, V> {
    pub users: U,
    pub recovery: RecoveryCodes<R, F, S, E>,
    pub sessions: Sessions<D, T, K, E, V, F>,
    /// Tells the account's owner by mail that the recovery code was used.
    pub notices: Notices,
}

impl<U, R, F, S, E, D, T, K, V> RecoverySignIn<U, R, F, S, E, D, T, K, V>
where
    U: UserRepo,
    R: RecoveryCodeRepo,
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    V: EventLog,
{
    fn open_challenge(&self, challenge: &[u8]) -> Result<Challenge, AppError> {
        let plain = self
            .recovery
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

    /// Checks the code, removes every method and signs the device in. A wrong or spent code is
    /// `Unauthorized`.
    pub async fn recover(
        &self,
        challenge: &[u8],
        code: &str,
        jkt: &str,
    ) -> Result<TokenPair, AppError> {
        let challenge = self.bound(challenge, jkt)?;
        let user = self
            .users
            .by_id(challenge.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        // The password was proved with the challenge, so saying why is safe; an account disabled
        // since then gets no code looked at.
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        self.recovery.recover(user.id, code).await?;
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
            .record("auth.two_step_recovered", user.id, Some(device.id))
            .await;
        self.notices
            .send(Notice::TwoStepRecovered(TwoStepRecoveredNotice {
                to: user.email.clone(),
                at: self.sessions.env.now(),
            }))
            .await;
        self.sessions
            .record("auth.sign_in", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }
}
