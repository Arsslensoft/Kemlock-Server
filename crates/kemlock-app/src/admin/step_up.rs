//! Step-up: an admin's writes need a password or two-step check made just now.
//!
//! The access token proves who is calling; it can be minutes old, and a laptop left open would
//! let anyone at the keyboard change the server. So the console asks the admin to prove it again
//! before a write, with a re-run OPAQUE login (their master password, which never leaves the
//! device) or a TOTP code, and gets a step-up token. The token is sealed under `server.key`, so
//! the server keeps no state for it; it names the account and the device it was made for, and
//! expires after [`TOKEN_TTL`]. Writes send it in the `Step-Up-Token` header.
//!
//! A passkey check is a third way ([`super::passkey_step_up`]); the token is the same.

use super::error::AdminError;
use crate::authenticate::Actor;
use crate::b64url;
use crate::platform::Platform;
use crate::ports::{
    PasswordAuth, SecretSeal, Totp, TwoFactorMethod, TwoFactorRepo, UserRepo, Zeroizing,
};
use crate::sealed::PURPOSE_TOTP;
use crate::sign_in::credential_id;
use kemlock_domain::UserId;
use time::Duration;
use uuid::Uuid;

/// `SecretSeal` purpose of a step-up token.
pub const PURPOSE_TOKEN: &str = "admin-step-up";
/// `SecretSeal` purpose of the OPAQUE state between the two messages of a step-up login.
pub const PURPOSE_LOGIN: &str = "admin-step-up-login";
/// How long a step-up token is good for.
pub const TOKEN_TTL: Duration = Duration::minutes(5);
/// How long a step-up login may take between its two messages.
pub const LOGIN_TTL: Duration = Duration::minutes(2);

const TOKEN_VERSION: u8 = 1;

/// A step-up token that was just made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The token, base64url; sent back as the `Step-Up-Token` header.
    pub token: String,
    /// When it stops working, in Unix seconds.
    pub expires_at: i64,
}

/// The first message of a step-up login, answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordStarted {
    /// OPAQUE's `CredentialResponse`.
    pub response: Vec<u8>,
    /// The sealed server state; sent back unread with the last message.
    pub login_state: Vec<u8>,
}

#[derive(Debug)]
pub struct StepUp<U, F, P, S, T, E> {
    pub users: U,
    pub two_factor: F,
    pub auth: P,
    pub seal: S,
    pub totp: T,
    pub env: E,
}

/// Makes a step-up token for `actor`: sealed under `server.key`, good for [`TOKEN_TTL`], naming
/// the account and the device. Every way of proving oneself (password, authenticator code,
/// passkey) ends here.
pub fn issue_token<S: SecretSeal, E: Platform>(seal: &S, env: &E, actor: &Actor) -> Issued {
    let expires_at = (env.now() + TOKEN_TTL).unix_timestamp();
    let mut payload = Vec::with_capacity(41);
    payload.push(TOKEN_VERSION);
    payload.extend_from_slice(actor.user.as_bytes());
    payload.extend_from_slice(actor.device.as_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    Issued {
        token: b64url::encode(&seal.seal(PURPOSE_TOKEN, &payload)),
        expires_at,
    }
}

fn invalid(why: &str) -> AdminError {
    AdminError::Invalid(why.to_owned())
}

impl<U, F, P, S, T, E> StepUp<U, F, P, S, T, E>
where
    U: UserRepo,
    F: TwoFactorRepo,
    P: PasswordAuth,
    S: SecretSeal,
    T: Totp,
    E: Platform,
{
    fn issue(&self, actor: &Actor) -> Issued {
        issue_token(&self.seal, &self.env, actor)
    }

    /// Whether `token` is a fresh step-up token made for this actor on this device.
    pub fn check(&self, actor: &Actor, token: &str) -> Result<(), AdminError> {
        let sealed = b64url::decode(token).ok_or(AdminError::StepUpRequired)?;
        let plain = self
            .seal
            .open(PURPOSE_TOKEN, &sealed)
            .map_err(|_| AdminError::StepUpRequired)?;
        let bytes: &[u8] = &plain;
        if bytes.len() != 41 || bytes[0] != TOKEN_VERSION {
            return Err(AdminError::StepUpRequired);
        }
        let user = Uuid::from_slice(&bytes[1..17]).map_err(|_| AdminError::StepUpRequired)?;
        let device = Uuid::from_slice(&bytes[17..33]).map_err(|_| AdminError::StepUpRequired)?;
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&bytes[33..41]);
        let expires_at = i64::from_be_bytes(expiry);
        if user != actor.user.0
            || device != actor.device.0
            || self.env.now().unix_timestamp() >= expires_at
        {
            return Err(AdminError::StepUpRequired);
        }
        Ok(())
    }

    /// A step-up login, first message: the admin's own OPAQUE login, run again.
    pub async fn password_start(
        &self,
        actor: &Actor,
        request: &[u8],
    ) -> Result<PasswordStarted, AdminError> {
        let user = self
            .users
            .by_id(actor.user)
            .await?
            .ok_or(AdminError::NotFound)?;
        let record = user.opaque_record.as_deref().ok_or(AdminError::State(
            "this account has no Kemlock password to check; use a code from the authenticator app",
        ))?;
        let credential = credential_id(user.email.as_str());
        let (state, response) = self
            .auth
            .login_start(credential.as_bytes(), Some(record), request)
            .map_err(|_| invalid("the login request isn't valid"))?;
        let expires_at = (self.env.now() + LOGIN_TTL).unix_timestamp();
        let mut payload = Vec::with_capacity(24 + state.len());
        payload.extend_from_slice(&expires_at.to_be_bytes());
        payload.extend_from_slice(actor.user.as_bytes());
        payload.extend_from_slice(&state);
        Ok(PasswordStarted {
            response,
            login_state: self.seal.seal(PURPOSE_LOGIN, &payload),
        })
    }

    /// The account a step-up login state is for, if it is genuine and fresh. The API remembers
    /// a state as used only after this passes, so made-up states take no room.
    pub fn login_state_user(&self, sealed: &[u8]) -> Result<UserId, AdminError> {
        let (user, _) = self.open_login_state(sealed)?;
        Ok(UserId(user))
    }

    fn open_login_state(&self, sealed: &[u8]) -> Result<(Uuid, Zeroizing<Vec<u8>>), AdminError> {
        let plain = self
            .seal
            .open(PURPOSE_LOGIN, sealed)
            .map_err(|_| invalid("the login state isn't valid"))?;
        let bytes: &[u8] = &plain;
        if bytes.len() < 24 {
            return Err(invalid("the login state isn't valid"));
        }
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&bytes[..8]);
        if self.env.now().unix_timestamp() >= i64::from_be_bytes(expiry) {
            return Err(invalid("the login has expired"));
        }
        let user =
            Uuid::from_slice(&bytes[8..24]).map_err(|_| invalid("the login state isn't valid"))?;
        Ok((user, Zeroizing::new(bytes[24..].to_vec())))
    }

    /// A step-up login, last message: a token when the password was right.
    pub async fn password_finish(
        &self,
        actor: &Actor,
        login_state: &[u8],
        finalization: &[u8],
    ) -> Result<Issued, AdminError> {
        let (user, state) = self.open_login_state(login_state)?;
        // A state is for the account that started it; another admin can't finish it.
        if user != actor.user.0 {
            return Err(AdminError::StepUpFailed);
        }
        self.auth
            .login_finish(&state, finalization)
            .map_err(|_| AdminError::StepUpFailed)?;
        Ok(self.issue(actor))
    }

    /// A token for a code from the admin's authenticator app. A code is good once, so one used
    /// to sign in a moment ago has to be waited out.
    pub async fn totp(&self, actor: &Actor, code: &str) -> Result<Issued, AdminError> {
        let factor = self
            .two_factor
            .list(actor.user)
            .await?
            .into_iter()
            .find(|t| t.enabled && t.method == TwoFactorMethod::Totp)
            .ok_or(AdminError::State(
                "this account has no authenticator app; use the password check",
            ))?;
        let secret = self
            .seal
            .open(PURPOSE_TOTP, &factor.sealed_secret)
            .map_err(|_| {
                AdminError::App(crate::AppError::Store(
                    "a stored TOTP secret doesn't open".to_owned(),
                ))
            })?;
        let step = self
            .totp
            .verify_step(&secret, code.trim(), self.env.now())
            .ok_or(AdminError::StepUpFailed)?;
        if !self.two_factor.accept_totp_step(actor.user, step).await? {
            return Err(AdminError::StepUpFailed);
        }
        Ok(self.issue(actor))
    }
}
