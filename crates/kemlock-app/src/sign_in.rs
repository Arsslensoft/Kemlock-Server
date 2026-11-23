//! Sign in: OPAQUE login (two messages), an optional second step, then a device and tokens.
//!
//! The server keeps no login state. The OPAQUE state goes to the client sealed under `server.key`
//! (purpose `"opaque-login"`) with a 5-minute expiry, and comes back with the client's last
//! message. The same trick carries the account between the password and a second step (purpose
//! `"two-factor-challenge"`), bound to the DPoP key that passed the password.

use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, PasswordAuth, SecretSeal, TokenRepo, TokenSigner, Totp, TwoFactorMethod,
    TwoFactorRepo, UserRepo, Zeroizing,
};
use crate::privacy::ensure_not_pending;
use crate::sealed::{Challenge, LoginState, PURPOSE_CHALLENGE, PURPOSE_LOGIN, PURPOSE_TOTP};
use crate::session::{DeviceInfo, Sessions, TokenPair};
use crate::sso::{MembershipFacts, RequireSso, SignInMethod};
use kemlock_domain::{Device, Email, User, UserId};
use subtle::ConstantTimeEq;

#[derive(Debug)]
/// `sso` is the Require SSO check: an account that a space requires to use single sign-on gets no
/// tokens here, once its password has proved to be right.
pub struct SignIn<U, D, T, F, P, S, O, K, E, V, M> {
    pub users: U,
    pub two_factor: F,
    pub auth: P,
    pub seal: S,
    pub totp: O,
    pub sessions: Sessions<D, T, K, E, V, F>,
    pub sso: RequireSso<M>,
}

#[derive(Clone, Debug)]
pub struct OpaqueStartInput {
    pub email: String,
    /// OPAQUE's `CredentialRequest`.
    pub request: Vec<u8>,
    /// The thumbprint of the DPoP key that signed this request. The login state is bound to it:
    /// only the same key can finish the login.
    pub jkt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueStarted {
    /// OPAQUE's `CredentialResponse`, for the client.
    pub response: Vec<u8>,
    /// The sealed server state; the client sends it back unread with its last message.
    pub login_state: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct OpaqueFinishInput {
    pub email: String,
    pub login_state: Vec<u8>,
    /// OPAQUE's `CredentialFinalization`.
    pub finalization: Vec<u8>,
    pub device: DeviceInfo,
    /// The thumbprint of the DPoP key that signed this request.
    pub jkt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondStep {
    /// A sealed challenge to send back with the code.
    pub challenge: Vec<u8>,
    pub methods: Vec<TwoFactorMethod>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedIn {
    Tokens(TokenPair),
    SecondStep(SecondStep),
}

#[derive(Clone, Debug)]
pub struct SecondStepInput {
    pub challenge: Vec<u8>,
    pub method: TwoFactorMethod,
    pub code: String,
    /// The thumbprint of the DPoP key that signed this request; must be the one that passed the
    /// password.
    pub jkt: String,
}

/// The credential identifier OPAQUE binds: the email, trimmed and lower-cased.
pub fn credential_id(email: &str) -> String {
    email.trim().to_lowercase()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl<U, D, T, F, P, S, O, K, E, V, M> SignIn<U, D, T, F, P, S, O, K, E, V, M>
where
    U: UserRepo,
    D: DeviceRepo,
    T: TokenRepo,
    F: TwoFactorRepo,
    P: PasswordAuth,
    S: SecretSeal,
    O: Totp,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    M: MembershipFacts,
{
    /// OPAQUE login, first message. An unknown email gets a response that looks real.
    pub async fn start(&self, input: OpaqueStartInput) -> Result<OpaqueStarted, AppError> {
        if input.email.len() > Email::MAX_LEN * 2 {
            return Err(AppError::Invalid("the email is too long"));
        }
        let credential = credential_id(&input.email);
        let user = match Email::parse(&input.email) {
            Ok(email) => self.users.by_email(&email).await?,
            Err(_) => None,
        };
        let record = user.as_ref().and_then(|u| u.opaque_record.as_deref());
        let (state, response) =
            self.auth
                .login_start(credential.as_bytes(), record, &input.request)?;
        let expires_at =
            (self.sessions.env.now() + self.sessions.config.challenge_ttl).unix_timestamp();
        let login_state = self.seal.seal(
            PURPOSE_LOGIN,
            &LoginState {
                expires_at,
                credential_id: credential,
                jkt: input.jkt,
                opaque: Zeroizing::new(state),
            }
            .encode(),
        );
        Ok(OpaqueStarted {
            response,
            login_state,
        })
    }

    /// OPAQUE login, last message. Tokens on success, or a second step the account requires.
    pub async fn finish(&self, input: OpaqueFinishInput) -> Result<SignedIn, AppError> {
        let state = self.open_login_state(&input.login_state)?;
        if !constant_time_eq(&state.credential_id, &credential_id(&input.email)) {
            return Err(AppError::Invalid(
                "the login state belongs to another email",
            ));
        }
        // A login state is bound to the DPoP key that asked for it: a state captured from one
        // device is no use to another key.
        if !constant_time_eq(&state.jkt, &input.jkt) {
            return Err(AppError::Unauthorized);
        }
        // The session key is for channel binding the Kemlock API doesn't use: the DPoP key is the
        // binding here. What matters is that the client's proof checked.
        self.auth
            .login_finish(&state.opaque, &input.finalization)
            .map_err(|_| AppError::Unauthorized)?;
        let email = Email::parse(&input.email).map_err(|_| AppError::Unauthorized)?;
        let user = self
            .users
            .by_email(&email)
            .await?
            .ok_or(AppError::Unauthorized)?;
        // Also only now: an account that is disabled says so to whoever holds its password, and
        // to nobody else.
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        ensure_not_pending(&self.users, user.id).await?;
        // Only now, with the password proved: the answer never tells a stranger which accounts
        // a space has locked to single sign-on.
        self.sso.check(&user, SignInMethod::Password).await?;

        let methods: Vec<TwoFactorMethod> = self
            .two_factor
            .list(user.id)
            .await?
            .into_iter()
            .filter(|t| t.enabled)
            .map(|t| t.method)
            .collect();
        if methods.is_empty() {
            let device = self
                .sessions
                .register_device(user.id, &input.device, &input.jkt)
                .await?;
            return self
                .complete(&user, device, &input.jkt)
                .await
                .map(SignedIn::Tokens);
        }

        // The device is registered only after the second step, so a stolen password alone
        // leaves no trace on the account's device list.
        let id = input.device.resolve(user.id, &self.sessions.env);
        let challenge = Challenge {
            expires_at: (self.sessions.env.now() + self.sessions.config.challenge_ttl)
                .unix_timestamp(),
            user: user.id,
            device: id,
            device_name: input.device.name,
            device_kind: input.device.kind,
            jkt: input.jkt,
        };
        Ok(SignedIn::SecondStep(SecondStep {
            challenge: self.seal.seal(PURPOSE_CHALLENGE, &challenge.encode()),
            methods,
        }))
    }

    /// The account a two-step challenge is for, if the challenge is genuine and fresh. The API
    /// uses it to count second-step failures per account before the code is looked at.
    pub fn challenge_user(&self, challenge: &[u8]) -> Result<UserId, AppError> {
        Ok(self.open_challenge(challenge)?.user)
    }

    fn open_challenge(&self, challenge: &[u8]) -> Result<Challenge, AppError> {
        let plain = self
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

    /// The second step: a code for one of the account's enabled methods.
    pub async fn second_step(&self, input: SecondStepInput) -> Result<TokenPair, AppError> {
        let challenge = self.open_challenge(&input.challenge)?;
        let now = self.sessions.env.now();
        if !constant_time_eq(&challenge.jkt, &input.jkt) {
            return Err(AppError::Unauthorized);
        }
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
        self.sso.check(&user, SignInMethod::Password).await?;
        let factor = self
            .two_factor
            .list(user.id)
            .await?
            .into_iter()
            .find(|t| t.enabled && t.method == input.method)
            .ok_or(AppError::Unauthorized)?;
        match factor.method {
            TwoFactorMethod::Totp => {
                let secret = self
                    .seal
                    .open(PURPOSE_TOTP, &factor.sealed_secret)
                    .map_err(|_| AppError::Store("a stored TOTP secret doesn't open".to_owned()))?;
                let step = self
                    .totp
                    .verify_step(&secret, input.code.trim(), now)
                    .ok_or(AppError::Unauthorized)?;
                // The same step can be accepted once: a code seen over a shoulder or in a
                // proxy log is useless for the rest of its window.
                if !self.two_factor.accept_totp_step(user.id, step).await? {
                    return Err(AppError::Unauthorized);
                }
            }
            // These have their own calls: a security key answers a challenge of its own
            // (`SecurityKeyStep`), and an emailed code, a YubiKey OTP or Duo need the mailer or
            // an outside service (`TwoStepSignIn`).
            TwoFactorMethod::WebAuthn
            | TwoFactorMethod::Email
            | TwoFactorMethod::YubiKey
            | TwoFactorMethod::Duo => {
                return Err(AppError::Invalid(
                    "this method is answered at its own endpoint",
                ));
            }
        }
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
        self.complete(&user, device, &input.jkt).await
    }

    /// Whether `sealed` is a genuine, unexpired login state. The API checks this before it
    /// remembers the state as used, so made-up states take no room in that memory.
    pub fn check_login_state(&self, sealed: &[u8]) -> Result<(), AppError> {
        self.open_login_state(sealed).map(|_| ())
    }

    fn open_login_state(&self, sealed: &[u8]) -> Result<LoginState, AppError> {
        let plain = self
            .seal
            .open(PURPOSE_LOGIN, sealed)
            .map_err(|_| AppError::Invalid("the login state is invalid"))?;
        let state =
            LoginState::decode(&plain).ok_or(AppError::Invalid("the login state is invalid"))?;
        if self.sessions.env.now().unix_timestamp() >= state.expires_at {
            return Err(AppError::Invalid("the login has expired"));
        }
        Ok(state)
    }

    async fn complete(
        &self,
        user: &User,
        device: Device,
        jkt: &str,
    ) -> Result<TokenPair, AppError> {
        let tokens = self.sessions.issue(user, &device, jkt, None).await?;
        self.sessions
            .record("auth.sign_in", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }
}
