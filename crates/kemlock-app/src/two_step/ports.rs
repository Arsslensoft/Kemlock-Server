//! The services the second steps call out to, and the settings that switch them on.

use super::data::DuoKeys;
use crate::notices::BoxFuture;

/// Why Yubico's service didn't accept an OTP.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum YubicoError {
    /// The service said no: a made-up, replayed or damaged OTP, or an answer it didn't sign.
    #[error("the OTP was refused")]
    Rejected,
    /// The service couldn't be asked, or isn't set up.
    #[error("Yubico's service couldn't be asked: {0}")]
    Unavailable(String),
}

/// Checks a YubiKey OTP with Yubico's validation service (`YUBICO_CLIENT_ID`,
/// `YUBICO_SECRET_KEY`, `YUBICO_SERVER`). Object safe, so the server holds one behind an `Arc`.
pub trait Yubico: Send + Sync {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>>;
}

/// A Yubico that isn't set up: it refuses everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoYubico;

impl Yubico for NoYubico {
    fn verify<'a>(&'a self, _otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(async { Err(YubicoError::Unavailable("Yubico isn't set up".to_owned())) })
    }
}

/// Why Duo didn't accept a prompt or an answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DuoError {
    /// Duo said no: the code, the user or the nonce didn't check.
    #[error("Duo refused")]
    Rejected,
    /// Duo couldn't be reached, answered unreadably, or isn't set up.
    #[error("Duo couldn't be asked: {0}")]
    Unavailable(String),
}

/// One Duo Universal Prompt: who is signing in, from what, and the state and nonce that tie the
/// prompt to its answer.
#[derive(Clone, Copy, Debug)]
pub struct DuoPrompt<'a> {
    pub keys: &'a DuoKeys,
    /// The account's email address, which Duo knows the person by.
    pub username: &'a str,
    /// The client asking (`web`, `browser`, `desktop`, `mobile`, `cli`), which Duo's redirect
    /// page needs to tell the app to carry on.
    pub client: &'a str,
    /// The device's identifier. The nonce Duo signs is bound to it.
    pub device: &'a str,
    /// The OAuth state, which comes back with the code.
    pub state: &'a str,
    /// The OIDC nonce, before it is bound to the device.
    pub nonce: &'a str,
}

/// Duo's Universal Prompt (OIDC). Object safe, so the server holds one behind an `Arc`.
pub trait Duo: Send + Sync {
    /// Checks that the keys are Duo's (`/auth/v2/check`), when an account saves its own.
    fn check_keys<'a>(&'a self, keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>>;

    /// Checks Duo is up and builds the address the person is sent to for their prompt.
    fn auth_url<'a>(&'a self, prompt: &'a DuoPrompt<'a>)
    -> BoxFuture<'a, Result<String, DuoError>>;

    /// Trades the code Duo sent back for the result of the prompt, and checks it was for this
    /// person and this device.
    fn verify<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
        code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>>;
}

/// A Duo that isn't set up: it refuses everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDuo;

impl Duo for NoDuo {
    fn check_keys<'a>(&'a self, _keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async { Err(DuoError::Unavailable("Duo isn't set up".to_owned())) })
    }

    fn auth_url<'a>(
        &'a self,
        _prompt: &'a DuoPrompt<'a>,
    ) -> BoxFuture<'a, Result<String, DuoError>> {
        Box::pin(async { Err(DuoError::Unavailable("Duo isn't set up".to_owned())) })
    }

    fn verify<'a>(
        &'a self,
        _prompt: &'a DuoPrompt<'a>,
        _code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async { Err(DuoError::Unavailable("Duo isn't set up".to_owned())) })
    }
}

/// The settings of the second steps, Vaultwarden's names in brackets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoStepSettings {
    /// Whether an emailed code is offered (`_ENABLE_EMAIL_2FA`, which Vaultwarden turns on with
    /// SMTP). Without a mailer the codes would never arrive.
    pub email_enabled: bool,
    /// How many digits a code has (`EMAIL_TOKEN_SIZE`, 6).
    pub email_token_size: u8,
    /// How long a code works, in seconds (`EMAIL_EXPIRATION_TIME`, 600).
    pub email_expiration_secs: u32,
    /// How many wrong entries a code survives (`EMAIL_ATTEMPTS_LIMIT`, 3).
    pub email_attempts_limit: u8,
    /// Whether YubiKeys are offered: the client id and the secret key are set
    /// (`YUBICO_CLIENT_ID`, `YUBICO_SECRET_KEY`, `_ENABLE_YUBICO`).
    pub yubico_enabled: bool,
    /// The Duo integration every account uses unless it saved its own (`DUO_HOST`, `DUO_IKEY`,
    /// `DUO_SKEY`, `_ENABLE_DUO`); `None` when there is none.
    pub duo_global: Option<DuoKeys>,
}

impl Default for TwoStepSettings {
    /// Nothing offered but the numbers Vaultwarden defaults to.
    fn default() -> Self {
        TwoStepSettings {
            email_enabled: false,
            email_token_size: 6,
            email_expiration_secs: 600,
            email_attempts_limit: 3,
            yubico_enabled: false,
            duo_global: None,
        }
    }
}
