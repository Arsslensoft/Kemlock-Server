//! The two-step methods beyond an authenticator app and a security key: emailed codes (Bitwarden's
//! type 1), Duo (2) and YubiKey OTPs (3), as Vaultwarden 1.37.5 has them.
//!
//! Each is one `two_factor` row (method `email`, `duo` or `yubikey`) whose data is Vaultwarden's
//! own JSON sealed under `server.key` ([`data`]), so a setup moved from Vaultwarden works as it
//! did. [`TwoStep`] is the use case both APIs share: setting a method up and taking it off, and
//! checking its code at sign-in. [`TwoStepSignIn`] is the Kemlock API's second step with them.
//!
//! - **Email**: a code of `EMAIL_TOKEN_SIZE` digits goes to the address through the notice
//!   sender (so through the mailer), lives `EMAIL_EXPIRATION_TIME` seconds and survives
//!   `EMAIL_ATTEMPTS_LIMIT` wrong entries. A new address is confirmed with a first code before
//!   the method is on.
//! - **YubiKey**: the account keeps the public ids of up to five keys; an OTP is checked
//!   against Yubico's service ([`Yubico`]).
//! - **Duo**: the Universal Prompt (OIDC). The person is sent to Duo's address and comes back
//!   with a code and a state, which Duo's token endpoint trades for the result ([`Duo`]). An
//!   account uses the integration keys it saved, or the server's.

mod data;
mod duo;
mod email;
mod ports;
mod protected;
mod recovery;
mod step;
mod yubikey;

pub use data::{
    DuoKeys, EmailData, GLOBAL_KEYS_MARK, PROVIDER_DUO, PROVIDER_EMAIL, PROVIDER_YUBIKEY,
    PURPOSE_DUO, PURPOSE_EMAIL, PURPOSE_YUBIKEY, YubikeyData, method_of_provider, obscure_email,
    provider_type,
};
pub use duo::DuoStatus;
pub use email::EmailChecked;
pub use ports::{Duo, DuoError, DuoPrompt, NoDuo, NoYubico, TwoStepSettings, Yubico, YubicoError};
pub use protected::{PROTECTED_REQUEST_DELAY_SECS, ProtectedError};
pub use recovery::{PURPOSE_LEGACY_RECOVERY, PURPOSE_RECOVERY, RecoveryCodeRepo, RecoveryCodes};
pub use step::{RecoverySignIn, TwoStepInput, TwoStepSignIn};

use crate::error::AppError;
use crate::notices::Notices;
use crate::passkeys::ChallengeRepo;
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::User;
use serde_json::{Value, json};
use std::sync::Arc;

/// The emailed-code, YubiKey and Duo methods over their ports.
pub struct TwoStep<F, S, E, C> {
    pub two_factor: F,
    pub seal: S,
    pub env: E,
    /// Where an address waiting for its first code and a Duo prompt keep their state.
    pub challenges: C,
    /// Sends the emailed codes.
    pub notices: Notices,
    pub yubico: Arc<dyn Yubico>,
    pub duo: Arc<dyn Duo>,
    pub settings: TwoStepSettings,
}

impl<F, S, E, C> std::fmt::Debug for TwoStep<F, S, E, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoStep")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<F, S, E, C> TwoStep<F, S, E, C>
where
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
{
    /// Whether `factor` can be answered on this server: it is on, and its service is set up. A
    /// security key's own switch is the relying party, which the caller knows.
    pub fn usable(&self, factor: &TwoFactor) -> bool {
        if !factor.enabled {
            return false;
        }
        match factor.method {
            TwoFactorMethod::Totp | TwoFactorMethod::WebAuthn => true,
            TwoFactorMethod::Email => self.settings.email_enabled,
            TwoFactorMethod::YubiKey => self.settings.yubico_enabled,
            TwoFactorMethod::Duo => self.duo_usable(factor),
        }
    }

    /// What the 400 that asks for a second step carries under `TwoFactorProviders2` for this
    /// method: the address (hidden) of an email, whether a YubiKey reads over NFC, the address of
    /// Duo's prompt; `null` for the rest.
    pub async fn login_options(
        &self,
        user: &User,
        method: TwoFactorMethod,
        client: &str,
        device: &str,
    ) -> Result<Value, AppError> {
        match method {
            TwoFactorMethod::Email => {
                let address = self
                    .email_address(user.id)
                    .await?
                    .ok_or(AppError::Invalid("no email address is set up"))?;
                Ok(json!({ "Email": obscure_email(&address) }))
            }
            TwoFactorMethod::YubiKey => {
                let data = self
                    .yubikey_keys(user.id)
                    .await?
                    .ok_or(AppError::Invalid("no YubiKey is registered"))?;
                Ok(json!({ "Nfc": data.nfc }))
            }
            TwoFactorMethod::Duo => {
                let url = self.duo_start(user, client, device).await?;
                Ok(json!({ "AuthUrl": url }))
            }
            TwoFactorMethod::Totp | TwoFactorMethod::WebAuthn => Ok(Value::Null),
        }
    }

    /// Checks the code of an emailed code, a YubiKey or Duo. `device` is the client's device
    /// identifier and `client` its kind, which Duo binds its prompt to. Wrong is `Unauthorized`.
    pub async fn verify_login(
        &self,
        user: &User,
        method: TwoFactorMethod,
        code: &str,
        client: &str,
        device: &str,
    ) -> Result<(), AppError> {
        match method {
            TwoFactorMethod::Email => self.email_verify(user.id, code).await,
            TwoFactorMethod::YubiKey => self.yubikey_verify(user.id, code).await,
            TwoFactorMethod::Duo => self.duo_verify(user, client, device, code).await,
            TwoFactorMethod::Totp | TwoFactorMethod::WebAuthn => Err(AppError::Invalid(
                "this method is answered at its own endpoint",
            )),
        }
    }
}
