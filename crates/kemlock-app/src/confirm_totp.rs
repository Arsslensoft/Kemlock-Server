//! Confirm TOTP: enables an enrolled authenticator once a code from it checks, so a secret the
//! owner never managed to scan can't lock them out.

use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, Totp, TwoFactorMethod, TwoFactorRepo};
use crate::sealed::{PURPOSE_TOTP, open_bound, seal_bound};
use kemlock_domain::UserId;

#[derive(Debug)]
pub struct ConfirmTotp<F, S, O, E> {
    pub two_factor: F,
    pub seal: S,
    pub totp: O,
    pub env: E,
}

impl<F: TwoFactorRepo, S: SecretSeal, O: Totp, E: Platform> ConfirmTotp<F, S, O, E> {
    pub async fn execute(&self, user: UserId, code: &str) -> Result<(), AppError> {
        let mut enrolment = self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .find(|t| t.method == TwoFactorMethod::Totp)
            .ok_or(AppError::NotFound)?;
        let opened = open_bound(&self.seal, PURPOSE_TOTP, user, &enrolment.sealed_secret)
            .map_err(|_| AppError::Store("a stored TOTP secret doesn't open".to_owned()))?;
        if !self.totp.verify(&opened.value, code.trim(), self.env.now()) {
            return Err(AppError::Unauthorized);
        }
        if !enrolment.enabled || opened.legacy {
            // Turned on, and sealed to the account if it was stored the old way, while the row
            // still holds the secret the code was checked against: an enrolment removed or
            // replaced since is not undone.
            let from = enrolment.sealed_secret.clone();
            if opened.legacy {
                enrolment.sealed_secret = seal_bound(&self.seal, PURPOSE_TOTP, user, &opened.value);
            }
            enrolment.enabled = true;
            if !self.two_factor.replace_if_sealed(&from, &enrolment).await? {
                return Err(AppError::Invalid(
                    "the authenticator app changed meanwhile: set it up again",
                ));
            }
        }
        Ok(())
    }
}
