//! Confirm TOTP: enables an enrolled authenticator once a code from it checks, so a secret the
//! owner never managed to scan can't lock them out.

use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, Totp, TwoFactorMethod, TwoFactorRepo};
use crate::sealed::PURPOSE_TOTP;
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
        let secret = self
            .seal
            .open(PURPOSE_TOTP, &enrolment.sealed_secret)
            .map_err(|_| AppError::Store("a stored TOTP secret doesn't open".to_owned()))?;
        if !self.totp.verify(&secret, code.trim(), self.env.now()) {
            return Err(AppError::Unauthorized);
        }
        if !enrolment.enabled {
            enrolment.enabled = true;
            self.two_factor.put(&enrolment).await?;
        }
        Ok(())
    }
}
