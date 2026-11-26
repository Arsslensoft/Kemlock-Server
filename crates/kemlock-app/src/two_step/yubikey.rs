//! YubiKey OTPs (Bitwarden's type 3), as Vaultwarden's `yubikey.rs` has them.

use super::TwoStep;
use super::data::{PURPOSE_YUBIKEY, YubikeyData, open_row, sealed_row};
use super::ports::YubicoError;
use crate::error::AppError;
use crate::passkeys::ChallengeRepo;
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::UserId;

/// How many keys an account may register: the web vault has five fields.
const MAX_YUBIKEYS: usize = 5;
/// The length of a YubiKey OTP: a 12-character public id and 32 of one-time code.
const OTP_LEN: usize = 44;
/// The length of a public id.
const ID_LEN: usize = 12;

impl<F, S, E, C> TwoStep<F, S, E, C>
where
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
{
    /// The registered keys' ids, when the method is on.
    pub async fn yubikey_keys(&self, user: UserId) -> Result<Option<YubikeyData>, AppError> {
        let Some(row) = self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .find(|t| t.method == TwoFactorMethod::YubiKey)
        else {
            return Ok(None);
        };
        let data =
            open_row::<YubikeyData, _>(&self.seal, PURPOSE_YUBIKEY, user, &row.sealed_secret)
                .ok_or_else(|| AppError::Store("a stored YubiKey setup doesn't open".to_owned()))?;
        Ok(Some(data))
    }

    /// Registers the keys that made these OTPs (an entry of 12 characters is taken as a public id
    /// as it is, without a check). Replaces the keys the account had. The OTPs are checked with
    /// Yubico so a typo can't lock the account out.
    pub async fn yubikey_set(
        &self,
        user: UserId,
        otps: &[String],
        nfc: bool,
    ) -> Result<YubikeyData, AppError> {
        let data = self.yubikey_check(otps, nfc).await?;
        self.yubikey_store(user, data).await
    }

    /// The checks of [`TwoStep::yubikey_set`] alone, with Yubico: the keys to store. A caller
    /// that wants a proof spent between the check and the change calls this, then the proof, then
    /// [`TwoStep::yubikey_store`].
    pub async fn yubikey_check(&self, otps: &[String], nfc: bool) -> Result<YubikeyData, AppError> {
        if !self.settings.yubico_enabled {
            return Err(AppError::Invalid("Yubico support is disabled"));
        }
        let entries: Vec<&str> = otps
            .iter()
            .map(|o| o.trim())
            .filter(|o| !o.is_empty())
            .take(MAX_YUBIKEYS)
            .collect();
        if entries.is_empty() {
            return Err(AppError::Invalid("A key is required."));
        }
        for entry in &entries {
            if entry.len() == ID_LEN {
                continue;
            }
            self.yubico
                .verify(entry)
                .await
                .map_err(|_| AppError::Invalid("Invalid Yubikey OTP provided"))?;
        }
        let keys: Vec<String> = entries
            .iter()
            .filter_map(|e| e.get(..ID_LEN).map(str::to_owned))
            .collect();
        if keys.is_empty() {
            return Err(AppError::Invalid("A key is required."));
        }
        Ok(YubikeyData { keys, nfc })
    }

    /// Stores keys that [`TwoStep::yubikey_check`] accepted, and turns the method on.
    pub async fn yubikey_store(
        &self,
        user: UserId,
        data: YubikeyData,
    ) -> Result<YubikeyData, AppError> {
        self.two_factor
            .put(&TwoFactor {
                user,
                method: TwoFactorMethod::YubiKey,
                sealed_secret: sealed_row(&self.seal, PURPOSE_YUBIKEY, user, &data),
                enabled: true,
                created_at: self.env.now(),
            })
            .await?;
        Ok(data)
    }

    /// Takes the method off, with all its keys.
    pub async fn yubikey_remove(&self, user: UserId) -> Result<(), AppError> {
        self.two_factor
            .remove(user, TwoFactorMethod::YubiKey)
            .await?;
        Ok(())
    }

    /// Checks an OTP at sign-in: 44 characters, from a registered key, accepted by Yubico.
    pub async fn yubikey_verify(&self, user: UserId, otp: &str) -> Result<(), AppError> {
        let otp = otp.trim();
        if otp.len() != OTP_LEN {
            return Err(AppError::Invalid("Invalid Yubikey OTP length"));
        }
        let data = self
            .yubikey_keys(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let id = otp.get(..ID_LEN).ok_or(AppError::Unauthorized)?;
        if !data.keys.iter().any(|k| k == id) {
            return Err(AppError::Unauthorized);
        }
        match self.yubico.verify(otp).await {
            Ok(()) => Ok(()),
            Err(YubicoError::Rejected) => Err(AppError::Unauthorized),
            Err(YubicoError::Unavailable(why)) => {
                tracing::warn!(%why, "Yubico's service couldn't check an OTP");
                Err(AppError::Unauthorized)
            }
        }
    }
}
