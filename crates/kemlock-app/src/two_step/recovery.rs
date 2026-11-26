//! The recovery code, as Vaultwarden has it (`users.totp_recover`): a code made when an account
//! first turns a two-step method on, which the account can show (with its master password or a
//! mailed code) and which, entered as the second step, switches every method off and is spent.
//!
//! The code is 20 random bytes in upper-case base32 (32 characters), kept sealed under
//! `server.key`. An account moved from Vaultwarden keeps the code it had in the legacy column of
//! its imported row ([`RecoveryCodeRepo::legacy_recovery_code`]); it is read from there until it is used, and a
//! code is never made for an account that has one. Entering a code ignores spaces and case, as
//! Vaultwarden does.

use super::data::same;
use crate::enrol_totp::base32;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, StoreError, TwoFactorRepo};
use crate::sealed::{open_bound, seal_bound};
use kemlock_domain::UserId;
use std::future::Future;
use time::OffsetDateTime;

/// `SecretSeal` purpose of a recovery code.
pub const PURPOSE_RECOVERY: &str = "two-step-recovery";
/// `SecretSeal` purpose of the legacy column of an account moved from Vaultwarden.
pub const PURPOSE_LEGACY_RECOVERY: &str = "vw-account";
/// Random bytes in a code, which Vaultwarden makes 20.
const CODE_BYTES: usize = 20;

/// Where recovery codes are kept: one per account.
pub trait RecoveryCodeRepo: Send + Sync {
    /// The account's sealed code ([`PURPOSE_RECOVERY`]).
    fn recovery_code(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>> + Send;

    /// The sealed code an account moved from Vaultwarden still has in its imported row
    /// ([`PURPOSE_LEGACY_RECOVERY`]).
    fn legacy_recovery_code(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>> + Send;

    /// Stores `sealed` unless the account has a code already, in either place. `false` means it
    /// has one and nothing was written.
    fn put_recovery_code_if_absent(
        &self,
        user: UserId,
        sealed: &[u8],
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Removes the account's code, in both places. `true` when there was one: of two calls racing
    /// for it, one gets `true`.
    fn remove_recovery_code(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// Making, showing and spending the recovery code.
#[derive(Debug)]
pub struct RecoveryCodes<R, F, S, E> {
    pub recovery: R,
    pub two_factor: F,
    pub seal: S,
    pub env: E,
}

impl<R, F, S, E> RecoveryCodes<R, F, S, E>
where
    R: RecoveryCodeRepo,
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
{
    /// Makes the account's code unless it has one. Call it when a two-step method is turned on,
    /// as Vaultwarden's `generate_recover_code` is.
    pub async fn ensure(&self, user: UserId) -> Result<(), AppError> {
        let code = base32(&self.env.bytes::<CODE_BYTES>());
        let sealed = seal_bound(&self.seal, PURPOSE_RECOVERY, user, code.as_bytes());
        self.recovery
            .put_recovery_code_if_absent(user, &sealed, self.env.now())
            .await?;
        Ok(())
    }

    /// The account's code, or `None` when it has none (no method was ever turned on, or the code
    /// was spent).
    pub async fn show(&self, user: UserId) -> Result<Option<String>, AppError> {
        let (sealed, purpose) = match self.recovery.recovery_code(user).await? {
            Some(sealed) => (sealed, PURPOSE_RECOVERY),
            None => match self.recovery.legacy_recovery_code(user).await? {
                Some(sealed) => (sealed, PURPOSE_LEGACY_RECOVERY),
                None => return Ok(None),
            },
        };
        let plain = open_bound(&self.seal, purpose, user, &sealed)
            .map_err(|_| AppError::Store("a stored recovery code doesn't open".to_owned()))?
            .value;
        String::from_utf8(plain.as_slice().to_vec())
            .map(Some)
            .map_err(|_| AppError::Store("a stored recovery code isn't text".to_owned()))
    }

    /// Spends the code: when `code` is the account's, every two-step method is removed and the
    /// code with them (the next method turned on makes a new one). Wrong, or already spent, is
    /// `Unauthorized`.
    pub async fn recover(&self, user: UserId, code: &str) -> Result<(), AppError> {
        // Like Vaultwarden: spaces and case don't matter.
        let entered = code.replace(' ', "").trim().to_lowercase();
        let Some(held) = self.show(user).await? else {
            return Err(AppError::Unauthorized);
        };
        if !same(&entered, &held.to_lowercase()) {
            return Err(AppError::Unauthorized);
        }
        // The removal is the claim: of two entries of the same code, one gets it.
        if !self.recovery.remove_recovery_code(user).await? {
            return Err(AppError::Unauthorized);
        }
        for factor in self.two_factor.list(user).await? {
            self.two_factor.remove(user, factor.method).await?;
        }
        Ok(())
    }
}
