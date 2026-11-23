//! Emailed codes (Bitwarden's type 1), as Vaultwarden's `email.rs` has them.

use super::TwoStep;
use super::data::{
    EmailData, PURPOSE_EMAIL, PURPOSE_EMAIL_SETUP, numeric_code, open, same, sealed,
};
use crate::error::AppError;
use crate::notices::{Notice, TwoStepCodeNotice};
use crate::passkeys::{ChallengeKind, ChallengeRepo};
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::{Email, User, UserId};
use time::{Duration, OffsetDateTime};

impl<F, S, E, C> TwoStep<F, S, E, C>
where
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
{
    fn email_allowed(&self) -> Result<(), AppError> {
        if self.settings.email_enabled {
            Ok(())
        } else {
            Err(AppError::Invalid(
                "email codes are not enabled on this server",
            ))
        }
    }

    fn email_lifetime(&self) -> Duration {
        Duration::seconds(i64::from(self.settings.email_expiration_secs))
    }

    /// The account's email setup: its row and what the row holds.
    async fn email_row(&self, user: UserId) -> Result<Option<(TwoFactor, EmailData)>, AppError> {
        let Some(row) = self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .find(|t| t.method == TwoFactorMethod::Email)
        else {
            return Ok(None);
        };
        let data = open::<EmailData, _>(&self.seal, PURPOSE_EMAIL, &row.sealed_secret)
            .ok_or_else(|| AppError::Store("a stored email setup doesn't open".to_owned()))?;
        Ok(Some((row, data)))
    }

    /// The address the account's codes go to, when the method is on.
    pub async fn email_address(&self, user: UserId) -> Result<Option<String>, AppError> {
        Ok(self
            .email_row(user)
            .await?
            .filter(|(row, _)| row.enabled)
            .map(|(_, data)| data.email))
    }

    /// Sends a first code to `address`, to check it is one the person reads. As Vaultwarden does,
    /// an account that already has the method loses it here: it is on again once the code is
    /// entered ([`TwoStep::email_confirm`]).
    pub async fn email_begin(&self, user: UserId, address: &str) -> Result<(), AppError> {
        self.email_allowed()?;
        let address = address.trim();
        let to = Email::parse(address)
            .map_err(|_| AppError::Invalid("the email address isn't valid"))?;
        self.two_factor.remove(user, TwoFactorMethod::Email).await?;
        let now = self.env.now();
        let code = numeric_code(&self.env, self.settings.email_token_size);
        let data = EmailData::new(address.to_owned(), Some(code.clone()), now.unix_timestamp());
        self.challenges
            .put_challenge(
                user,
                ChallengeKind::EmailSetup,
                &sealed(&self.seal, PURPOSE_EMAIL_SETUP, &data),
                now + self.email_lifetime(),
            )
            .await?;
        self.notices
            .send(Notice::TwoStepCode(TwoStepCodeNotice { to, code }))
            .await;
        Ok(())
    }

    /// Turns the method on with the code sent to `address`. A wrong code or address is
    /// `Unauthorized` and counts as an attempt; past the limit the code is gone.
    pub async fn email_confirm(
        &self,
        user: UserId,
        address: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.email_allowed()?;
        let now = self.env.now();
        let state = self
            .challenges
            .take_challenge(user, ChallengeKind::EmailSetup, now)
            .await?
            .ok_or(AppError::Invalid(
                "no email code was asked for, or it expired",
            ))?;
        let mut data = open::<EmailData, _>(&self.seal, PURPOSE_EMAIL_SETUP, &state)
            .ok_or(AppError::Invalid("the email code state isn't valid"))?;
        let right_address = same(&data.email, address.trim());
        let right_code = data
            .last_token
            .as_deref()
            .is_some_and(|issued| same(issued, code.trim()));
        if !(right_address && right_code) {
            data.attempts = data.attempts.saturating_add(1);
            if data.attempts < u64::from(self.settings.email_attempts_limit) {
                let sent = OffsetDateTime::from_unix_timestamp(data.token_sent).unwrap_or(now);
                self.challenges
                    .put_challenge(
                        user,
                        ChallengeKind::EmailSetup,
                        &sealed(&self.seal, PURPOSE_EMAIL_SETUP, &data),
                        sent + self.email_lifetime(),
                    )
                    .await?;
            }
            return Err(AppError::Unauthorized);
        }
        data.reset_token();
        self.two_factor
            .put(&TwoFactor {
                user,
                method: TwoFactorMethod::Email,
                sealed_secret: sealed(&self.seal, PURPOSE_EMAIL, &data),
                enabled: true,
                created_at: now,
            })
            .await?;
        Ok(())
    }

    /// Takes the method off.
    pub async fn email_disable(&self, user: UserId) -> Result<(), AppError> {
        self.two_factor.remove(user, TwoFactorMethod::Email).await?;
        Ok(())
    }

    /// Sends a new code to the address the account set up, for a sign-in that chose the method.
    /// `NotFound` when the account hasn't the method on.
    pub async fn email_send_login_code(&self, user: &User) -> Result<(), AppError> {
        self.email_allowed()?;
        let (row, mut data) = self
            .email_row(user.id)
            .await?
            .filter(|(row, _)| row.enabled)
            .ok_or(AppError::NotFound)?;
        let code = numeric_code(&self.env, self.settings.email_token_size);
        data.set_token(code.clone(), self.env.now().unix_timestamp());
        let to = Email::parse(&data.email)
            .map_err(|_| AppError::Invalid("the address set up for email codes isn't valid"))?;
        self.two_factor
            .put(&TwoFactor {
                sealed_secret: sealed(&self.seal, PURPOSE_EMAIL, &data),
                ..row
            })
            .await?;
        self.notices
            .send(Notice::TwoStepCode(TwoStepCodeNotice { to, code }))
            .await;
        Ok(())
    }

    /// Checks a code at sign-in, as Vaultwarden does. A code is good once: it is gone after it
    /// is entered, right or too late. A wrong entry counts, and the code is gone after
    /// `EMAIL_ATTEMPTS_LIMIT` of them.
    pub async fn email_verify(&self, user: UserId, code: &str) -> Result<(), AppError> {
        let (row, mut data) = self
            .email_row(user)
            .await?
            .filter(|(row, _)| row.enabled)
            .ok_or(AppError::Unauthorized)?;
        let Some(issued) = data.last_token.clone() else {
            return Err(AppError::Unauthorized);
        };
        let right = same(&issued, code.trim());
        if !right {
            data.attempts = data.attempts.saturating_add(1);
            if data.attempts >= u64::from(self.settings.email_attempts_limit) {
                data.reset_token();
            }
        } else {
            data.reset_token();
        }
        let sent = data.token_sent;
        self.two_factor
            .put(&TwoFactor {
                sealed_secret: sealed(&self.seal, PURPOSE_EMAIL, &data),
                ..row
            })
            .await?;
        if !right {
            return Err(AppError::Unauthorized);
        }
        let deadline = sent.saturating_add(i64::from(self.settings.email_expiration_secs));
        if deadline < self.env.now().unix_timestamp() {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }
}
