//! Protected actions, as Vaultwarden's `protected_actions.rs` has them: a one-time code mailed to
//! the account stands in for the master password on the calls that take either (`otp` beside
//! `masterPasswordHash`), for a person who has no password to type, such as one who signed in with
//! a device or a single sign-on.
//!
//! One code at a time per account. Asking again within 30 seconds is refused, and a code asked for
//! after that replaces the one before. A code works for `EMAIL_EXPIRATION_TIME` seconds (the same
//! setting as an emailed second-step code) and survives `EMAIL_ATTEMPTS_LIMIT` wrong entries; the
//! state is [`ProtectedData`], sealed, in the stored challenges (`ChallengeKind::ProtectedAction`).

use super::TwoStep;
use super::data::{open, same, sealed};
use crate::error::AppError;
use crate::notices::{Notice, ProtectedActionNotice};
use crate::passkeys::{ChallengeKind, ChallengeRepo};
use crate::platform::Platform;
use crate::ports::{SecretSeal, StoreError, TwoFactorRepo};
use kemlock_domain::{User, UserId};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// `SecretSeal` purpose of a protected action's state.
pub(crate) const PURPOSE_PROTECTED: &str = "protected-action";

/// How long a person must wait before another code is sent.
pub const PROTECTED_REQUEST_DELAY_SECS: i64 = 30;

/// How long a spent or expired state is kept, so a late entry is told the code ran out and is not
/// mistaken for never having asked.
const KEEP_AFTER_EXPIRY: Duration = Duration::hours(1);

/// What is kept of a code: Vaultwarden's `ProtectedActionData`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProtectedData {
    token: String,
    /// When the code was sent, in Unix seconds.
    token_sent: i64,
    /// The wrong entries so far.
    attempts: u64,
}

/// Why a protected action's code wasn't sent or accepted. Each is a message Vaultwarden says.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtectedError {
    /// The server can't mail.
    #[error("email is disabled for this server")]
    Disabled,
    /// A code was sent less than 30 seconds ago; this many seconds to wait.
    #[error("wait {0} seconds before asking for another code")]
    Wait(i64),
    /// No code was asked for (or it was used up).
    #[error("no code was asked for")]
    NotFound,
    /// The code ran out of time or of attempts.
    #[error("the code has expired")]
    Expired,
    /// The code is wrong.
    #[error("the code is invalid")]
    Invalid,
    #[error(transparent)]
    App(#[from] AppError),
}

impl From<StoreError> for ProtectedError {
    fn from(e: StoreError) -> Self {
        ProtectedError::App(e.into())
    }
}

impl<F, S, E, C> TwoStep<F, S, E, C>
where
    F: TwoFactorRepo,
    S: SecretSeal,
    E: Platform,
    C: ChallengeRepo,
{
    fn protected_lifetime(&self) -> Duration {
        Duration::seconds(i64::from(self.settings.email_expiration_secs))
    }

    /// When the stored state of a code sent at `sent` goes: later than the code does.
    fn protected_keep_until(&self, sent: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(sent).unwrap_or(OffsetDateTime::UNIX_EPOCH)
            + self.protected_lifetime()
            + KEEP_AFTER_EXPIRY
    }

    async fn protected_store(&self, user: UserId, data: &ProtectedData) -> Result<(), StoreError> {
        self.challenges
            .put_challenge(
                user,
                ChallengeKind::ProtectedAction,
                &sealed(&self.seal, PURPOSE_PROTECTED, data),
                self.protected_keep_until(data.token_sent),
            )
            .await
    }

    /// Mails a one-time code to the account's address, replacing any earlier code once 30 seconds
    /// have passed since it was sent.
    pub async fn protected_request(&self, user: &User) -> Result<(), ProtectedError> {
        if !self.settings.email_enabled {
            return Err(ProtectedError::Disabled);
        }
        let now = self.env.now();
        let earlier = self
            .challenges
            .take_challenge(user.id, ChallengeKind::ProtectedAction, now)
            .await?;
        if let Some(earlier) =
            earlier.and_then(|s| open::<ProtectedData, _>(&self.seal, PURPOSE_PROTECTED, &s))
        {
            let elapsed = now.unix_timestamp() - earlier.token_sent;
            if elapsed < PROTECTED_REQUEST_DELAY_SECS {
                // Put back what was taken: the code before is still the one that works.
                self.protected_store(user.id, &earlier).await?;
                return Err(ProtectedError::Wait(PROTECTED_REQUEST_DELAY_SECS - elapsed));
            }
        }
        let code = super::data::numeric_code(&self.env, self.settings.email_token_size);
        let data = ProtectedData {
            token: code.clone(),
            token_sent: now.unix_timestamp(),
            attempts: 0,
        };
        self.protected_store(user.id, &data).await?;
        self.notices
            .send(Notice::ProtectedAction(ProtectedActionNotice {
                to: user.email.clone(),
                code,
            }))
            .await;
        Ok(())
    }

    /// Checks a code the account was mailed. With `delete_if_valid` it is used up by a right
    /// entry; without, it can answer the next call of the same process too (a screen that asks for
    /// the proof, then acts on it). A wrong entry counts; a code that took `EMAIL_ATTEMPTS_LIMIT`
    /// of them is refused, and kept so the count stays.
    pub async fn protected_validate(
        &self,
        user: UserId,
        otp: &str,
        delete_if_valid: bool,
    ) -> Result<(), ProtectedError> {
        let now = self.env.now();
        let mut data = self
            .challenges
            .take_challenge(user, ChallengeKind::ProtectedAction, now)
            .await?
            .and_then(|s| open::<ProtectedData, _>(&self.seal, PURPOSE_PROTECTED, &s))
            .ok_or(ProtectedError::NotFound)?;
        if data.attempts >= u64::from(self.settings.email_attempts_limit) {
            self.protected_store(user, &data).await?;
            return Err(ProtectedError::Expired);
        }
        // Past its time the code is gone (it was taken above), as Vaultwarden deletes it.
        if now.unix_timestamp() - data.token_sent > self.protected_lifetime().whole_seconds() {
            return Err(ProtectedError::Expired);
        }
        if !same(&data.token, otp) {
            data.attempts = data.attempts.saturating_add(1);
            self.protected_store(user, &data).await?;
            return Err(ProtectedError::Invalid);
        }
        if !delete_if_valid {
            self.protected_store(user, &data).await?;
        }
        Ok(())
    }
}
