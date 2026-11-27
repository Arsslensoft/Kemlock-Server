//! Erase account: removes an account and what hangs on it (GDPR Art. 17, CCPA delete). The web
//! vault's "Delete account" calls it after the person proves the password again
//! ([`Reauthenticate`]); the admin console's "Erase user" calls it for a request.
//!
//! `erase_account` removes the items, files, Sends, devices, refresh tokens and sign-in log of the
//! account and strips its name and email from the event log. Backups are not touched: they age out
//! under the backup retention. With a grace period set (up to 30 days) a person's own request only
//! schedules the erasure and ends their sessions; the retention job erases the account when it is
//! due. An admin's erasure is always at once.

use super::Requester;
use super::ports::{
    AccountEraser, ErasedRows, ErasureFiles, PrivacyLog, PrivacySettings, SendEraser,
};
use crate::error::AppError;
use crate::notices::BoxFuture;
use crate::platform::{Platform, random_uuid};
use crate::ports::{Clock, Event, PasswordAuth, SecretSeal, StoreError, UserRepo};
use crate::sealed::{LoginState, PURPOSE_LOGIN};
use crate::sign_in::credential_id;
use crate::spaces::OWNER_REQUIRED;
use kemlock_domain::{User, UserId};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

/// What an erasure that would leave a space with members and no owner is refused with.
const ONLY_OWNER: &str = "the account is the only owner of a space with other members: hand it over or delete the space first";

/// Checks that the person asking still knows the password: the last message of an OPAQUE login
/// whose first message the same device's key started. The session already passed the second step,
/// so the password is all a re-check needs.
#[derive(Debug)]
pub struct Reauthenticate<U, P, S, C> {
    pub users: U,
    pub auth: P,
    pub seal: S,
    pub clock: C,
}

fn same(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl<U: UserRepo, P: PasswordAuth, S: SecretSeal, C: Clock> Reauthenticate<U, P, S, C> {
    /// `login_state` is what `POST /auth/opaque/start` answered, `finalization` the client's last
    /// OPAQUE message, `jkt` the thumbprint of the DPoP key that signed this request. Succeeds
    /// only for the account's own password. The caller makes the login state good once.
    pub async fn execute(
        &self,
        user: UserId,
        login_state: &[u8],
        finalization: &[u8],
        jkt: &str,
    ) -> Result<(), AppError> {
        let plain = self
            .seal
            .open(PURPOSE_LOGIN, login_state)
            .map_err(|_| AppError::Invalid("the login state is invalid"))?;
        let state =
            LoginState::decode(&plain).ok_or(AppError::Invalid("the login state is invalid"))?;
        if self.clock.now().unix_timestamp() >= state.expires_at {
            return Err(AppError::Invalid("the login has expired"));
        }
        let account = self
            .users
            .by_id(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if !same(&state.credential_id, &credential_id(account.email.as_str()))
            || !same(&state.jkt, jkt)
        {
            return Err(AppError::Unauthorized);
        }
        self.auth
            .login_finish(&state.opaque, finalization)
            .map(|_session_key| ())
            .map_err(|_| AppError::Unauthorized)
    }
}

/// What an erasure did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureReport {
    pub rows: ErasedRows,
    /// Sends removed by the Sends store.
    pub sends: u64,
    /// Files deleted.
    pub files_deleted: u64,
    /// Files that couldn't be deleted. Their rows are gone, so the file is left for the
    /// attachment purge or an operator; it is a leak of space, not of the vault.
    pub files_failed: u64,
}

/// The outcome of asking for an erasure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Erasure {
    /// The account is gone.
    Erased(ErasureReport),
    /// The deleted-account grace period is on: sessions ended, erasure due then.
    Scheduled { due: OffsetDateTime },
}

#[derive(Debug)]
pub struct EraseAccount<U, E, S, F, P, L, C> {
    pub users: U,
    pub eraser: E,
    pub sends: S,
    pub files: F,
    pub settings: P,
    pub log: L,
    pub env: C,
}

impl<U, E, S, F, P, L, C> EraseAccount<U, E, S, F, P, L, C>
where
    U: UserRepo,
    E: AccountEraser,
    S: SendEraser,
    F: ErasureFiles,
    P: PrivacySettings,
    L: PrivacyLog,
    C: Platform,
{
    /// Erases `user`, or schedules it when `requested_by` is the account and the settings give
    /// deleted accounts a grace period. Refused while the account is the only owner of a space
    /// that still has other members.
    pub async fn execute(
        &self,
        user: UserId,
        requested_by: Requester,
    ) -> Result<Erasure, AppError> {
        let account = self.users.by_id(user).await?.ok_or(AppError::NotFound)?;
        if !self.eraser.blocking_spaces(user).await?.is_empty() {
            return Err(AppError::Invalid(ONLY_OWNER));
        }
        let grace = match requested_by {
            Requester::Account => self.settings.retention().await?.deleted_account_grace_days,
            Requester::Admin(_) | Requester::Retention => 0,
        };
        if grace == 0 {
            return self.erase_now(account, requested_by).await;
        }
        if let Some(due) = self.eraser.scheduled_erasure(user).await? {
            return Ok(Erasure::Scheduled { due });
        }
        let now = self.env.now();
        let due = now + Duration::days(i64::from(grace));
        self.eraser.schedule_erasure(user, now, due).await?;
        // The sessions end now: a new stamp makes every token of the account stale.
        self.users
            .update(&User {
                security_stamp: random_uuid(&self.env),
                updated_at: now,
                ..account
            })
            .await?;
        self.record("account.erase_scheduled", Some(user), None)
            .await;
        Ok(Erasure::Scheduled { due })
    }

    /// Erases `user` at once, whatever grace period the settings give: for a caller whose own
    /// protocol has none (the Bitwarden API, as Vaultwarden erases at once). The same refusal for
    /// a space the account owns alone applies.
    pub async fn execute_now(
        &self,
        user: UserId,
        requested_by: Requester,
    ) -> Result<Erasure, AppError> {
        let account = self.users.by_id(user).await?.ok_or(AppError::NotFound)?;
        if !self.eraser.blocking_spaces(user).await?.is_empty() {
            return Err(AppError::Invalid(ONLY_OWNER));
        }
        self.erase_now(account, requested_by).await
    }

    /// Erases an account that is due, or that an admin asked to erase. The retention job calls
    /// this for each account `due_erasures` names. The grace period can end after another owner
    /// stepped down, so the check of `execute` runs again: an erasure that would leave a space with
    /// members and no owner is held (refused now, tried again at the next run).
    pub async fn erase_due(&self, user: UserId) -> Result<Erasure, AppError> {
        let account = self.users.by_id(user).await?.ok_or(AppError::NotFound)?;
        if !self.eraser.blocking_spaces(user).await?.is_empty() {
            return Err(AppError::Invalid(ONLY_OWNER));
        }
        self.erase_now(account, Requester::Retention).await
    }

    async fn erase_now(&self, account: User, requested_by: Requester) -> Result<Erasure, AppError> {
        let sends = self.sends.erase_sends(account.id).await?;
        // The store checks the owners again in the erasure's own transaction: an owner may have
        // stepped down since `blocking_spaces` was read. It also refuses the last admin.
        let rows = match self.eraser.erase_user(&account).await {
            Err(StoreError::Backend(why)) if why == OWNER_REQUIRED => {
                return Err(AppError::Invalid(ONLY_OWNER));
            }
            Err(StoreError::Backend(why)) if why == super::LAST_ADMIN => {
                return Err(AppError::Invalid("the last admin can't be deleted"));
            }
            other => other?,
        };

        let mut files_deleted = 0u64;
        let mut files_failed = 0u64;
        for blob in &rows.blobs {
            match self.files.delete_blob(*blob).await {
                Ok(()) => files_deleted += 1,
                Err(e) => {
                    files_failed += 1;
                    tracing::warn!(error = %e, "couldn't delete a file of an erased account");
                }
            }
        }
        for key in &rows.cipher_files {
            match self.files.delete_cipher_file(key).await {
                Ok(()) => files_deleted += 1,
                Err(e) => {
                    files_failed += 1;
                    tracing::warn!(error = %e, "couldn't delete a file of an erased account");
                }
            }
        }

        // The event holds no name or email, and names the admin who acted, never the erased
        // account.
        let actor = match requested_by {
            Requester::Admin(admin) => Some(admin),
            Requester::Account | Requester::Retention => None,
        };
        self.record("account.erased", actor, None).await;
        Ok(Erasure::Erased(ErasureReport {
            rows,
            sends,
            files_deleted,
            files_failed,
        }))
    }

    /// Writes an event; the erasure has happened, so a log failure is only logged.
    async fn record(&self, action: &'static str, actor: Option<UserId>, target: Option<String>) {
        let event = Event {
            actor,
            device: None,
            action,
            target,
            at: self.env.now(),
        };
        if let Err(e) = self.log.record_event(event, None).await {
            tracing::warn!(action, error = %e, "couldn't record an event");
        }
    }
}

/// Erases the account that asks, for a caller that doesn't know the store (the Bitwarden API's
/// `DELETE /api/accounts`). Object safe; [`EraseAccount`] implements it, acting as
/// [`Requester::Account`], so the grace period and the refusal for a space the account owns alone
/// are the ones the web vault's deletion has.
pub trait OwnErasure: Send + Sync {
    /// Erases `user`, or schedules it. The caller has checked who is asking.
    fn erase_own(&self, user: UserId) -> BoxFuture<'_, Result<Erasure, AppError>>;

    /// Erases `user` at once, with no grace period, for a protocol that has none.
    fn erase_own_now(&self, user: UserId) -> BoxFuture<'_, Result<Erasure, AppError>>;
}

impl<U, E, S, F, P, L, C> OwnErasure for EraseAccount<U, E, S, F, P, L, C>
where
    U: UserRepo,
    E: AccountEraser,
    S: SendEraser,
    F: ErasureFiles,
    P: PrivacySettings,
    L: PrivacyLog,
    C: Platform,
{
    fn erase_own(&self, user: UserId) -> BoxFuture<'_, Result<Erasure, AppError>> {
        Box::pin(self.execute(user, Requester::Account))
    }

    fn erase_own_now(&self, user: UserId) -> BoxFuture<'_, Result<Erasure, AppError>> {
        Box::pin(self.execute_now(user, Requester::Account))
    }
}
