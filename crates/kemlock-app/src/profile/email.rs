//! Changing the sign-in address: the request holds the new address and the credentials made for it
//! until the link mailed to it is opened, and opening the link swaps it in.
//!
//! The link's token is 32 random bytes; the server keeps only its SHA-256, so a copy of the
//! database opens no link. Opening it is the proof of owning the address, so no session is needed:
//! it is opened from the mail client, often in another browser.

use super::credentials::{NewCredentials, check};
use super::{ProfileError, ProfileRepo, account, changeable_password, free_address};
use crate::b64url;
use crate::notices::{EmailChangeNotice, EmailChangeRequestedNotice, Notice, Notices};
use crate::platform::{Platform, random_uuid};
use crate::ports::{DeviceRepo, StoreError, TokenRepo, UserRepo};
use kemlock_domain::{Email, EmailChange, User, UserId};
use time::OffsetDateTime;

/// What asking for a change of address did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailChangeAsked {
    /// The address the link was mailed to.
    pub email: Email,
    /// When the link runs out.
    pub expires_at: OffsetDateTime,
}

/// Asking for a change of address, and taking the ask back.
#[derive(Debug)]
pub struct EmailChanges<U, R, P, E> {
    pub users: U,
    pub repo: R,
    pub auth: P,
    pub env: E,
    pub notices: Notices,
}

impl<U: UserRepo, R: ProfileRepo, P: crate::ports::PasswordAuth, E: Platform>
    EmailChanges<U, R, P, E>
{
    /// Keeps `email` and the credentials made under it, and mails the link to it. A new ask
    /// replaces the one before: its link stops working. The old address is told, best effort.
    ///
    /// The server must be able to mail, or no one could open the link.
    pub async fn request(
        &self,
        user: UserId,
        email: &str,
        new: NewCredentials,
    ) -> Result<EmailChangeAsked, ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        if self.repo.has_sso_identity(user).await? {
            return Err(ProfileError::SsoManaged);
        }
        let email = free_address(&self.users, &account, email).await?;
        let checked = check(&self.auth, new)?;
        if !self.notices.mails() {
            return Err(ProfileError::MailOff);
        }

        let now = self.env.now();
        let token = b64url::encode(&self.env.bytes::<32>());
        let change = EmailChange {
            user,
            email: email.clone(),
            token_hash: self.env.sha256(token.as_bytes()),
            opaque_record: checked.opaque_record,
            kdf: checked.kdf,
            wrapped_root_key: checked.wrapped_root_key,
            requested_at: now,
            expires_at: now + EmailChange::LIFETIME,
        };
        self.repo.put_email_change(&change).await?;

        let sent = self
            .notices
            .send_checked(Notice::EmailChange(EmailChangeNotice {
                to: email.clone(),
                token,
            }))
            .await;
        if let Err(error) = sent {
            // A link that was never sent can't be opened: don't leave it pending.
            tracing::warn!(%error, "the mail with the link of a change of address was not sent");
            self.repo.remove_email_change(user).await?;
            return Err(ProfileError::MailFailed);
        }
        self.notices
            .send(Notice::EmailChangeRequested(EmailChangeRequestedNotice {
                to: account.email,
                new_address: email.clone(),
                at: now,
            }))
            .await;
        Ok(EmailChangeAsked {
            email,
            expires_at: change.expires_at,
        })
    }

    /// Takes the ask back: its link stops working. Nothing to take back is not an error.
    pub async fn cancel(&self, user: UserId) -> Result<(), ProfileError> {
        Ok(self.repo.remove_email_change(user).await?)
    }
}

/// Who changed address, for the event that says so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailChangeDone {
    pub user: UserId,
    /// The address the account has now.
    pub email: Email,
}

/// Opening the link: the pending address, record, settings and wrap replace the account's, and
/// every session ends, so each device signs in again with the new address.
#[derive(Debug)]
pub struct ConfirmEmailChange<U, R, D, T, E> {
    pub users: U,
    pub repo: R,
    pub devices: D,
    pub tokens: T,
    pub env: E,
}

impl<U: UserRepo, R: ProfileRepo, D: DeviceRepo, T: TokenRepo, E: Platform>
    ConfirmEmailChange<U, R, D, T, E>
{
    /// `token` is the one in the link. It is good once: the change is taken out of the store before
    /// anything is written, so a failure after that means asking again. A token that is unknown,
    /// spent or out of time is [`ProfileError::EmailChangeInvalid`], whichever it is.
    pub async fn confirm(&self, token: &str) -> Result<EmailChangeDone, ProfileError> {
        let now = self.env.now();
        let change = self
            .repo
            .take_email_change(self.env.sha256(token.as_bytes()))
            .await?
            .filter(|change| !change.is_expired(now))
            .ok_or(ProfileError::EmailChangeInvalid)?;
        let account = self
            .users
            .by_id(change.user)
            .await?
            .ok_or(ProfileError::EmailChangeInvalid)?;
        // Someone may have taken the address since: the pending change is gone, and so is the ask.
        if let Some(other) = self.users.by_email(&change.email).await?
            && other.id != account.id
        {
            return Err(ProfileError::EmailTaken);
        }

        let done = EmailChangeDone {
            user: account.id,
            email: change.email.clone(),
        };
        let updated = User {
            email: change.email,
            opaque_record: Some(change.opaque_record),
            kdf: change.kdf,
            wrapped_root_key: change.wrapped_root_key,
            // A new stamp makes every access and refresh token of the account stale.
            security_stamp: random_uuid(&self.env),
            updated_at: now,
            ..account
        };
        match self.users.update(&updated).await {
            Err(StoreError::Duplicate) => return Err(ProfileError::EmailTaken),
            other => other?,
        }
        for device in self.devices.list(done.user).await? {
            self.tokens.revoke_device(device.id).await?;
        }
        Ok(done)
    }
}
