//! Changing the sign-in address: the request holds the new address and the credentials made for it
//! until the link mailed to it is opened, and opening the link swaps it in.
//!
//! The link's token is 32 random bytes; the server keeps only its SHA-256, so a copy of the
//! database opens no link. Opening it is the proof of owning the address, so no session is needed:
//! it is opened from the mail client, often in another browser.
//!
//! Asking for an address another account has looks, to whoever asks, like asking for a free one:
//! the same answer, the same pending change on the profile, the same mail to the old address. The
//! mail to the address itself says it already has an account and carries no link, and the pending
//! change that stands in for the real one has a token no one was given.

use super::credentials::{NewCredentials, check};
use super::ticket::Ticket;
use super::{ProfileError, ProfileRepo, account, changeable_password, is_taken, new_address};
use crate::b64url;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::notices::{
    EmailChangeNotice, EmailChangeRequestedNotice, EmailChangedNotice, EmailTakenNotice, Notice,
    Notices,
};
use crate::platform::{Platform, random_uuid};
use crate::ports::{DeviceRepo, PasswordAuth, SecretSeal, StoreError, TokenRepo, UserRepo};
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
pub struct EmailChanges<U, R, P, S, E> {
    pub users: U,
    pub repo: R,
    pub auth: P,
    pub seal: S,
    pub env: E,
    pub notices: Notices,
    /// Read only for the lifetime tickets have; the change's own is [`EmailChange::LIFETIME`].
    pub config: AuthConfig,
}

impl<U: UserRepo, R: ProfileRepo, P: PasswordAuth, S: SecretSeal, E: Platform>
    EmailChanges<U, R, P, S, E>
{
    /// The account, if its address may be changed here and a link can be mailed: it has a master
    /// password this API can change, no identity provider owns its address, and the server sends
    /// mail, or no one could open the link.
    async fn allowed(&self, user: UserId) -> Result<User, ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        if self.repo.has_sso_identity(user).await? {
            return Err(ProfileError::SsoManaged);
        }
        if !self.notices.mails() {
            return Err(ProfileError::MailOff);
        }
        Ok(account)
    }

    /// The ticket, if it is a good one for asking for `email`: handed to this account and this
    /// DPoP key, not run out, and asked for this very address. The comparison is the same whether
    /// the address is free or not, so it says nothing about who has an account.
    fn open_ticket(
        &self,
        account: &User,
        email: &Email,
        sealed: &[u8],
        jkt: &str,
    ) -> Result<Ticket, ProfileError> {
        let ticket = Ticket::open(&self.seal, sealed, self.env.now(), account.id, jkt)?;
        if ticket.address.as_deref() != Some(email.as_str()) {
            return Err(AppError::Invalid("the registration ticket is not valid").into());
        }
        Ok(ticket)
    }

    /// Whether the account's address may be changed at all, to `email`, with this ticket. Asked
    /// before the password is spent, so a refusal that can be known costs the person nothing.
    pub async fn check(
        &self,
        user: UserId,
        email: &str,
        ticket: &[u8],
        jkt: &str,
    ) -> Result<(), ProfileError> {
        let account = self.allowed(user).await?;
        let email = new_address(&account, email)?;
        self.open_ticket(&account, &email, ticket, jkt)?;
        Ok(())
    }

    /// Keeps `email` and the credentials made under it, and mails the link to it. A new ask
    /// replaces the one before: its link stops working. The old address is told, best effort.
    ///
    /// An address another account has is kept all the same, under a token nobody has, and mailed
    /// the notice that it has an account instead of the link: the ask can't tell the person who
    /// has an account.
    pub async fn request(
        &self,
        user: UserId,
        email: &str,
        new: NewCredentials,
        ticket: &[u8],
        jkt: &str,
    ) -> Result<EmailChangeAsked, ProfileError> {
        let account = self.allowed(user).await?;
        let email = new_address(&account, email)?;
        let ticket = self.open_ticket(&account, &email, ticket, jkt)?;
        let taken = is_taken(&self.users, &account, &email).await?;
        // A registration for a free address was made for that address. (For a taken one it was made
        // for random bytes, and nothing was going to be stored from it anyway.)
        if !taken && ticket.credential != self.env.sha256(email.as_str().as_bytes()) {
            return Err(AppError::Invalid("the registration ticket is not valid").into());
        }
        let checked = check(&self.auth, new)?;

        let now = self.env.now();
        let token = b64url::encode(&self.env.bytes::<32>());
        let change = EmailChange {
            user,
            email: email.clone(),
            token_hash: self.env.sha256(token.as_bytes()),
            opaque_record: checked.opaque_record,
            kdf: checked.kdf,
            wrapped_root_key: checked.wrapped_root_key,
            // The wrap is of the root key as it is now; a rotation before the link is opened
            // replaces that key, and the change is then refused.
            key_version: account.key_version,
            requested_at: now,
            expires_at: now + EmailChange::LIFETIME,
        };
        self.repo.put_email_change(&change).await?;

        let notice = if taken {
            Notice::EmailTaken(EmailTakenNotice {
                to: email.clone(),
                at: now,
            })
        } else {
            Notice::EmailChange(EmailChangeNotice {
                to: email.clone(),
                token,
            })
        };
        if let Err(error) = self.notices.send_checked(notice).await {
            // A link that was never sent can't be opened: don't leave it pending.
            tracing::warn!(%error, "the mail of a change of address was not sent");
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
    /// Tells the old address that the change was made.
    pub notices: Notices,
}

impl<U: UserRepo, R: ProfileRepo, D: DeviceRepo, T: TokenRepo, E: Platform>
    ConfirmEmailChange<U, R, D, T, E>
{
    /// `token` is the one in the link. It is good once, and it is spent by the write that makes
    /// the change, not before: a write that does not happen
    /// ([`ProfileError::AccountChanged`]) leaves the link good. A token that is unknown, spent or
    /// out of time is [`ProfileError::EmailChangeInvalid`], whichever it is.
    ///
    /// The account is looked at again before anything is written, as it is now and not as it was
    /// when the link was asked for: an account that was disabled or is being deleted gets
    /// [`ProfileError::EmailChangeInvalid`] too, and one that has since been linked to an identity
    /// provider, shared with the Bitwarden apps or left with no password gets the refusal the
    /// request would have had, and its pending change is dropped, since it can never be applied.
    pub async fn confirm(&self, token: &str) -> Result<EmailChangeDone, ProfileError> {
        let now = self.env.now();
        let change = self
            .repo
            .email_change_by_token(self.env.sha256(token.as_bytes()))
            .await?
            .filter(|change| !change.is_expired(now))
            .ok_or(ProfileError::EmailChangeInvalid)?;
        let account = self
            .users
            .by_id(change.user)
            .await?
            .ok_or(ProfileError::EmailChangeInvalid)?;
        if self.users.account_disabled(account.id).await?
            || self.users.erasure_pending(account.id).await?.is_some()
        {
            return Err(ProfileError::EmailChangeInvalid);
        }
        if let Err(refused) = self.changeable(&account).await {
            self.repo.remove_email_change(account.id).await?;
            return Err(refused);
        }
        // The wrap was made for the root key of one key version. A rotation since replaced that
        // key, and putting the wrap back would bring back a wrap of the retired root and leave the
        // new one unopenable by the password: the ask is dropped, as it can't be applied.
        if change.key_version != account.key_version {
            self.repo.remove_email_change(account.id).await?;
            return Err(ProfileError::EmailChangeInvalid);
        }
        // Someone may have taken the address since: the ask is dropped, as it can't be applied.
        if is_taken(&self.users, &account, &change.email).await? {
            self.repo.remove_email_change(account.id).await?;
            return Err(ProfileError::EmailTaken);
        }

        let updated = User {
            email: change.email.clone(),
            opaque_record: Some(change.opaque_record.clone()),
            kdf: change.kdf.clone(),
            wrapped_root_key: change.wrapped_root_key.clone(),
            // A new stamp makes every access and refresh token of the account stale.
            security_stamp: random_uuid(&self.env),
            updated_at: now,
            ..account.clone()
        };
        match self
            .repo
            .apply_email_change(&change, &account, &updated)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(ProfileError::AccountChanged),
            // The database refused the address: another account has it, as the check above could
            // not know a moment ago.
            Err(StoreError::Duplicate) => {
                self.repo.remove_email_change(account.id).await?;
                return Err(ProfileError::EmailTaken);
            }
            Err(other) => return Err(other.into()),
        }

        // The change is made. What follows can't fail it: the new stamp already ended every
        // session, and what is left is cleaning up and telling the old address.
        match self.devices.list(account.id).await {
            Ok(devices) => {
                for device in devices {
                    if let Err(error) = self.tokens.revoke_device(device.id).await {
                        tracing::warn!(%error, "couldn't delete a device's tokens after a change of address");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "couldn't list the devices after a change of address");
            }
        }
        self.notices
            .send(Notice::EmailChanged(EmailChangedNotice {
                to: account.email,
                new_address: change.email.clone(),
                at: now,
            }))
            .await;
        Ok(EmailChangeDone {
            user: account.id,
            email: change.email,
        })
    }

    /// Whether the account is one whose address this API changes.
    async fn changeable(&self, account: &User) -> Result<(), ProfileError> {
        changeable_password(account)?;
        if self.repo.has_sso_identity(account.id).await? {
            return Err(ProfileError::SsoManaged);
        }
        Ok(())
    }
}
