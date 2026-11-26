//! Confirming the address of a new account (the "verify the email of a new account" setting,
//! `SIGNUPS_VERIFY`).
//!
//! With the setting on, an account made on a sign-up is held back until the link mailed to its
//! address is opened: it can't sign in or be used (`Authenticate` and the password sign-in refuse
//! it with [`AppError::EmailNotConfirmed`]) and single sign-on doesn't link to it by email. The
//! hold is kept with the SHA-256 of the link's token, never the token (`UserRepo::hold_unconfirmed`),
//! so a copy of the database opens no link. An account with no hold is confirmed, which is every
//! account that existed before the setting did and every account made without it.
//!
//! Anyone can register an address they don't own, so the mail says no more than the link: it is
//! sent to the address, and opening it proves the address is read by whoever opened it.

use crate::b64url;
use crate::error::AppError;
use crate::notices::{Notice, Notices, SignupVerifyNotice};
use crate::platform::Platform;
use crate::ports::UserRepo;
use crate::register::EmailHold;
use kemlock_domain::{Email, User, UserId};
use time::Duration;

/// How long a link works.
pub const LIFETIME: Duration = Duration::hours(24);
/// How soon another link may be asked for: a person who registered an address they don't own
/// can't make the server mail it over and over.
pub const RESEND_AFTER: Duration = Duration::minutes(5);

/// A link made but not yet in use: the hold to write with the account, and the token that goes in
/// the mail.
pub struct PreparedLink {
    pub hold: EmailHold,
    /// The secret of the link, base64url. Never logged.
    pub token: String,
}

impl std::fmt::Debug for PreparedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedLink")
            .field("hold", &self.hold)
            .finish_non_exhaustive()
    }
}

/// Holds a new account until its address is confirmed, mails the link, and opens it.
#[derive(Debug)]
pub struct SignupVerify<U, E> {
    pub users: U,
    pub env: E,
    pub notices: Notices,
}

impl<U: UserRepo, E: Platform> SignupVerify<U, E> {
    /// A link and the hold that goes with it, to be written with a new account (see
    /// [`Register::finish_with`](crate::register::Register::finish_with)) and mailed with
    /// [`SignupVerify::mail`] once the account exists.
    pub fn prepare(&self) -> PreparedLink {
        let token = b64url::encode(&self.env.bytes::<32>());
        let hold = EmailHold {
            token_hash: self.env.sha256(token.as_bytes()),
            expires_at: self.env.now() + LIFETIME,
        };
        PreparedLink { hold, token }
    }

    /// Mails the link to `to`. A mail that can't be sent leaves the account held: its owner asks for
    /// a new link from the sign-in screen.
    pub async fn mail(&self, to: &Email, token: String) {
        let notice = Notice::SignupVerify(SignupVerifyNotice {
            to: to.clone(),
            token,
        });
        if let Err(error) = self.notices.send_checked(notice).await {
            tracing::warn!(%error, "the mail that confirms a new account's address was not sent");
        }
    }

    /// A new link for `user`, in place of any before it, mailed to the account's address.
    async fn send_link(&self, user: &User) -> Result<(), AppError> {
        let now = self.env.now();
        let link = self.prepare();
        self.users
            .hold_unconfirmed(user.id, link.hold.token_hash, now, link.hold.expires_at)
            .await?;
        self.mail(&user.email, link.token).await;
        Ok(())
    }

    /// Mails a new link to the address, when an account with that address is held and no link was
    /// made in the last [`RESEND_AFTER`]. Says nothing either way: the answer is the same for an
    /// address with no account, a confirmed account and a held one.
    pub async fn resend(&self, email: &Email) -> Result<(), AppError> {
        let Some(user) = self.users.by_email(email).await? else {
            return Ok(());
        };
        let Some(hold) = self.users.confirmation_of(user.id).await? else {
            return Ok(());
        };
        if self.env.now() < hold.requested_at + RESEND_AFTER {
            return Ok(());
        }
        self.send_link(&user).await
    }

    /// Opens the link with this token: the account is confirmed. A link that is unknown, already
    /// opened or out of time is `Invalid`, whichever it is.
    pub async fn confirm(&self, token: &str) -> Result<UserId, AppError> {
        self.users
            .spend_confirmation(self.env.sha256(token.as_bytes()), self.env.now())
            .await?
            .ok_or(AppError::Invalid("the link isn't valid or has run out"))
    }
}
