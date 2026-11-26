//! The profile as the account sees it, and its name.

use super::{ProfileError, ProfileRepo, account};
use crate::error::AppError;
use crate::ports::{Clock, UserRepo};
use crate::register::MAX_NAME_LEN;
use kemlock_domain::{AccountMode, Email, User, UserId};

/// What the profile page shows and which of its parts may change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileView {
    pub user: UserId,
    pub email: Email,
    pub name: Option<String>,
    /// A single sign-on identity is linked: the name and the address are the identity provider's.
    pub sso: bool,
    /// The account has a master password to change.
    pub has_password: bool,
    /// The account is shared with the Bitwarden apps.
    pub compatible: bool,
    /// The address a link was mailed to, while it can still be opened.
    pub pending_email: Option<Email>,
}

/// Showing the profile and changing the name.
#[derive(Debug)]
pub struct Profile<U, R, C> {
    pub users: U,
    pub repo: R,
    pub clock: C,
}

impl<U: UserRepo, R: ProfileRepo, C: Clock> Profile<U, R, C> {
    pub async fn show(&self, user: UserId) -> Result<ProfileView, ProfileError> {
        let account = account(&self.users, user).await?;
        self.view_of(&account).await
    }

    /// Changes the name. Blank clears it. The name shows to the people the account shares spaces
    /// with. An account whose name comes from the identity provider keeps it.
    pub async fn rename(&self, user: UserId, name: &str) -> Result<ProfileView, ProfileError> {
        let account = account(&self.users, user).await?;
        if self.repo.has_sso_identity(user).await? {
            return Err(ProfileError::SsoManaged);
        }
        let name = name.trim();
        if name.chars().count() > MAX_NAME_LEN {
            return Err(AppError::Invalid("the name is too long").into());
        }
        if name.chars().any(char::is_control) {
            return Err(AppError::Invalid("the name can't hold control characters").into());
        }
        let name = (!name.is_empty()).then(|| name.to_owned());
        // Only the name column is written: a full-row write of the copy read above could put back
        // a password or stamp that another request changed in between.
        if !self.repo.set_name(user, name.as_deref()).await? {
            return Err(AppError::Unauthorized.into());
        }
        self.view_of(&User { name, ..account }).await
    }

    async fn view_of(&self, account: &User) -> Result<ProfileView, ProfileError> {
        let now = self.clock.now();
        let pending_email = self
            .repo
            .email_change_of(account.id)
            .await?
            .filter(|change| !change.is_expired(now))
            .map(|change| change.email);
        Ok(ProfileView {
            user: account.id,
            email: account.email.clone(),
            name: account.name.clone(),
            sso: self.repo.has_sso_identity(account.id).await?,
            has_password: has_password(account),
            compatible: account.mode == AccountMode::Compatible,
            pending_email,
        })
    }
}

/// Whether the account has a master password: an OPAQUE record and a password wrap of the root
/// key. An account single sign-on made has neither.
pub(super) fn has_password(account: &User) -> bool {
    account.opaque_record.is_some() && !account.wrapped_root_key.is_empty()
}
