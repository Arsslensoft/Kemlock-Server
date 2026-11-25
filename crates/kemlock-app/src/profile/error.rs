//! What changing the profile can fail with, beside the failures every use case has.

use crate::error::AppError;
use crate::ports::{CryptoError, StoreError};

/// The API maps each variant to a status and a problem type of its own, so a client can say what
/// is wrong in words instead of a bare "forbidden".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The name and the address come from the identity provider, which changes them.
    #[error("the name and the address come from the identity provider")]
    SsoManaged,
    /// The account is shared with the Bitwarden apps, whose password hash and key live in the
    /// Bitwarden account record: its password and address are changed there.
    #[error("the account is shared with Bitwarden apps: change it there")]
    CompatibleAccount,
    /// The account signs in without a master password (single sign-on made it), so there is none
    /// to change.
    #[error("the account has no master password")]
    NoPassword,
    /// Another account has that address.
    #[error("that address belongs to another account")]
    EmailTaken,
    /// The link's token is unknown, spent or out of time. Never says which.
    #[error("the link is not valid or has run out")]
    EmailChangeInvalid,
    /// The server sends no mail, so a new address can't be checked.
    #[error("the server sends no mail, so a new address can't be checked")]
    MailOff,
    /// The mail with the link could not be sent.
    #[error("the mail with the link could not be sent")]
    MailFailed,
    #[error(transparent)]
    App(#[from] AppError),
}

impl From<StoreError> for ProfileError {
    fn from(e: StoreError) -> Self {
        ProfileError::App(AppError::from(e))
    }
}

impl From<CryptoError> for ProfileError {
    fn from(e: CryptoError) -> Self {
        ProfileError::App(AppError::from(e))
    }
}
