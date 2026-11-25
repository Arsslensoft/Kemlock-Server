//! The account's profile (design, "Profile"): its name, its sign-in address and its master
//! password, changed from the web vault's Profile page.
//!
//! - [`Profile`] shows the profile and changes the name.
//! - [`Credentials`] answers the first OPAQUE registration message for a new password or a new
//!   address, with a ticket that binds the registration to its use, and replaces the password's
//!   records. The master password is changed in the browser: the root key does not change, so the
//!   page makes a new master key, a new OPAQUE record and a new wrap of the same root key, and
//!   sends the three here (docs/crypto.md, "Changing the master password and the sign-in
//!   address").
//! - [`OtherDevices`] signs the other devices out after a change that ended their sessions, and
//!   gives the device that asked new tokens.
//! - [`EmailChanges`] and [`ConfirmEmailChange`] hold a new address until the link mailed to it is
//!   opened, then swap it in and end every session.
//!
//! Who is asking has proved the password again before any of these writes: that check is
//! [`crate::privacy::Reauthenticate`], which the API runs first, as it does for erasing the account.

mod credentials;
mod devices;
mod email;
mod error;
pub mod ports;
mod ticket;
mod view;

pub use credentials::{Credentials, NewCredentials, PasswordChanged, RegistrationStarted};
pub use devices::OtherDevices;
pub use email::{ConfirmEmailChange, EmailChangeAsked, EmailChangeDone, EmailChanges};
pub use error::ProfileError;
pub use ports::ProfileRepo;
pub use ticket::PURPOSE_REGISTRATION;
pub use view::{Profile, ProfileView};

use crate::error::AppError;
use crate::ports::UserRepo;
use kemlock_domain::{AccountMode, Email, User, UserId};

/// The account that asks. A token that names no account is an ended session.
async fn account<U: UserRepo>(users: &U, user: UserId) -> Result<User, AppError> {
    users.by_id(user).await?.ok_or(AppError::Unauthorized)
}

/// The account must have a master password this API can change: not one shared with the Bitwarden
/// apps (their password hash lives in the Bitwarden account record), and not one single sign-on
/// made without a password.
fn changeable_password(account: &User) -> Result<(), ProfileError> {
    if account.mode == AccountMode::Compatible {
        return Err(ProfileError::CompatibleAccount);
    }
    if !view::has_password(account) {
        return Err(ProfileError::NoPassword);
    }
    Ok(())
}

/// `raw` as the account's new sign-in address: well formed, and not the one it has. Whether
/// someone else has it is [`is_taken`]'s to say, and is never said to the one who asks.
fn new_address(account: &User, raw: &str) -> Result<Email, ProfileError> {
    let email = Email::parse(raw).map_err(|_| AppError::Invalid("not an email"))?;
    if email == account.email {
        return Err(AppError::Invalid("that is already the address of the account").into());
    }
    Ok(email)
}

/// Whether another account has `email`.
async fn is_taken<U: UserRepo>(
    users: &U,
    account: &User,
    email: &Email,
) -> Result<bool, ProfileError> {
    Ok(users
        .by_email(email)
        .await?
        .is_some_and(|other| other.id != account.id))
}
