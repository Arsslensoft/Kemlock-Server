//! The password's records: the OPAQUE registration that makes a new record, and the replacement of
//! the record, the KDF settings and the root-key wrap in one write.

use super::{ProfileError, ProfileRepo, account, changeable_password, free_address};
use crate::error::AppError;
use crate::ports::{Clock, PasswordAuth, UserRepo};
use crate::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_domain::{KdfParams, User, UserId};

/// What the browser makes with the new master key: the last OPAQUE registration message, the
/// settings and salt of the master key, and the root key wrapped under it and the record's export
/// key (docs/crypto.md, "The password wrap of the root key"). The root key itself does not change.
#[derive(Clone, Debug)]
pub struct NewCredentials {
    /// OPAQUE's `RegistrationUpload`.
    pub upload: Vec<u8>,
    pub kdf: KdfParams,
    pub wrapped_root_key: Vec<u8>,
}

/// New credentials that passed the checks the server can make: the record, ready to store.
#[derive(Debug)]
pub(super) struct Checked {
    pub(super) opaque_record: Vec<u8>,
    pub(super) kdf: KdfParams,
    pub(super) wrapped_root_key: Vec<u8>,
}

/// Checks what a client sent, without opening any of it. The settings must be exactly the
/// defaults with a 16-byte salt, as at registration: prelogin answers an unknown email with those,
/// so an account that differed would be told apart from an unknown one by its answer.
pub(super) fn check<P: PasswordAuth>(
    auth: &P,
    new: NewCredentials,
) -> Result<Checked, ProfileError> {
    if !new.kdf.is_account_default() {
        return Err(AppError::Invalid(
            "the KDF settings must be the defaults with a 16-byte salt",
        )
        .into());
    }
    if new.wrapped_root_key.len() != WRAPPED_ROOT_KEY_LEN {
        return Err(AppError::Invalid("the wrapped root key is malformed").into());
    }
    Ok(Checked {
        opaque_record: auth.registration_record(&new.upload)?,
        kdf: new.kdf,
        wrapped_root_key: new.wrapped_root_key,
    })
}

/// Changing the master password, and the first message of the registration that makes the new
/// record for it or for a new address.
#[derive(Debug)]
pub struct Credentials<U, R, P, C> {
    pub users: U,
    pub repo: R,
    pub auth: P,
    pub clock: C,
}

impl<U: UserRepo, R: ProfileRepo, P: PasswordAuth, C: Clock> Credentials<U, R, P, C> {
    /// Whether the account has a master password this API can change. Asked before the password
    /// is spent, so a refusal that can be known costs the person nothing.
    pub async fn check(&self, user: UserId) -> Result<(), ProfileError> {
        changeable_password(&account(&self.users, user).await?)
    }

    /// OPAQUE registration, first message: the server's `RegistrationResponse`. It is bound to the
    /// account's own address, or to `email` when the registration is for a new address, which must
    /// be free and may not be an identity provider's account's.
    pub async fn start(
        &self,
        user: UserId,
        email: Option<&str>,
        request: &[u8],
    ) -> Result<Vec<u8>, ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        let credential = match email {
            None => account.email.clone(),
            Some(raw) => {
                if self.repo.has_sso_identity(user).await? {
                    return Err(ProfileError::SsoManaged);
                }
                free_address(&self.users, &account, raw).await?
            }
        };
        Ok(self
            .auth
            .registration_response(credential.as_str().as_bytes(), request)?)
    }

    /// Replaces the account's OPAQUE record, KDF settings and root-key wrap in one write. The key
    /// version, the bundle, the sealed private keys and the security stamp stay: the root key is
    /// the same, so the recovery kit, the passkey wraps and the trusted devices' copies still
    /// open it. A change of address asked for before is dropped, since it was made from the old
    /// password and would put it back.
    pub async fn change_password(
        &self,
        user: UserId,
        new: NewCredentials,
    ) -> Result<(), ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        let checked = check(&self.auth, new)?;
        self.users
            .update(&User {
                opaque_record: Some(checked.opaque_record),
                kdf: checked.kdf,
                wrapped_root_key: checked.wrapped_root_key,
                updated_at: self.clock.now(),
                ..account
            })
            .await?;
        self.repo.remove_email_change(user).await?;
        Ok(())
    }
}
