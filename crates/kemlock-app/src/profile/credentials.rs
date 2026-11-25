//! The password's records: the OPAQUE registration that makes a new record, and the replacement of
//! the record, the KDF settings and the root-key wrap in one write.

use super::ticket::Ticket;
use super::{ProfileError, ProfileRepo, account, changeable_password, is_taken, new_address};
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::notices::{Notice, Notices, PasswordChangedNotice};
use crate::platform::{Platform, random_uuid};
use crate::ports::{PasswordAuth, SecretSeal, UserRepo};
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

/// The server's half of the first registration message, and the ticket to bring back with the last.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistrationStarted {
    /// OPAQUE's `RegistrationResponse`.
    pub response: Vec<u8>,
    /// The sealed ticket that binds the registration to the account, the DPoP key, the address
    /// asked for (if any) and the next few minutes.
    pub ticket: Vec<u8>,
}

impl std::fmt::Debug for RegistrationStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationStarted").finish_non_exhaustive()
    }
}

/// What a change of password did.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordChanged {
    /// The account as it is now, for the sessions that follow.
    pub account: User,
    /// The security stamp was replaced, so every session of the account ended with the write.
    pub others_signed_out: bool,
}

impl std::fmt::Debug for PasswordChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The account holds the record and the wrap.
        f.debug_struct("PasswordChanged")
            .field("others_signed_out", &self.others_signed_out)
            .finish_non_exhaustive()
    }
}

/// Changing the master password, and the first message of the registration that makes the new
/// record for it or for a new address.
#[derive(Debug)]
pub struct Credentials<U, R, P, S, E> {
    pub users: U,
    pub repo: R,
    pub auth: P,
    pub seal: S,
    pub env: E,
    pub notices: Notices,
    /// Gives the ticket its lifetime: that of a login state.
    pub config: AuthConfig,
}

impl<U: UserRepo, R: ProfileRepo, P: PasswordAuth, S: SecretSeal, E: Platform>
    Credentials<U, R, P, S, E>
{
    /// Whether the account has a master password this API can change, and `ticket` is a good one
    /// for a change of it. Asked before the password is spent, so a refusal that can be known
    /// costs the person nothing.
    pub async fn check(&self, user: UserId, ticket: &[u8], jkt: &str) -> Result<(), ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        self.open_for_password(&account, ticket, jkt)
    }

    /// OPAQUE registration, first message. It is bound to the account's own address, or to `email`
    /// when the registration is for a new address, which may not be an identity provider's
    /// account's. An address another account has is answered as a free one is, so the answer says
    /// nothing of who has an account: the server's half is evaluated for random bytes instead of
    /// that address, and never for another account's identifier. The ticket says which it was.
    pub async fn start(
        &self,
        user: UserId,
        email: Option<&str>,
        request: &[u8],
        jkt: &str,
    ) -> Result<RegistrationStarted, ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        let (address, credential) = match email {
            None => (None, account.email.as_str().as_bytes().to_vec()),
            Some(raw) => {
                if self.repo.has_sso_identity(user).await? {
                    return Err(ProfileError::SsoManaged);
                }
                let email = new_address(&account, raw)?;
                let credential = if is_taken(&self.users, &account, &email).await? {
                    self.env.bytes::<32>().to_vec()
                } else {
                    email.as_str().as_bytes().to_vec()
                };
                (Some(email), credential)
            }
        };
        let response = self.auth.registration_response(&credential, request)?;
        let ticket = Ticket {
            expires_at: (self.env.now() + self.config.challenge_ttl).unix_timestamp(),
            user,
            address: address.map(|email| email.as_str().to_owned()),
            credential: self.env.sha256(&credential),
            jkt: jkt.to_owned(),
        }
        .seal(&self.seal);
        Ok(RegistrationStarted { response, ticket })
    }

    /// Replaces the account's OPAQUE record, KDF settings and root-key wrap in one write, which is
    /// conditional on nobody having written the account since it was read here
    /// ([`ProfileError::AccountChanged`] otherwise, with nothing written). The key version, the
    /// bundle and the sealed private keys stay: the root key is the same, so the recovery kit, the
    /// passkey wraps and the trusted devices' copies still open it. With `sign_out_others` the
    /// security stamp is replaced in the same write, which ends every session of the account at
    /// once: the caller gives the device that asked new ones. A change of address asked for before
    /// is dropped with it, since it was made from the old password and would put it back.
    ///
    /// Once the write is made nothing after it can fail the change: the notice is best effort.
    pub async fn change_password(
        &self,
        user: UserId,
        new: NewCredentials,
        ticket: &[u8],
        jkt: &str,
        sign_out_others: bool,
    ) -> Result<PasswordChanged, ProfileError> {
        let account = account(&self.users, user).await?;
        changeable_password(&account)?;
        self.open_for_password(&account, ticket, jkt)?;
        let checked = check(&self.auth, new)?;
        let now = self.env.now();
        let after = User {
            opaque_record: Some(checked.opaque_record),
            kdf: checked.kdf,
            wrapped_root_key: checked.wrapped_root_key,
            security_stamp: if sign_out_others {
                random_uuid(&self.env)
            } else {
                account.security_stamp
            },
            updated_at: now,
            ..account.clone()
        };
        if !self.repo.replace_credentials(&account, &after).await? {
            return Err(ProfileError::AccountChanged);
        }
        self.notices
            .send(Notice::PasswordChanged(PasswordChangedNotice {
                to: after.email.clone(),
                at: now,
                others_signed_out: sign_out_others,
            }))
            .await;
        Ok(PasswordChanged {
            account: after,
            others_signed_out: sign_out_others,
        })
    }

    /// The ticket, if it is a good one for a new password of `account`: handed to this account
    /// and this DPoP key, not run out, asked for no address, and the server's half was made for
    /// the address the account has now.
    fn open_for_password(
        &self,
        account: &User,
        ticket: &[u8],
        jkt: &str,
    ) -> Result<(), ProfileError> {
        let ticket = Ticket::open(&self.seal, ticket, self.env.now(), account.id, jkt)?;
        if ticket.address.is_some()
            || ticket.credential != self.env.sha256(account.email.as_str().as_bytes())
        {
            return Err(AppError::Invalid("the registration ticket is not valid").into());
        }
        Ok(())
    }
}
