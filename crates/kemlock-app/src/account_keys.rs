//! The signed-in account's key material, as the server holds it: what a new browser needs to
//! unlock the vault once it has the password.

use crate::error::AppError;
use crate::ports::UserRepo;
use kemlock_domain::{KdfParams, UserId};

/// Everything the server keeps for the account's keys. Every value is ciphertext or public: the
/// root key is wrapped under the master key and the OPAQUE export key, the private keys under the
/// user key, and the bundle holds only public keys. An account made by single sign-on has no
/// keys until a device enrols them (the use case answers not-found until then, a 404); once
/// enrolled it has no password, so its `wrapped_root_key` is empty: its devices open the vault
/// with a trusted-device copy, a passkey's PRF wrap or an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeysView {
    pub key_version: u32,
    pub kdf: KdfParams,
    pub wrapped_root_key: Vec<u8>,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
}

#[derive(Debug)]
pub struct AccountKeys<U> {
    pub users: U,
}

impl<U: UserRepo> AccountKeys<U> {
    /// The account's keys; `NotFound` for an account that has none yet (a Compatible account that
    /// has not enrolled OPAQUE, or an SSO account whose device has not made its keys).
    pub async fn execute(&self, user: UserId) -> Result<AccountKeysView, AppError> {
        let account = self
            .users
            .by_id(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if account.public_bundle.is_empty() {
            return Err(AppError::NotFound);
        }
        Ok(AccountKeysView {
            key_version: account.key_version,
            kdf: account.kdf,
            wrapped_root_key: account.wrapped_root_key,
            public_bundle: account.public_bundle,
            bundle_signature: account.bundle_signature,
            sealed_private_keys: account.sealed_private_keys,
        })
    }
}
