//! The Recovery Kit: the account's root key wrapped under a key that is split into 3 pieces, any 2
//! of which rebuild it (docs/crypto.md, "The Recovery Kit").
//!
//! The browser's key worker makes the kit and keeps the pieces' secrecy; the server keeps only the
//! non-secret record: the kit id, when it was made, the key version it is for and the wrap, which
//! only the pieces open and whose AEAD tag is the check that rebuilt pieces are right. An account
//! has at most one kit; making a new one replaces the old, so its pieces stop working.

use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{StoreError, UserRepo};
use kemlock_crypto::recovery_kit::{WRAPPED_LEN, is_kit_id};
use kemlock_domain::{RecoveryKit, User, UserId};
use std::future::Future;

/// Where Recovery Kit records are kept: one per account.
pub trait RecoveryKitRepo: Send + Sync {
    /// The account's kit.
    fn recovery_kit(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<RecoveryKit>, StoreError>> + Send;

    /// Stores the account's first kit; `false` when it has one and nothing was written.
    fn insert_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Replaces the account's kit; `false` when it has none and nothing was written.
    fn replace_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Removes the account's kit; `true` when there was one.
    fn remove_recovery_kit(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// What a client sends to make or replace a kit.
#[derive(Clone, Debug)]
pub struct NewKit {
    pub kit_id: String,
    pub wrapped_key: Vec<u8>,
    pub key_version: u32,
}

/// A kit as an account sees it: the record, and whether its wrap is for the account's current key
/// version, so the pieces can still open the vault.
#[derive(Clone, Debug)]
pub struct KitView {
    pub kit: RecoveryKit,
    pub current: bool,
}

/// Making, showing, replacing and removing the account's Recovery Kit.
#[derive(Debug)]
pub struct RecoveryKits<R, U, E> {
    pub kits: R,
    pub users: U,
    pub env: E,
}

impl<R, U, E> RecoveryKits<R, U, E>
where
    R: RecoveryKitRepo,
    U: UserRepo,
    E: Platform,
{
    async fn account(&self, user: UserId) -> Result<User, AppError> {
        self.users.by_id(user).await?.ok_or(AppError::Unauthorized)
    }

    /// A kit is kept only with a well-formed id, the length of a wrapped root key, and the
    /// account's current key version: a wrap for another version opens nothing.
    fn checked(&self, account: &User, new: NewKit) -> Result<RecoveryKit, AppError> {
        if !is_kit_id(&new.kit_id) {
            return Err(AppError::Invalid("the kit id is not 8 base32 characters"));
        }
        if new.wrapped_key.len() != WRAPPED_LEN {
            return Err(AppError::Invalid("the wrapped key has the wrong length"));
        }
        if new.key_version != account.key_version {
            return Err(AppError::Invalid(
                "the wrapped key is for another key version than the account's",
            ));
        }
        Ok(RecoveryKit {
            kit_id: new.kit_id,
            wrapped_key: new.wrapped_key,
            key_version: new.key_version,
            created_at: self.env.now(),
        })
    }

    /// The account's kit, or `None`.
    pub async fn show(&self, user: UserId) -> Result<Option<KitView>, AppError> {
        let account = self.account(user).await?;
        Ok(self.kits.recovery_kit(user).await?.map(|kit| KitView {
            current: kit.key_version == account.key_version,
            kit,
        }))
    }

    /// Makes the account's first kit. `Duplicate` when it has one: replace it instead.
    pub async fn create(&self, user: UserId, new: NewKit) -> Result<RecoveryKit, AppError> {
        let kit = self.checked(&self.account(user).await?, new)?;
        if !self.kits.insert_recovery_kit(user, &kit).await? {
            return Err(AppError::Duplicate);
        }
        Ok(kit)
    }

    /// Replaces the account's kit with a new one: the old pieces stop working. `NotFound` when it
    /// has none.
    pub async fn regenerate(&self, user: UserId, new: NewKit) -> Result<RecoveryKit, AppError> {
        let kit = self.checked(&self.account(user).await?, new)?;
        if !self.kits.replace_recovery_kit(user, &kit).await? {
            return Err(AppError::NotFound);
        }
        Ok(kit)
    }

    /// Removes the account's kit. `NotFound` when it has none.
    pub async fn remove(&self, user: UserId) -> Result<(), AppError> {
        if !self.kits.remove_recovery_kit(user).await? {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}
