//! `POST /api/accounts/kdf`: new KDF settings for the master password, as Vaultwarden takes them.
//!
//! Bitwarden clients from 2026.10 call it at sign-in to move a PBKDF2 account below 600,000
//! rounds to the minimum (their `MinimumKdfMigration`), so without it such an account can't sign
//! in from them at all. The password stays the same; its hash and the wrapped user key change.
//!
//! Vaultwarden resets the security stamp and lets the calling device refresh its way back in, and
//! so does this: the stamp moves, which ends every access token (and every live connection) at
//! once, the other devices' refresh tokens are revoked so they sign in again with the new hash,
//! and the calling device's refresh tokens follow the new stamp, so its next refresh works.

use crate::account::{Kdf, check_valid_password};
use crate::app::{App, Authed, BwStore};
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::password::hash_password;
use kemlock_app::bitwarden::{BwAccountRepo, BwUserKeyIdRepo};
use kemlock_app::ports::{DeviceRepo, TokenRepo, UserRepo};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticationData {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    kdf: KdfData,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnlockData {
    salt: String,
    kdf: KdfData,
    master_key_wrapped_user_key: String,
    contained_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangeKdfData {
    authentication_data: AuthenticationData,
    unlock_data: UnlockData,
    master_password_hash: String,
}

/// Vaultwarden's `post_kdf`, with its checks in its order and its messages.
pub(crate) async fn change_kdf<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: ChangeKdfData,
) -> BwResult<()> {
    let mut account = authed.account.clone();
    if !check_valid_password(&account, &data.master_password_hash) {
        return Err(BwError::msg("Invalid password"));
    }
    let (auth, unlock) = (&data.authentication_data, &data.unlock_data);
    if auth.kdf != unlock.kdf {
        return Err(BwError::msg(
            "KDF settings must be equal for authentication and unlock",
        ));
    }
    let salt = authed.user.email.as_str().trim().to_lowercase();
    if auth.salt != salt || auth.salt != unlock.salt {
        return Err(BwError::msg("Invalid master password salt"));
    }
    // The user key stays, so the key it wraps must be the one the server knows, when both are.
    let known = BwUserKeyIdRepo::user_key_id(&app.store, account.user).await?;
    if let (Some(known), Some(contained)) = (known.as_deref(), unlock.contained_key_id.as_deref())
        && known != contained
    {
        return Err(BwError::msg(
            "Invalid user key sent in master-password unlock data.",
        ));
    }
    let kdf = Kdf {
        kind: unlock.kdf.kdf,
        iterations: unlock.kdf.kdf_iterations,
        memory: unlock.kdf.kdf_memory,
        parallelism: unlock.kdf.kdf_parallelism,
    }
    .checked()?;

    account.kdf_type = kdf.kind;
    account.kdf_iterations = kdf.iterations;
    account.kdf_memory = kdf.memory;
    account.kdf_parallelism = kdf.parallelism;
    account.password_iterations = app.settings.password_iterations;
    account.password_hash = hash_password(
        auth.master_password_authentication_hash.as_bytes(),
        &account.salt,
        account.password_iterations,
    );
    account.akey.clone_from(&unlock.master_key_wrapped_user_key);
    BwAccountRepo::update(&app.store, &account).await?;
    // As Vaultwarden does, the security stamp moves: every access token the account had, and every
    // live connection that holds one, is dead at once, not up to two hours from now.
    // Only the stamp (and the time of the change) is written, on the account as it is now, not on
    // the copy this request was authenticated with, so nothing changed meanwhile is written back.
    let mut user = UserRepo::by_id(&app.store, account.user)
        .await?
        .ok_or(BwError::Unauthorized)?;
    user.security_stamp = random_uuid(app.env.as_ref());
    user.updated_at = app.now();
    UserRepo::update(&app.store, &user).await?;
    for device in DeviceRepo::list(&app.store, account.user).await? {
        if device.id != authed.device.id {
            TokenRepo::revoke_device(&app.store, device.id).await?;
        }
    }
    // The calling device keeps its way back in, as it does in Vaultwarden: its refresh tokens
    // follow the new stamp, so its next refresh gives it a new access token.
    TokenRepo::restamp_device(&app.store, authed.device.id, user.security_stamp).await?;
    app.touch(account.user).await?;
    app.sessions_ended(authed);
    Ok(())
}
