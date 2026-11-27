//! `POST /api/accounts/kdf`: new KDF settings for the master password, as Vaultwarden takes them.
//!
//! Bitwarden clients from 2026.10 call it at sign-in to move a PBKDF2 account below 600,000
//! rounds to the minimum (their `MinimumKdfMigration`), so without it such an account can't sign
//! in from them at all. The password stays the same; its hash and the wrapped user key change.
//!
//! Vaultwarden resets the security stamp and lets the calling device refresh its way back in. Not
//! here: the clients compare the stamp at every sync and sign themselves out when it changed, so
//! the client that asked for the change would sign itself out (the Bitwarden CLI does). The stamp
//! stays and every other device's sign-in is revoked instead, which ends its access token at once
//! too (`App::session` takes a signed-in device's access token only while its sign-in lives) and
//! closes its live connections; it signs in again with the password, whose old hash no longer
//! matches. The calling device keeps its session.

use crate::account::Kdf;
use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::password::hash_password;
use kemlock_app::bitwarden::{BwAccountRepo, BwUserKeyIdRepo};
use kemlock_app::ports::{DeviceRepo, TokenRepo};
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
    if !app
        .password_matches(&account, &data.master_password_hash, Some(authed.ip))
        .await?
    {
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
    let (secret, salt, iterations) = (
        auth.master_password_authentication_hash.as_bytes().to_vec(),
        account.salt.clone(),
        account.password_iterations,
    );
    account.password_hash = app
        .hashing(app.who_of(account.user, Some(authed.ip)), move || {
            hash_password(&secret, &salt, iterations)
        })
        .await?;
    account.akey.clone_from(&unlock.master_key_wrapped_user_key);
    BwAccountRepo::update(&app.store, &account).await?;
    // Every other device's sign-in ends, and with it its access token, not up to two hours from
    // now.
    for device in DeviceRepo::list(&app.store, account.user).await? {
        if device.id != authed.device.id {
            TokenRepo::revoke_device(&app.store, device.id).await?;
        }
    }
    app.touch(account.user).await?;
    app.sessions_ended(authed);
    Ok(())
}
