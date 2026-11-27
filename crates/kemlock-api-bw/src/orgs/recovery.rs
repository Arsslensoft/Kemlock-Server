//! Account recovery (Bitwarden's "admin password reset"): an organization with the account
//! recovery policy lets its members enrol, and lets an owner or admin set a new master password
//! (and clear the two-step providers) of an enrolled member.
//!
//! The server stores only what the client encrypts. Enrolling hands it the member's key, which
//! the member's client encrypted to the organization's public key; the details route gives it
//! back, with the organization's encrypted private key, to the admin's client, which decrypts it
//! and encrypts a new key for the member. The server then replaces the member's password hash and
//! wrapped key with what the admin's client made. It never sees a key or a password. In Kemlock's
//! own terms this is the space's `account-recovery` sealed box (docs/crypto.md): a member's root
//! key sealed to the space's recovery key; Bitwarden clients seal with RSA and the server keeps
//! the bytes as they come.
//!
//! The rules are Vaultwarden 1.37.5's, whose routes check the same things in the same order but
//! need an outbound mailer; there is none here, so the mail steps are left out and the routes
//! work.

use super::guard::Ctx;
use super::model::{ACCEPTED, ADMIN, MemberDoc, OWNER, level};
use super::policy::{RESET_PASSWORD, TWO_FACTOR};
use crate::app::{App, BwStore};
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::events::kind;
use crate::password::hash_password;
use axum::http::StatusCode;
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::ports::{DeviceRepo, TokenRepo, TwoFactorRepo, UserRepo};
use kemlock_domain::UserId;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// The client's KDF settings in a recovery request, under either set of names.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct KdfData {
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
struct AuthenticationData {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    kdf: KdfData,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockData {
    salt: String,
    kdf: KdfData,
    master_key_wrapped_user_key: String,
}

/// `OrganizationUserRecoverAccountRequest`; the older `reset-password` route sends only the new
/// hash and key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoverData {
    #[serde(default)]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,
    new_master_password_hash: Option<String>,
    key: Option<String>,
}

/// Whether the organization's account recovery policy turns enrolment on by itself: its data's
/// `autoEnrollEnabled`.
pub(crate) fn auto_enroll(org: &super::model::Org) -> bool {
    org.policy(RESET_PASSWORD)
        .filter(|p| p.enabled)
        .and_then(|p| serde_json::from_str::<Value>(&p.data).ok())
        .and_then(|data| {
            data.get("autoEnrollEnabled")
                .or_else(|| data.get("AutoEnrollEnabled"))
                .and_then(Value::as_bool)
        })
        .unwrap_or(false)
}

/// `check_reset_password_applicable`: the policy must exist and be on.
fn policy_on(ctx: &Ctx) -> BwResult<()> {
    match ctx.org.policy(RESET_PASSWORD) {
        None => Err(BwError::msg("Policy not found")),
        Some(policy) if !policy.enabled => Err(BwError::msg("Reset password policy not enabled")),
        Some(_) => Ok(()),
    }
}

/// What the caller may reset: an owner anyone, an admin anyone but an owner.
fn may_reset(ctx: &Ctx, target: &MemberDoc) -> BwResult<()> {
    if ctx.doc.atype == OWNER || level(target.atype) <= level(ADMIN) {
        return Ok(());
    }
    Err(BwError::msg("No permission to reset this user's password"))
}

/// The member a recovery route is about, with the checks every one of them makes first.
fn target_of(ctx: &Ctx, member_id: &str) -> BwResult<(UserId, MemberDoc)> {
    let isnt_member = || BwError::msg("User to reset isn't member of required organization");
    let user = Uuid::parse_str(member_id)
        .map(UserId)
        .map_err(|_| isnt_member())?;
    let doc = ctx.org.member(user).cloned().ok_or_else(isnt_member)?;
    Ok((user, doc))
}

/// `PUT /api/organizations/{id}/users/{user}/reset-password-enrollment`: the caller's key for
/// recovery, as their client encrypted it; empty or absent withdraws.
pub(crate) async fn enroll<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    reset_key: Option<String>,
    proof: impl std::future::Future<Output = BwResult<()>>,
) -> BwResult<()> {
    policy_on(ctx)?;
    let key = reset_key.filter(|k| !k.is_empty());
    if key.is_none() && auto_enroll(&ctx.org) {
        return Err(BwError::msg(
            "Reset password can't be withdrawn due to an enterprise policy",
        ));
    }
    // Giving a key away needs the account's password.
    if key.is_some() {
        proof.await?;
    }
    let mut doc = ctx.doc.clone();
    let enrolled = key.is_some();
    doc.reset_password_key = key;
    app.put_member(&ctx.org, ctx.me, &doc, ctx.me).await?;
    let event = if enrolled {
        kind::MEMBER_RESET_PASSWORD_ENROLLED
    } else {
        kind::MEMBER_RESET_PASSWORD_WITHDRAWN
    };
    ctx.log(app, event, &ctx.me.to_string()).await;
    Ok(())
}

/// `GET /api/organizations/{id}/users/{user}/reset-password-details`: what the admin's client
/// needs to decrypt the member's key and make a new one.
pub(crate) async fn details<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    member_id: &str,
) -> BwResult<Value> {
    let (user, target) = target_of(ctx, member_id)?;
    let Some(account_user) = UserRepo::by_id(&app.store, user).await? else {
        return Err(BwError::msg("User not found"));
    };
    policy_on(ctx)?;
    may_reset(ctx, &target)?;
    let account = BwAccountRepo::get(&app.store, user)
        .await?
        .ok_or_else(|| BwError::msg("User not found"))?;
    Ok(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": user.to_string(),
        "kdf": account.kdf_type,
        "kdfIterations": account.kdf_iterations,
        "kdfMemory": account.kdf_memory,
        "kdfParallelism": account.kdf_parallelism,
        "masterPasswordSalt": account_user.email.as_str().trim().to_lowercase(),
        "resetPasswordKey": target.reset_password_key,
        "encryptedPrivateKey": ctx.org.doc.private_key,
    }))
}

/// The new password hash and wrapped key a request carries, after the checks on its KDF.
fn credentials(
    data: RecoverData,
    email: &str,
    kdf: (i32, i32, Option<i32>, Option<i32>),
) -> BwResult<(String, String)> {
    match (
        data.authentication_data,
        data.unlock_data,
        data.new_master_password_hash,
        data.key,
    ) {
        (Some(authentication), Some(unlock), _, _) => {
            if authentication.kdf != unlock.kdf {
                return Err(BwError::msg(
                    "KDF settings must be equal for authentication and unlock",
                ));
            }
            let salt = email.trim().to_lowercase();
            if authentication.salt != salt || salt != unlock.salt {
                return Err(BwError::msg("Invalid master password salt"));
            }
            let sent = &authentication.kdf;
            let same = (
                sent.kdf,
                sent.kdf_iterations,
                sent.kdf_memory,
                sent.kdf_parallelism,
            ) == kdf;
            if !same {
                return Err(BwError::msg("KDF settings do not match the user account"));
            }
            Ok((
                authentication.master_password_authentication_hash,
                unlock.master_key_wrapped_user_key,
            ))
        }
        (_, _, Some(hash), Some(key)) => Ok((hash, key)),
        _ => Err(BwError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Missing fields to reset password",
        )),
    }
}

/// `PUT …/recover-account` and the older `…/reset-password`: sets the member's new password and
/// key, and clears their two-step providers, as asked. `legacy` is the older route, which always
/// resets the password and never the providers.
pub(crate) async fn recover<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    member_id: &str,
    data: RecoverData,
    legacy: bool,
) -> BwResult<()> {
    let (reset_password, reset_two_factor) = if legacy {
        (true, false)
    } else {
        (data.reset_master_password, data.reset_two_factor)
    };
    let (user, target) = target_of(ctx, member_id)?;
    let Some(mut account_user) = UserRepo::by_id(&app.store, user).await? else {
        return Err(BwError::msg("User not found"));
    };
    policy_on(ctx)?;
    may_reset(ctx, &target)?;
    if target.reset_password_key.is_none() {
        return Err(BwError::msg("Password reset not or not correctly enrolled"));
    }
    if !target.confirmed() {
        return Err(BwError::msg(
            "Organization user must be confirmed for password reset functionality",
        ));
    }
    let mut account = BwAccountRepo::get(&app.store, user)
        .await?
        .ok_or_else(|| BwError::msg("User not found"))?;

    let new = if reset_password {
        let kdf = (
            account.kdf_type,
            account.kdf_iterations,
            account.kdf_memory,
            account.kdf_parallelism,
        );
        Some(credentials(data, account_user.email.as_str(), kdf)?)
    } else {
        None
    };

    if let Some((hash, key)) = new {
        let (secret, salt, iterations) = (
            hash.as_bytes().to_vec(),
            account.salt.clone(),
            account.password_iterations,
        );
        account.password_hash = app
            .hashing(app.who_of(user, None), move || {
                hash_password(&secret, &salt, iterations)
            })
            .await?;
        account.akey = key;
        BwAccountRepo::update(&app.store, &account).await?;
    }
    if reset_password || reset_two_factor {
        // Every session the member had ends: a new password and an emptied second step are a
        // sign-in nobody holds a token for.
        account_user.security_stamp = random_uuid(app.env.as_ref());
        account_user.updated_at = app.now();
        UserRepo::update(&app.store, &account_user).await?;
        for device in DeviceRepo::list(&app.store, user).await? {
            TokenRepo::revoke_device(&app.store, device.id).await?;
        }
    }
    if reset_two_factor {
        for enrolment in TwoFactorRepo::list(&app.store, user).await? {
            TwoFactorRepo::remove(&app.store, user, enrolment.method).await?;
        }
        enforce_two_factor_policy(app, ctx, user).await?;
    }
    app.touch(user).await?;
    if reset_password {
        ctx.log(app, kind::MEMBER_ADMIN_RESET_PASSWORD, &user.to_string())
            .await;
    }
    if reset_two_factor {
        ctx.log(app, kind::MEMBER_ADMIN_RESET_TWO_FACTOR, &user.to_string())
            .await;
    }
    Ok(())
}

/// A member with no second step left can't stay in an organization that requires one: they are
/// revoked there until they set one up.
async fn enforce_two_factor_policy<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    user: UserId,
) -> BwResult<()> {
    for org in app.orgs_of(user).await? {
        if !org.policy_enabled(TWO_FACTOR) {
            continue;
        }
        let Some(mut doc) = org.member(user).cloned() else {
            continue;
        };
        if level(doc.atype) >= level(ADMIN) || doc.revoked() || doc.unrevoked_status() < ACCEPTED {
            continue;
        }
        doc.revoke();
        app.put_member(&org, user, &doc, ctx.me).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(value: Value) -> RecoverData {
        serde_json::from_value(value).expect("parses")
    }

    const KDF: (i32, i32, Option<i32>, Option<i32>) = (0, 600_000, None, None);

    #[test]
    fn a_legacy_payload_carries_its_hash_and_key() {
        let got = credentials(
            data(json!({"newMasterPasswordHash": "h", "key": "k"})),
            "Ada@Example.com",
            KDF,
        );
        assert_eq!(got, Ok(("h".to_owned(), "k".to_owned())));
    }

    #[test]
    fn a_current_payload_is_checked_against_the_accounts_kdf_and_salt() {
        let kdf = json!({"kdfType": 0, "iterations": 600_000});
        let good = json!({
            "authenticationData": {"salt": "ada@example.com", "kdf": kdf,
                "masterPasswordAuthenticationHash": "h"},
            "unlockData": {"salt": "ada@example.com", "kdf": kdf,
                "masterKeyWrappedUserKey": "k"},
        });
        assert_eq!(
            credentials(data(good.clone()), "Ada@Example.com", KDF),
            Ok(("h".to_owned(), "k".to_owned()))
        );
        assert_eq!(
            credentials(
                data(good.clone()),
                "ada@example.com",
                (0, 100_000, None, None)
            ),
            Err(BwError::msg("KDF settings do not match the user account"))
        );
        assert_eq!(
            credentials(data(good), "bob@example.com", KDF),
            Err(BwError::msg("Invalid master password salt"))
        );
    }

    #[test]
    fn a_payload_with_neither_form_is_unprocessable() {
        assert_eq!(
            credentials(data(json!({"resetMasterPassword": true})), "a@b.c", KDF),
            Err(BwError::status(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Missing fields to reset password"
            ))
        );
    }
}
