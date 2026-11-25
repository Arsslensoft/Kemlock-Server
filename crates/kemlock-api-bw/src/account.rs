//! Accounts: prelogin, the profile, registration and the personal API key.

use crate::app::{App, BwStore};
use crate::dates::{epoch_millis, format_date};
use crate::env::{random_alphanumeric, random_bytes, random_uuid};
use crate::error::{BwError, BwResult};
use crate::password::{hash_password, verify_password};
use crate::tokens::RegisterVerifyClaims;
use axum::http::StatusCode;
use kemlock_app::AppError;
use kemlock_app::admin::{InviteGate, InviteTicket};
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::ports::{StoreError, TwoFactorRepo, UserRepo};
use kemlock_app::spaces::SpaceRepo;
use kemlock_crypto::hash;
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) const PBKDF2: i32 = 0;
pub(crate) const ARGON2ID: i32 = 1;

/// A KDF type, cost and (for Argon2id) memory in MiB and lanes, as Bitwarden clients send them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kdf {
    pub kind: i32,
    pub iterations: i32,
    pub memory: Option<i32>,
    pub parallelism: Option<i32>,
}

impl Kdf {
    /// Vaultwarden's `set_kdf_data` checks, with its messages. Memory and lanes are dropped for
    /// PBKDF2.
    pub(crate) fn checked(self) -> BwResult<Kdf> {
        if self.kind == PBKDF2 && self.iterations < 100_000 {
            return Err(BwError::msg(
                "PBKDF2 KDF iterations must be at least 100000.",
            ));
        }
        if self.kind == ARGON2ID {
            if self.iterations < 1 {
                return Err(BwError::msg("Argon2 KDF iterations must be at least 1."));
            }
            match self.memory {
                Some(m) if (15..=1024).contains(&m) => {}
                Some(_) => {
                    return Err(BwError::msg(
                        "Argon2 memory must be between 15 MB and 1024 MB.",
                    ));
                }
                None => return Err(BwError::msg("Argon2 memory parameter is required.")),
            }
            match self.parallelism {
                Some(p) if (1..=16).contains(&p) => {}
                Some(_) => {
                    return Err(BwError::msg("Argon2 parallelism must be between 1 and 16."));
                }
                None => return Err(BwError::msg("Argon2 parallelism parameter is required.")),
            }
            Ok(self)
        } else {
            Ok(Kdf {
                memory: None,
                parallelism: None,
                ..self
            })
        }
    }
}

/// The settings of an email with no account: one of six common ones picked by a keyed hash of the
/// email, so they stay the same between requests. The default is listed twice to weigh it more.
pub(crate) fn unknown_email_kdf<S: BwStore>(app: &App<S>, email: &str) -> Kdf {
    const SETTINGS: [Kdf; 6] = [
        Kdf {
            kind: PBKDF2,
            iterations: 600_000,
            memory: None,
            parallelism: None,
        },
        Kdf {
            kind: PBKDF2,
            iterations: 600_000,
            memory: None,
            parallelism: None,
        },
        Kdf {
            kind: PBKDF2,
            iterations: 100_000,
            memory: None,
            parallelism: None,
        },
        Kdf {
            kind: PBKDF2,
            iterations: 5_000,
            memory: None,
            parallelism: None,
        },
        Kdf {
            kind: ARGON2ID,
            iterations: 3,
            memory: Some(64),
            parallelism: Some(4),
        },
        Kdf {
            kind: ARGON2ID,
            iterations: 6,
            memory: Some(32),
            parallelism: Some(4),
        },
    ];
    let tag = hash::hmac_sha256(&app.prelogin_key, email.as_bytes());
    SETTINGS[usize::from(u16::from_be_bytes([tag[0], tag[1]])) % SETTINGS.len()]
}

/// The body of both prelogin routes.
pub(crate) async fn prelogin<S: BwStore>(app: &App<S>, email: &str) -> BwResult<Value> {
    let email = email.trim().to_lowercase();
    let known = match Email::parse(&email) {
        Ok(parsed) => match UserRepo::by_email(&app.store, &parsed).await? {
            Some(user) => BwAccountRepo::get(&app.store, user.id).await?,
            None => None,
        },
        Err(_) => None,
    };
    let kdf = match known {
        Some(a) => Kdf {
            kind: a.kdf_type,
            iterations: a.kdf_iterations,
            memory: a.kdf_memory,
            parallelism: a.kdf_parallelism,
        },
        None => unknown_email_kdf(app, &email),
    };
    Ok(json!({
        "kdf": kdf.kind,
        "kdfIterations": kdf.iterations,
        "kdfMemory": kdf.memory,
        "kdfParallelism": kdf.parallelism,
        "kdfSettings": {
            "iterations": kdf.iterations,
            "kdfType": kdf.kind,
            "memory": kdf.memory,
            "parallelism": kdf.parallelism
        },
        "salt": null,
    }))
}

/// Whether `password` (the text of the client's `masterPasswordHash`) is the account's.
pub(crate) fn check_valid_password(account: &BwAccount, password: &str) -> bool {
    verify_password(
        password.as_bytes(),
        &account.salt,
        &account.password_hash,
        account.password_iterations,
    )
}

/// Re-hashes the password with the current number of rounds when the account has fewer, as
/// Vaultwarden's `kdf_upgrade` does after a correct check. Returns whether it did.
pub(crate) async fn kdf_upgrade<S: BwStore>(
    app: &App<S>,
    account: &mut BwAccount,
    password: &str,
) -> BwResult<bool> {
    if account.password_iterations >= app.settings.password_iterations {
        return Ok(false);
    }
    account.password_iterations = app.settings.password_iterations;
    account.password_hash = hash_password(
        password.as_bytes(),
        &account.salt,
        account.password_iterations,
    );
    BwAccountRepo::update(&app.store, account).await?;
    app.touch(account.user).await?;
    Ok(true)
}

/// The user's name as Vaultwarden shows it: its own, which defaults to the email.
pub(crate) fn user_name(user: &User) -> String {
    user.name
        .clone()
        .unwrap_or_else(|| user.email.as_str().to_owned())
}

/// `accountKeys` in `/api/sync` and the profile (Vaultwarden's `account_keys_json`).
pub(crate) fn account_keys_json(account: &BwAccount) -> Value {
    if account.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": account.private_key,
                "publicKey": account.public_key,
                "signedPublicKey": null,
                "object": "publicKeyEncryptionKeyPair",
            },
            "securityState": null,
            "signatureKeyPair": null,
            "object": "privateKeys"
        })
    } else {
        Value::Null
    }
}

/// `profile`: the user as `/api/sync` and `/api/accounts/profile` show it.
pub(crate) async fn profile_json<S: BwStore>(
    app: &App<S>,
    user: &User,
    account: &BwAccount,
) -> BwResult<Value> {
    let two_factor = !TwoFactorRepo::list(&app.store, user.id).await?.is_empty();
    let status = i32::from(account.password_hash.is_empty());
    let (organizations, organizations_new) = crate::orgs::profile_orgs(app, user.id).await?;
    Ok(json!({
        "_status": status,
        "accountKeys": account_keys_json(account),
        "id": user.id.to_string(),
        "name": user_name(user),
        "email": user.email.as_str(),
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "culture": "en-US",
        "twoFactorEnabled": two_factor,
        "key": account.akey,
        "privateKey": account.private_key,
        "securityStamp": user.security_stamp.to_string(),
        "organizations": organizations,
        "organizationsNew": organizations_new,
        "providers": [],
        "providerOrganizations": [],
        "forcePasswordReset": false,
        "avatarColor": account.avatar_color,
        "usesKeyConnector": false,
        "creationDate": format_date(user.created_at),
        "object": "profile",
    }))
}

/// `userDecryption` in `/api/sync` (camelCase here; the token answer's copy is PascalCase).
/// `userKeyId` is left out while the server holds none, as in Vaultwarden.
pub(crate) fn user_decryption_json(
    user: &User,
    account: &BwAccount,
    key_id: Option<&str>,
) -> Value {
    let unlock = if account.password_hash.is_empty() {
        Value::Null
    } else {
        json!({
            "kdf": {
                "kdfType": account.kdf_type,
                "iterations": account.kdf_iterations,
                "memory": account.kdf_memory,
                "parallelism": account.kdf_parallelism
            },
            "masterKeyEncryptedUserKey": account.akey,
            "masterKeyWrappedUserKey": account.akey,
            "salt": user.email.as_str()
        })
    };
    let mut out = json!({ "masterPasswordUnlock": unlock });
    if let Some(key_id) = key_id {
        out["userKeyId"] = json!(key_id);
    }
    out
}

/// Whether `key_id` is a Bitwarden `KeyId`: 32 lowercase hex digits.
pub(crate) fn is_key_id(key_id: &str) -> bool {
    key_id.len() == 32
        && key_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `POST /api/accounts/key-management/user-key-id`: records the id of the account's user key,
/// once. Afterwards only a key rotation would change it, so a second report is refused.
pub(crate) async fn record_user_key_id<S: BwStore>(
    app: &App<S>,
    user: UserId,
    key_id: &str,
) -> BwResult<()> {
    if !app.store.put_user_key_id_if_absent(user, key_id).await? {
        return Err(BwError::msg("User key id is already set."));
    }
    app.touch(user).await
}

/// What a registration request says, in either of the two shapes clients send.
#[derive(Debug)]
pub(crate) struct Registration {
    pub email: String,
    pub hash: String,
    pub kdf: Kdf,
    pub key: String,
    /// The wrapped RSA private key and the public key, when the client made a pair.
    pub keys: Option<(String, String)>,
    pub hint: Option<String>,
    pub verification_token: Option<String>,
    /// `inviteToken`: the token of a server invitation (Kemlock's own field; Bitwarden clients
    /// never send it).
    pub invite_token: Option<String>,
}

fn text(v: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| v.get(*n).and_then(Value::as_str))
        .map(str::to_owned)
}

fn pick<'a>(v: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names
        .iter()
        .find_map(|n| v.get(*n))
        .filter(|x| !x.is_null())
}

fn kdf_of(v: &Value) -> Option<Kdf> {
    let number = |names: &[&str]| pick(v, names).and_then(Value::as_i64);
    let int = |names: &[&str]| number(names).and_then(|n| i32::try_from(n).ok());
    Some(Kdf {
        kind: int(&["kdf", "kdfType", "Kdf", "KdfType"])?,
        iterations: int(&["kdfIterations", "iterations", "KdfIterations", "Iterations"])?,
        memory: int(&["kdfMemory", "memory", "KdfMemory", "Memory"]),
        parallelism: int(&[
            "kdfParallelism",
            "parallelism",
            "KdfParallelism",
            "Parallelism",
        ]),
    })
}

/// Parses `RegisterData`: the flat form (`masterPasswordHash`, `userSymmetricKey`, KDF fields) or
/// the current one (`masterPasswordAuthentication` and `masterPasswordUnlock`). A request that
/// breaks neither shape's rules about its salt and KDF is a 422, as in Vaultwarden.
pub(crate) fn parse_registration(body: &Value) -> BwResult<Registration> {
    let malformed = || {
        BwError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unexpected RegisterData format",
        )
    };
    let email = text(body, &["email"]).ok_or_else(malformed)?;
    let (hash, kdf, key) = if let Some(auth) = pick(
        body,
        &[
            "masterPasswordAuthentication",
            "MasterPasswordAuthentication",
        ],
    ) {
        let unlock =
            pick(body, &["masterPasswordUnlock", "MasterPasswordUnlock"]).ok_or_else(malformed)?;
        let auth_kdf = pick(auth, &["kdf", "Kdf"])
            .and_then(kdf_of)
            .ok_or_else(malformed)?;
        let unlock_kdf = pick(unlock, &["kdf", "Kdf"])
            .and_then(kdf_of)
            .ok_or_else(malformed)?;
        let normalized = email.trim().to_lowercase();
        let auth_salt = text(auth, &["salt", "Salt"]).ok_or_else(malformed)?;
        let unlock_salt = text(unlock, &["salt", "Salt"]).ok_or_else(malformed)?;
        if auth_kdf != unlock_kdf || auth_salt != normalized || unlock_salt != normalized {
            return Err(BwError::status(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unexpected RegisterData format",
            ));
        }
        (
            text(
                auth,
                &[
                    "masterPasswordAuthenticationHash",
                    "MasterPasswordAuthenticationHash",
                    "hash",
                ],
            )
            .ok_or_else(malformed)?,
            auth_kdf,
            text(unlock, &["masterKeyWrappedUserKey", "key"]).ok_or_else(malformed)?,
        )
    } else {
        (
            text(body, &["masterPasswordHash"]).ok_or_else(malformed)?,
            kdf_of(body).ok_or_else(malformed)?,
            text(body, &["userSymmetricKey", "key"]).ok_or_else(malformed)?,
        )
    };
    let keys = pick(body, &["userAsymmetricKeys", "keys"])
        .and_then(|k| Some((text(k, &["encryptedPrivateKey"])?, text(k, &["publicKey"])?)));
    Ok(Registration {
        email,
        hash,
        kdf,
        key,
        keys,
        hint: text(body, &["masterPasswordHint"]),
        verification_token: text(body, &["emailVerificationToken"]),
        invite_token: text(body, &["inviteToken"]),
    })
}

const REGISTRATION_REFUSED: &str = "Registration not allowed or user already exists";

/// A server invitation that let an address register: consumed once its account exists.
struct Invitation {
    gate: Arc<dyn InviteGate>,
    ticket: InviteTicket,
}

impl Invitation {
    async fn consume(self) {
        if let Err(error) = self.gate.consume(&self.ticket).await {
            tracing::warn!(%error, "couldn't mark an invitation as used");
        }
    }
}

/// Whether an address may register now.
enum Admission {
    Refused,
    /// Sign-ups are on for it, or an organization invited it.
    Open,
    /// A server invitation token let it in.
    Invited(Invitation),
}

/// Whether `email` may register now. Sign-ups on, an organization's invitation, or a good server
/// invitation token each let an address in; a token that isn't good counts as no token.
async fn admit<S: BwStore>(app: &App<S>, email: &str, token: Option<&str>) -> BwResult<Admission> {
    if let (Some(token), Some(gate), Ok(parsed)) =
        (token, app.settings.invites(), Email::parse(email))
    {
        match gate.accept(token, &parsed).await {
            Ok(ticket) => return Ok(Admission::Invited(Invitation { gate, ticket })),
            Err(AppError::Forbidden) => {}
            Err(e) => return Err(BwError::Server(e.to_string())),
        }
    }
    // Sign-ups closed still let an address that an organization invited register.
    if app.settings.signups_open_for(email)
        || app.has_invitation(&email.trim().to_lowercase()).await?
    {
        return Ok(Admission::Open);
    }
    Ok(Admission::Refused)
}

/// `POST /identity/accounts/register/send-verification-email`: with no mail to send, the token
/// goes straight back and the client uses it to finish.
pub(crate) async fn verification_token<S: BwStore>(
    app: &App<S>,
    email: &str,
    name: Option<String>,
    invite_token: Option<&str>,
) -> BwResult<String> {
    if matches!(admit(app, email, invite_token).await?, Admission::Refused) {
        return Err(BwError::msg(REGISTRATION_REFUSED));
    }
    let now = app.now_secs();
    let claims = RegisterVerifyClaims {
        nbf: now,
        exp: now + 30 * 60,
        iss: app.settings.issuer("register_verify"),
        sub: email.to_owned(),
        name,
        verified: false,
    };
    app.keys
        .encode(&claims)
        .map_err(|e| BwError::Server(e.to_string()))
}

/// Whether `emailVerificationToken` is a verified token for `email` and the account doesn't exist.
pub(crate) async fn verification_clicked<S: BwStore>(
    app: &App<S>,
    email: &str,
    token: &str,
) -> BwResult<()> {
    let valid = app
        .keys
        .decode::<RegisterVerifyClaims>(
            token,
            &app.settings.issuer("register_verify"),
            app.now_secs(),
        )
        .is_ok_and(|c| c.verified && c.sub.eq_ignore_ascii_case(email));
    let exists = match Email::parse(email) {
        Ok(parsed) => UserRepo::by_email(&app.store, &parsed).await?.is_some(),
        Err(_) => false,
    };
    if !valid || exists {
        return Err(BwError::msg(
            "Expired link. Please restart registration or try logging in. You may already have an account",
        ));
    }
    Ok(())
}

/// `POST /identity/accounts/register/finish`: makes a Compatible account.
pub(crate) async fn register<S: BwStore>(app: &App<S>, request: Registration) -> BwResult<()> {
    let Some(token) = &request.verification_token else {
        return Err(BwError::msg("Registration is missing required parameters"));
    };
    let claims: RegisterVerifyClaims = app
        .keys
        .decode(
            token,
            &app.settings.issuer("register_verify"),
            app.now_secs(),
        )
        .map_err(|e| BwError::msg(e.to_string()))?;
    if claims.sub != request.email {
        return Err(BwError::msg(
            "Email verification token does not match email",
        ));
    }
    let name = claims.name;
    if name.as_ref().is_some_and(|n| n.len() > 50) {
        return Err(BwError::msg(
            "The field Name must be a string with a maximum length of 50.",
        ));
    }
    let admission = admit(app, &request.email, request.invite_token.as_deref()).await?;
    if matches!(admission, Admission::Refused) {
        return Err(BwError::msg(REGISTRATION_REFUSED));
    }
    let kdf = request.kdf.checked()?;
    let email = Email::parse(&request.email).map_err(|_| {
        BwError::msg(format!(
            "User email {} is not a valid email address",
            request.email.escape_debug()
        ))
    })?;

    let now = app.now();
    let user = User {
        id: kemlock_domain::UserId(random_uuid(app.env.as_ref())),
        email: email.clone(),
        name: Some(name.unwrap_or_else(|| email.as_str().to_owned())),
        mode: AccountMode::Compatible,
        role: Role::User,
        // The Kemlock side of the account is empty until its owner enrols OPAQUE.
        kdf: KdfParams::new_account(random_bytes::<16>(app.env.as_ref())),
        opaque_record: None,
        wrapped_root_key: Vec::new(),
        public_bundle: Vec::new(),
        bundle_signature: Vec::new(),
        sealed_private_keys: Vec::new(),
        key_version: 0,
        security_stamp: random_uuid(app.env.as_ref()),
        created_at: now,
        updated_at: now,
    };
    match UserRepo::insert(&app.store, &user).await {
        Ok(()) => {}
        Err(StoreError::Duplicate) => return Err(BwError::msg(REGISTRATION_REFUSED)),
        Err(e) => return Err(e.into()),
    }

    let salt = random_bytes::<64>(app.env.as_ref()).to_vec();
    let iterations = app.settings.password_iterations;
    let account = BwAccount {
        user: user.id,
        password_hash: hash_password(request.hash.as_bytes(), &salt, iterations),
        salt,
        password_iterations: iterations,
        kdf_type: kdf.kind,
        kdf_iterations: kdf.iterations,
        kdf_memory: kdf.memory,
        kdf_parallelism: kdf.parallelism,
        akey: request.key,
        private_key: request.keys.as_ref().map(|k| k.0.clone()),
        public_key: request.keys.map(|k| k.1),
        password_hint: request
            .hint
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty()),
        api_key: None,
        avatar_color: None,
        revision_ms: epoch_millis(now),
    };
    BwAccountRepo::insert(&app.store, &account).await?;
    // Invitations to this address become memberships.
    app.adopt_invitations(&user).await?;
    if let Admission::Invited(invitation) = admission {
        invitation.consume().await;
    }
    Ok(())
}

/// `POST /api/accounts/api-key` and `rotate-api-key`: the personal API key, made on first ask. The
/// caller has checked the password or code.
pub(crate) async fn api_key<S: BwStore>(
    app: &App<S>,
    account: &BwAccount,
    rotate: bool,
) -> BwResult<Value> {
    let mut account = account.clone();
    if rotate || account.api_key.is_none() {
        account.api_key = Some(random_alphanumeric(app.env.as_ref(), 30));
        BwAccountRepo::update(&app.store, &account).await?;
        app.touch(account.user).await?;
        account = BwAccountRepo::get(&app.store, account.user)
            .await?
            .ok_or(BwError::NotFound)?;
    }
    let revision = time::OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(account.revision_ms) * 1_000_000,
    )
    .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    Ok(json!({
        "apiKey": account.api_key,
        "revisionDate": format_date(revision),
        "object": "apiKey",
    }))
}

/// `DELETE /api/accounts` and `POST /api/accounts/delete`: erases the account that asks, its vault,
/// attachments, Sends, devices and the rest, at once, as Vaultwarden's `User::delete` does (the
/// grace period of a deleted account is the Kemlock API's, not this one's). The caller has checked
/// the password or code.
///
/// As `User::delete` has it, the last confirmed owner of any organization is refused with
/// "Can't delete last owner", even when no one else is in it, and nothing is touched.
pub(crate) async fn delete_account<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<()> {
    let Some(erasure) = app.erasure.as_ref() else {
        return Err(BwError::msg(
            "Deleting an account is not available on this server",
        ));
    };
    for member in SpaceRepo::memberships(&app.store, user).await? {
        if !member.is_confirmed() || member.role != SpaceRole::Owner {
            continue;
        }
        let owners = SpaceRepo::load(&app.store, member.space)
            .await?
            .map_or(0, |state| {
                state
                    .members
                    .iter()
                    .filter(|m| m.is_confirmed() && m.role == SpaceRole::Owner)
                    .count()
            });
        if owners <= 1 {
            return Err(BwError::msg("Can't delete last owner"));
        }
    }
    erasure
        .erase_own_now(user)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            AppError::Invalid(_) => BwError::msg("Can't delete last owner"),
            other => crate::two_step::failed(other),
        })
}

/// `{"object":"masterPasswordPolicy"}`, which Vaultwarden's identity answers carry with
/// PascalCase keys (no policies exist, so it is only the `Object`).
pub(crate) fn identity_master_password_policy() -> Value {
    json!({"Object": "masterPasswordPolicy"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_settings_are_checked_with_vaultwardens_messages() {
        let pbkdf2 = |iterations| Kdf {
            kind: PBKDF2,
            iterations,
            memory: Some(64),
            parallelism: Some(4),
        };
        assert_eq!(
            pbkdf2(99_999).checked(),
            Err(BwError::msg(
                "PBKDF2 KDF iterations must be at least 100000."
            ))
        );
        let ok = pbkdf2(600_000).checked().expect("valid");
        assert_eq!(
            (ok.memory, ok.parallelism),
            (None, None),
            "PBKDF2 has neither"
        );

        let argon = |iterations, memory, parallelism| Kdf {
            kind: ARGON2ID,
            iterations,
            memory,
            parallelism,
        };
        assert!(argon(3, Some(64), Some(4)).checked().is_ok());
        assert!(argon(1, Some(15), Some(1)).checked().is_ok());
        assert!(argon(3, Some(1024), Some(16)).checked().is_ok());
        for (bad, message) in [
            (
                argon(0, Some(64), Some(4)),
                "Argon2 KDF iterations must be at least 1.",
            ),
            (
                argon(3, Some(14), Some(4)),
                "Argon2 memory must be between 15 MB and 1024 MB.",
            ),
            (
                argon(3, Some(1025), Some(4)),
                "Argon2 memory must be between 15 MB and 1024 MB.",
            ),
            (
                argon(3, None, Some(4)),
                "Argon2 memory parameter is required.",
            ),
            (
                argon(3, Some(64), Some(17)),
                "Argon2 parallelism must be between 1 and 16.",
            ),
            (
                argon(3, Some(64), None),
                "Argon2 parallelism parameter is required.",
            ),
        ] {
            assert_eq!(bad.checked(), Err(BwError::msg(message)));
        }
    }

    #[test]
    fn the_flat_registration_shape_parses() {
        let body = json!({
            "email": "Ada@Example.com",
            "masterPasswordHash": "hash",
            "masterPasswordHint": "a hint",
            "kdf": 0, "kdfIterations": 600000,
            "userSymmetricKey": "2.key",
            "keys": {"encryptedPrivateKey": "2.priv", "publicKey": "pub"},
            "emailVerificationToken": "tok"
        });
        let r = parse_registration(&body).expect("parses");
        assert_eq!(r.email, "Ada@Example.com");
        assert_eq!(r.hash, "hash");
        assert_eq!(r.kdf.iterations, 600_000);
        assert_eq!(r.key, "2.key");
        assert_eq!(r.keys, Some(("2.priv".to_owned(), "pub".to_owned())));
        assert_eq!(r.hint.as_deref(), Some("a hint"));
        assert_eq!(r.verification_token.as_deref(), Some("tok"));
    }

    #[test]
    fn the_current_registration_shape_parses_and_is_checked() {
        let body = |salt: &str, iterations: i64| {
            json!({
                "email": "ada@example.com",
                "emailVerificationToken": "tok",
                "masterPasswordAuthentication": {
                    "kdf": {"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4},
                    "salt": salt,
                    "masterPasswordAuthenticationHash": "hash"
                },
                "masterPasswordUnlock": {
                    "kdf": {"kdfType": 1, "iterations": iterations, "memory": 64, "parallelism": 4},
                    "salt": "ada@example.com",
                    "masterKeyWrappedUserKey": "2.key"
                },
                "userAsymmetricKeys": {"encryptedPrivateKey": "2.priv", "publicKey": "pub"}
            })
        };
        let r = parse_registration(&body("ada@example.com", 3)).expect("parses");
        assert_eq!(
            r.kdf,
            Kdf {
                kind: 1,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4)
            }
        );
        assert_eq!(r.hash, "hash");
        assert_eq!(r.key, "2.key");
        assert!(r.keys.is_some());
        for bad in [body("other@example.com", 3), body("ada@example.com", 4)] {
            let Err(BwError::Status(code, _)) = parse_registration(&bad) else {
                panic!("a 422");
            };
            assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[test]
    fn a_registration_without_its_parts_is_a_422() {
        for body in [
            json!({}),
            json!({"email": "a@b.co"}),
            json!({"email": "a@b.co", "masterPasswordHash": "h"}),
        ] {
            assert!(matches!(
                parse_registration(&body),
                Err(BwError::Status(StatusCode::UNPROCESSABLE_ENTITY, _))
            ));
        }
    }
}
