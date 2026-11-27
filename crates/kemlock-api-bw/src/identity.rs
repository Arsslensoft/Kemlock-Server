// Partly ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/api/identity.rs (login, as the grant dispatch in token(); check_is_some).
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! `/identity/connect/token`: the password, refresh-token and API-key grants, and the second step.
//!
//! Vaultwarden's answers, quirks included: any non-empty `client_id`, the device type from the
//! body or the `Device-Type` header, a 400 with `TwoFactorProviders` and `TwoFactorProviders2` for
//! the second step, no new-device challenge, and an API-key grant that gets no refresh token.

use crate::account::{identity_master_password_policy, kdf_upgrade, user_name};
use crate::app::{App, BwStore};
use crate::env::{random_bytes, random_uuid};
use crate::error::{BwError, BwResult};
use crate::tokens::{LoginClaims, RememberClaims};
use crate::webauthn::SealRef;
use kemlock_app::b64url;
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo, BwTryRepo};
use kemlock_app::bw_events::BwDeviceRepo;
use kemlock_app::devices::{NewDeviceNotice, bitwarden_device_id};
use kemlock_app::error::AppError;
use kemlock_app::notices::{Notice, TwoStepRecoveredNotice};
use kemlock_app::ports::{
    DeviceRepo, Event, EventLog, RefreshToken, TokenRepo, TwoFactorMethod, TwoFactorRepo, UserRepo,
};
use kemlock_app::privacy::{NewSignIn, record_sign_in};
use kemlock_app::sealed::{PURPOSE_TOTP, open_bound};
use kemlock_app::second_step_guard::{Reservation, SecondStepGuard};
use kemlock_app::sso::{RequireSso, SignInMethod, SsoError};
use kemlock_app::two_step::{method_of_provider, provider_type};
use kemlock_crypto::{hash, totp};
use kemlock_domain::privacy::SignInOutcome;
use kemlock_domain::unlock::truncate_ip;
use kemlock_domain::{Device, DeviceId, DeviceKind, Email, User, UserId};
use serde_json::{Map, Value, json};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Access tokens live two hours.
const ACCESS_TTL: Duration = Duration::hours(2);
/// Refresh tokens live 30 days, or 90 on a phone.
const REFRESH_TTL: Duration = Duration::days(30);
const MOBILE_REFRESH_TTL: Duration = Duration::days(90);
/// A refresh token used again within this long is a retry after a lost answer, not a theft.
const REFRESH_GRACE: Duration = Duration::seconds(60);
/// A "remember this device" token lasts 30 days.
const REMEMBER_TTL: Duration = Duration::days(30);

const PASSWORD_SCOPE: &str = "api offline_access";
const API_KEY_SCOPE: &str = "api";
const BAD_LOGIN: &str = "Username or password is incorrect. Try again";
/// What Vaultwarden says to a user it has disabled.
const DISABLED: &str = "This user has been disabled";
/// What it says to one whose API key is right.
const DISABLED_API_KEY: &str = "This user has been disabled (API key login)";
/// What it says to one who deleted the account and is in the grace period before its erasure. An
/// admin can cancel the deletion; signing in does not.
const BEING_DELETED: &str = "This user is being deleted";

/// The form of a token request. Names are read without regard to case, with or without
/// underscores: `grant_type`, `grantType` and `granttype` are one.
#[derive(Debug, Default)]
pub(crate) struct ConnectData {
    pub grant_type: String,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub password: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub device_identifier: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub two_factor_provider: Option<i32>,
    pub two_factor_token: Option<String>,
    pub two_factor_remember: Option<i32>,
    pub auth_request: Option<String>,
    /// `send_access`: the access id of the Send and, for a password-protected one, the hash.
    pub send_id: Option<String>,
    pub password_hash_b64: Option<String>,
}

impl ConnectData {
    /// Parses an `application/x-www-form-urlencoded` body; `None` when `grant_type` is missing or a
    /// number isn't one (Rocket answers those 422).
    pub(crate) fn from_form(body: &[u8]) -> Option<Self> {
        let mut data = ConnectData::default();
        let mut have_grant = false;
        for (key, value) in url::form_urlencoded::parse(body) {
            let name: String = key
                .chars()
                .filter(|c| *c != '_')
                .map(|c| c.to_ascii_lowercase())
                .collect();
            let value = value.into_owned();
            match name.as_str() {
                "granttype" => {
                    data.grant_type = value;
                    have_grant = true;
                }
                "refreshtoken" => data.refresh_token = Some(value),
                "clientid" => data.client_id = Some(value),
                "clientsecret" => data.client_secret = Some(value),
                "password" => data.password = Some(value),
                "scope" => data.scope = Some(value),
                "username" => data.username = Some(value),
                "deviceidentifier" => data.device_identifier = Some(value),
                "devicename" => data.device_name = Some(value),
                "devicetype" => data.device_type = Some(value),
                "twofactorprovider" => data.two_factor_provider = Some(value.parse().ok()?),
                "twofactortoken" => data.two_factor_token = Some(value),
                "twofactorremember" => data.two_factor_remember = Some(value.parse().ok()?),
                "authrequest" => data.auth_request = Some(value),
                "sendid" => data.send_id = Some(value),
                "passwordhashb64" => data.password_hash_b64 = Some(value),
                _ => {}
            }
        }
        have_grant.then_some(data)
    }
}

fn check_is_some(value: Option<&String>, message: &str) -> BwResult<()> {
    if value.is_none() {
        return Err(BwError::msg(message));
    }
    Ok(())
}

/// The name Bitwarden gives a device type, which goes into the token's `devicetype`.
pub(crate) fn device_type_name(device_type: i32) -> &'static str {
    match device_type {
        0 | 15 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        26 => "DuckDuckGo",
        _ => "Unknown Browser",
    }
}

/// What the Devices screen shows: Amethystora Vault and the Kemlock app by their device names,
/// everything else as a Bitwarden app.
fn device_kind(name: &str, device_type: i32) -> DeviceKind {
    let lower = name.trim().to_ascii_lowercase();
    if lower.starts_with("amethystora") {
        DeviceKind::Amethystora
    } else if lower.starts_with("kemlock") {
        match device_type {
            0 | 15 => DeviceKind::KemlockAndroid,
            1 => DeviceKind::KemlockIos,
            23..=25 => DeviceKind::KemlockCli,
            _ => DeviceKind::KemlockWeb,
        }
    } else {
        DeviceKind::Bitwarden
    }
}

/// The id of the device a client calls `identifier` on this account. It is made from both, so
/// one phone signed in to two accounts, which sends the same identifier for both, is two devices.
pub(crate) fn device_id_for(user: UserId, identifier: &str) -> DeviceId {
    bitwarden_device_id(hash::sha256, user, identifier)
}

/// The second step's 400: `TwoFactorProviders` lists the usable providers and
/// `TwoFactorProviders2` maps each to its options: none for an authenticator app (`null`), the
/// request options of `navigator.credentials.get` for a security key.
fn two_factor_response(providers: &[i32], options: Map<String, Value>) -> BwError {
    BwError::Json(json!({
        "error": "invalid_grant",
        "error_description": "Two factor required.",
        "TwoFactorProviders": providers.iter().map(ToString::to_string).collect::<Vec<String>>(),
        "TwoFactorProviders2": options,
        "MasterPasswordPolicy": identity_master_password_policy(),
    }))
}

/// The second step's 400 for providers that need no options.
fn two_factor_required(providers: &[i32]) -> BwError {
    let mut options = Map::new();
    for provider in providers {
        options.insert(provider.to_string(), Value::Null);
    }
    two_factor_response(providers, options)
}

fn invalid_grant() -> BwError {
    BwError::Json(json!({"error": "invalid_grant"}))
}

/// `account_keys` of the token answer: PascalCase `Object`, no signed key or state.
fn token_account_keys(account: &BwAccount) -> Value {
    if account.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": account.private_key,
                "publicKey": account.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        })
    } else {
        Value::Null
    }
}

fn user_decryption_options(user: &User, account: &BwAccount) -> Value {
    let has_password = !account.password_hash.is_empty();
    let unlock = if has_password {
        json!({
            "Kdf": {
                "KdfType": account.kdf_type,
                "Iterations": account.kdf_iterations,
                "Memory": account.kdf_memory,
                "Parallelism": account.kdf_parallelism
            },
            "MasterKeyEncryptedUserKey": account.akey,
            "MasterKeyWrappedUserKey": account.akey,
            "Salt": user.email.as_str()
        })
    } else {
        Value::Null
    };
    json!({
        "HasMasterPassword": has_password,
        "MasterPasswordUnlock": unlock,
        "Object": "userDecryptionOptions"
    })
}

pub(crate) fn time_of_day(t: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// What Vaultwarden says when an emailed code, a YubiKey or Duo doesn't check out.
fn login_refused(method: TwoFactorMethod, error: AppError, caller: &Caller) -> BwError {
    match error {
        AppError::Unauthorized => BwError::msg(match method {
            TwoFactorMethod::Email => format!("Token is invalid! IP: {}", caller.ip),
            TwoFactorMethod::YubiKey => "Failed to verify Yubikey against OTP server".to_owned(),
            _ => "Error validating duo authentication".to_owned(),
        }),
        other => crate::two_step::failed(other),
    }
}

/// Everything one sign-in needs to know about the request that isn't the form.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// The `Device-Type` header, used when the body has no `device_type`.
    pub device_type_header: Option<String>,
    pub ip: IpAddr,
}

/// What a token request found out about itself, for the sign-in log.
#[derive(Debug, Default)]
struct Attempt {
    /// Credentials were being checked. A request refused before that (a blank field, a scope this
    /// server doesn't know) is not a sign-in attempt.
    checked: bool,
    /// The secret was right (the password, or the API key): what fails after it is not the secret.
    proved: bool,
    /// The second step was being checked.
    second_step: bool,
    /// The account and device, once known. A wrong secret proves nothing about who asked, so the
    /// account is set only after the secret was right.
    user: Option<UserId>,
    device: Option<DeviceId>,
}

/// Whether an error is the 400 that asks the client for its second step.
fn is_two_factor_prompt(error: &BwError) -> bool {
    matches!(
        error,
        BwError::Json(body)
            if body.get("error_description").and_then(Value::as_str) == Some("Two factor required.")
    )
}

/// The sign-in log row for a token request, or `None` when it was no attempt. A password that is
/// right but owes a second step is a `password` success; the second step is its own `two-factor`
/// row, success or failure. A store failure is not an attempt.
fn attempt_entry(
    method: &'static str,
    second_step_code: bool,
    attempt: &Attempt,
    result: &BwResult<Value>,
    at: OffsetDateTime,
    ip: IpAddr,
) -> Option<NewSignIn> {
    if !attempt.checked {
        return None;
    }
    let (method, outcome) = match result {
        Ok(_) if second_step_code => ("two-factor", SignInOutcome::Success),
        Ok(_) => (method, SignInOutcome::Success),
        Err(BwError::Server(_)) => return None,
        Err(error) if attempt.proved && is_two_factor_prompt(error) => {
            (method, SignInOutcome::Success)
        }
        Err(_) if attempt.second_step => ("two-factor", SignInOutcome::Failure),
        Err(_) => (method, SignInOutcome::Failure),
    };
    Some(NewSignIn {
        user: attempt.user,
        device: attempt.device,
        method,
        outcome,
        at,
        ip: Some(ip),
    })
}

/// Writes the sign-in log row of a token request. The request has been answered, so a log failure
/// is only logged.
async fn log_attempt<S: BwStore>(
    app: &App<S>,
    method: &'static str,
    second_step_code: bool,
    attempt: &Attempt,
    result: &BwResult<Value>,
    ip: IpAddr,
) {
    let entry = attempt_entry(method, second_step_code, attempt, result, app.now(), ip);
    record_sign_in(&app.store, entry).await;
}

impl<S: BwStore> App<S> {
    /// What the recovery code's use leaves behind: an event in the activity log, Vaultwarden's
    /// `UserRecovered2fa` for the clients, and a mail to the owner. None can fail the sign-in: the
    /// code is spent and the methods are gone already.
    async fn recovered(
        &self,
        user: &User,
        data: &ConnectData,
        caller: &Caller,
        at: OffsetDateTime,
    ) {
        let event = Event {
            actor: Some(user.id),
            device: None,
            action: "auth.two_step_recovered",
            target: None,
            at,
        };
        if let Err(e) = EventLog::record(&self.store, event).await {
            tracing::warn!(error = %e, "couldn't record that the recovery code was used");
        }
        let acting = crate::events::Acting {
            user: user.id,
            device_type: requested_device_type(data, caller),
            ip: caller.ip,
        };
        crate::events::log_user_event(self, crate::events::kind::USER_RECOVERED_2FA, &acting).await;
        self.notices
            .send(Notice::TwoStepRecovered(TwoStepRecoveredNotice {
                to: user.email.clone(),
                at,
            }))
            .await;
    }

    /// The second step's 400, with what each provider needs to be answered: the request options a
    /// security key (7) is asked to answer (a new challenge each time, which replaces the one
    /// before it), the hidden address of an email (1), the address of Duo's prompt (2) and
    /// whether a YubiKey reads over NFC (3).
    async fn two_factor_challenge(
        &self,
        user: &User,
        usable: &[i32],
        data: &ConnectData,
    ) -> BwResult<BwError> {
        if usable.iter().all(|p| *p == 0) {
            return Ok(two_factor_required(usable));
        }
        let steps = crate::two_step::steps(self);
        let client = data.client_id.as_deref().unwrap_or_default();
        let device = data.device_identifier.as_deref().unwrap_or_default();
        let mut options = Map::new();
        for provider in usable {
            let value = match method_of_provider(*provider) {
                Some(TwoFactorMethod::WebAuthn) => {
                    crate::webauthn::login_options(self, user.id).await?
                }
                Some(
                    method @ (TwoFactorMethod::Email
                    | TwoFactorMethod::YubiKey
                    | TwoFactorMethod::Duo),
                ) => steps
                    .login_options(user, method, client, device)
                    .await
                    .map_err(crate::two_step::failed)?,
                _ => Value::Null,
            };
            options.insert(provider.to_string(), value);
        }
        Ok(two_factor_response(usable, options))
    }

    /// The signed access token and its claims' scope, for `device` and `client_id`.
    fn access_token(
        &self,
        user: &User,
        device: &Device,
        device_type: i32,
        identifier: Option<Uuid>,
        client_id: Option<String>,
        scope: &str,
    ) -> BwResult<String> {
        let now = self.now_secs();
        let claims = LoginClaims {
            nbf: now,
            exp: now + ACCESS_TTL.whole_seconds(),
            iss: self.settings.issuer("login"),
            sub: user.id.to_string(),
            premium: true,
            name: user_name(user),
            email: user.email.as_str().to_owned(),
            email_verified: true,
            sstamp: user.security_stamp.to_string(),
            device: device.id.to_string(),
            devicetype: device_type_name(device_type).to_owned(),
            client_id: client_id.unwrap_or_else(|| "undefined".to_owned()),
            scope: scope.split_whitespace().map(str::to_owned).collect(),
            amr: vec!["Application".to_owned()],
            appid: identifier.map(|id| id.to_string()),
        };
        self.keys
            .encode(&claims)
            .map_err(|e| BwError::Server(e.to_string()))
    }

    /// Stores a new refresh token and returns its text.
    async fn new_refresh_token(
        &self,
        user: UserId,
        device: DeviceId,
        family: Option<Uuid>,
        ttl: Duration,
    ) -> BwResult<String> {
        let now = self.now();
        let raw = random_bytes::<32>(self.env.as_ref());
        // Bound to the account's stamp, so a password change or key replacement ends it.
        let security_stamp = UserRepo::by_id(&self.store, user)
            .await?
            .map_or(Uuid::nil(), |u| u.security_stamp);
        TokenRepo::insert(
            &self.store,
            &RefreshToken {
                security_stamp,
                hash: hash::sha256(&raw),
                family: family.unwrap_or_else(|| random_uuid(self.env.as_ref())),
                user,
                device,
                created_at: now,
                expires_at: now + ttl,
                used_at: None,
            },
        )
        .await?;
        Ok(b64url::encode(&raw))
    }

    /// Keeps the identifier and device type the app signs in with, and returns the identifier for
    /// the token. An identifier that is not a UUID is not kept: its changes then name no device.
    async fn note_device(
        &self,
        device: &Device,
        identifier: &str,
        device_type: i32,
    ) -> Option<Uuid> {
        let identifier = Uuid::parse_str(identifier.trim()).ok()?;
        if let Err(error) = BwDeviceRepo::note_bw_device(
            &self.store,
            device.id,
            device.user,
            identifier,
            device_type,
            self.now(),
        )
        .await
        {
            tracing::warn!(%error, "could not record a device's identifier");
        }
        Some(identifier)
    }

    /// Finds the device this client is, or makes it; nothing is stored until the sign-in is done.
    async fn device_for(
        &self,
        user: UserId,
        identifier: &str,
        name: &str,
        device_type: i32,
    ) -> BwResult<(Device, bool)> {
        let id = device_id_for(user, identifier);
        let now = self.now();
        let known = DeviceRepo::get(&self.store, id)
            .await?
            .filter(|known| known.user == user);
        let is_new = known.is_none();
        let device = match known {
            Some(known) => Device {
                name: Device::clean_name(name),
                kind: device_kind(name, device_type),
                last_seen_at: now,
                ..known
            },
            None => Device {
                id,
                user,
                name: Device::clean_name(name),
                kind: device_kind(name, device_type),
                dpop_jkt: None,
                created_at: now,
                last_seen_at: now,
            },
        };
        Ok((device, is_new))
    }

    /// Mails the account that a device signed in that it had not used before, as Vaultwarden does
    /// when mail is set up. With `REQUIRE_DEVICE_EMAIL` a mail that can't be sent refuses the
    /// sign-in.
    async fn announce_new_device(&self, user: &User, device: &Device, ip: IpAddr) -> BwResult<()> {
        if !self.notices.mails() {
            return Ok(());
        }
        let notice = NewDeviceNotice {
            to: user.email.clone(),
            device_name: device.name.clone(),
            device_kind: device.kind,
            ip: truncate_ip(ip),
            at: self.now(),
        };
        match self.notices.send_checked(Notice::NewDevice(notice)).await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::error!(%error, "couldn't send the new-device mail");
                if self.require_device_email {
                    Err(BwError::msg(
                        "Could not send login notification email. Please contact your administrator.",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The second step. Returns a "remember this device" token when the client asked for one.
    async fn second_step(
        &self,
        user: &User,
        device: &Device,
        data: &ConnectData,
        caller: &Caller,
    ) -> BwResult<Option<String>> {
        let factors = TwoFactorRepo::list(&self.store, user.id).await?;
        if factors.is_empty() {
            return Ok(None);
        }
        // What this server can answer: an authenticator app (0), an emailed code (1) when it can
        // mail, Duo (2) and a YubiKey (3) when their services are set up, and a security key (7)
        // when a WebAuthn relying party is configured. The recovery code (8) is never listed, as in
        // Vaultwarden, but is taken whatever the list says (below).
        let steps = crate::two_step::steps(self);
        let mut usable: Vec<i32> = factors
            .iter()
            .filter(|f| match f.method {
                TwoFactorMethod::WebAuthn => f.enabled && self.webauthn.is_some(),
                _ => steps.usable(f),
            })
            .map(|f| provider_type(f.method))
            .collect();
        usable.sort_unstable();
        let Some(first) = usable.first().copied() else {
            return Err(BwError::msg(
                "No enabled and usable two factor providers are available for this account",
            ));
        };
        let selected = data.two_factor_provider.unwrap_or(first);
        if ![5, 8].contains(&selected) && !usable.contains(&selected) {
            return Err(self.two_factor_challenge(user, &usable, data).await?);
        }
        let Some(code) = data
            .two_factor_token
            .as_deref()
            .filter(|t| !t.trim().is_empty())
        else {
            return Err(self.two_factor_challenge(user, &usable, data).await?);
        };

        // The try is reserved before the code is looked at, so tries that arrive together each
        // count, in the count the Kemlock API's second step keeps for the account (the console's
        // limit, then doubling waits): an account that waits refuses even the right code.
        let reserved = SecondStepGuard::reserve_second_step(
            &self.store,
            user.id,
            self.now().unix_timestamp(),
            self.settings.second_step_limit(),
            TRIES_WINDOW_SECS,
        )
        .await?;
        if let Reservation::Wait(_) = reserved {
            return Err(too_many_logins());
        }

        let now = self.now();
        match selected {
            0 => {
                if !code.chars().all(char::is_numeric) {
                    return Err(BwError::msg("TOTP code is not a number"));
                }
                let sealed = factors
                    .iter()
                    .find(|f| f.enabled && f.method == TwoFactorMethod::Totp)
                    .map(|f| f.sealed_secret.as_slice())
                    .ok_or_else(|| BwError::msg("Two factor doesn't exist"))?;
                let secret = open_bound(&SealRef(&self.seal), PURPOSE_TOTP, user.id, sealed)
                    .map_err(|_| BwError::Server("a stored TOTP secret doesn't open".to_owned()))?
                    .value;
                let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
                let refused = || {
                    BwError::msg(format!(
                        "Invalid TOTP code! Server time: {} IP: {}",
                        time_of_day(now),
                        caller.ip
                    ))
                };
                let step = totp::verify_step(&secret, code.trim(), unix).ok_or_else(refused)?;
                // As Vaultwarden's `validate_totp_code` keeps `last_used`: a code whose time
                // step was used already is refused, with the message of a wrong one. The step
                // is kept per enrolment, where the Kemlock API's second step keeps it too.
                if !TwoFactorRepo::accept_totp_step(&self.store, user.id, step).await? {
                    return Err(refused());
                }
            }
            5 => {
                // The token is good for this device and account, and only while the account's
                // methods are as they were when it was made: turning one on or off, the recovery
                // code and an admin's reset all end it (Vaultwarden's `check_2fa_state`).
                let version = TwoFactorRepo::two_step_version(&self.store, user.id).await?;
                let valid = self
                    .keys
                    .decode::<RememberClaims>(
                        code,
                        &self.settings.issuer("2faremember"),
                        now.unix_timestamp(),
                    )
                    .is_ok_and(|c| {
                        c.sub == device.id.to_string()
                            && c.user_uuid == user.id.to_string()
                            && c.two_step_version == version
                    });
                if !valid {
                    return Err(self.two_factor_challenge(user, &usable, data).await?);
                }
            }
            7 => crate::webauthn::validate_login(self, user.id, code).await?,
            8 => {
                // Vaultwarden's `RecoveryCode` arm: the code ignores spaces and case, and
                // switches every second step off. The code is spent with them (the next method
                // the account turns on makes a new one).
                crate::two_step::recovery_codes(self)
                    .recover(user.id, code)
                    .await
                    .map_err(|e| match e {
                        AppError::Unauthorized => {
                            BwError::msg("Two-step token is invalid. Try again.")
                        }
                        other => crate::two_step::failed(other),
                    })?;
                self.recovered(user, data, caller, now).await;
            }
            1..=3 => {
                let method = method_of_provider(selected)
                    .ok_or_else(|| BwError::msg("Invalid two factor provider"))?;
                steps
                    .verify_login(
                        user,
                        method,
                        code,
                        data.client_id.as_deref().unwrap_or_default(),
                        data.device_identifier.as_deref().unwrap_or_default(),
                    )
                    .await
                    .map_err(|e| login_refused(method, e, caller))?;
            }
            _ => return Err(BwError::msg("Invalid two factor provider")),
        }
        if let Err(error) = SecondStepGuard::clear_second_step(&self.store, user.id).await {
            tracing::warn!(%error, "couldn't clear an account's second-step attempts");
        }

        if data.two_factor_remember.unwrap_or(0) == 1 {
            let at = now.unix_timestamp();
            let claims = RememberClaims {
                nbf: at,
                exp: at + REMEMBER_TTL.whole_seconds(),
                iss: self.settings.issuer("2faremember"),
                sub: device.id.to_string(),
                user_uuid: user.id.to_string(),
                two_step_version: TwoFactorRepo::two_step_version(&self.store, user.id).await?,
            };
            let token = self
                .keys
                .encode(&claims)
                .map_err(|e| BwError::Server(e.to_string()))?;
            return Ok(Some(token));
        }
        Ok(None)
    }
}

/// `POST /identity/connect/token`.
pub(crate) async fn token<S: BwStore>(
    app: &App<S>,
    data: ConnectData,
    caller: Caller,
) -> BwResult<Value> {
    match data.grant_type.as_str() {
        "refresh_token" => {
            check_is_some(data.refresh_token.as_ref(), "refresh_token cannot be blank")?;
            let mut attempt = Attempt::default();
            let result = refresh_login(app, &data, &mut attempt).await;
            log_attempt(app, "refresh", false, &attempt, &result, caller.ip).await;
            result
        }
        "password" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.password.as_ref(), "password cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;
            check_is_some(data.username.as_ref(), "username cannot be blank")?;
            check_is_some(
                data.device_identifier.as_ref(),
                "device_identifier cannot be blank",
            )?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(
                data.device_type
                    .as_ref()
                    .or(caller.device_type_header.as_ref()),
                "device_type cannot be blank",
            )?;
            let second_step_code = data
                .two_factor_token
                .as_deref()
                .is_some_and(|t| !t.trim().is_empty());
            let mut attempt = Attempt::default();
            let result = password_login(app, data, &caller, &mut attempt).await;
            log_attempt(
                app,
                "password",
                second_step_code,
                &attempt,
                &result,
                caller.ip,
            )
            .await;
            result
        }
        "client_credentials" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.client_secret.as_ref(), "client_secret cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;
            let mut attempt = Attempt::default();
            let result = api_key_login(app, data, &caller, &mut attempt).await;
            log_attempt(app, "api-key", false, &attempt, &result, caller.ip).await;
            result
        }
        _ => Err(BwError::msg("Invalid type")),
    }
}

/// The device type a request names: the body's, else the header's, else "Unknown Browser" (14).
fn requested_device_type(data: &ConnectData, caller: &Caller) -> i32 {
    data.device_type
        .as_ref()
        .or(caller.device_type_header.as_ref())
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(14)
}

/// A space that requires SSO closes this way in to its members (owners and admins are exempt).
/// Called after the caller has proved who they are, so the answer never tells a stranger.
async fn require_sso<S: BwStore>(app: &App<S>, user: &User, method: SignInMethod) -> BwResult<()> {
    let sso = RequireSso {
        membership: crate::orgs::OrgMembership(app.store.clone()),
    };
    match sso.check(user, method).await {
        Ok(()) => Ok(()),
        Err(SsoError::SsoRequired { .. }) => Err(BwError::msg(
            "Single sign-on is required for your organization. Sign in with SSO.",
        )),
        Err(other) => Err(BwError::Server(other.to_string())),
    }
}

/// Refuses while the account's erasure is pending (the deleted-account grace period). Called after
/// the credentials checked out, like the disabled check, so it tells nobody about a stranger's account.
async fn refuse_pending_erasure<S: BwStore>(app: &App<S>, user: &User) -> BwResult<()> {
    match UserRepo::erasure_pending(&app.store, user.id).await? {
        Some(_) => Err(BwError::msg(BEING_DELETED)),
        None => Ok(()),
    }
}

async fn account_of<S: BwStore>(app: &App<S>, user: &User) -> BwResult<Option<BwAccount>> {
    Ok(BwAccountRepo::get(&app.store, user.id).await?)
}

/// The mails with a sign-in code an account may ask for in the window.
const EMAIL_LOGIN_KIND: &str = "email-login";
const EMAIL_LOGIN_MAX_TRIES: u32 = 5;
/// The window of the tries an account may have (the one the Kemlock API's second step uses).
const TRIES_WINDOW_SECS: i64 = 15 * 60;

/// The 429 of a limit, in the words of Vaultwarden's own.
fn too_many_logins() -> BwError {
    BwError::status(
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "Too many login requests",
    )
}

/// Vaultwarden's `check_limit_login`, which `password_login` (the second step comes in the same
/// request) and `api_key_login` call once the scope is known: a client address gets
/// `LOGIN_RATELIMIT_MAX_BURST` tries at once and one more every `LOGIN_RATELIMIT_SECONDS`. A refusal
/// is a 429 with `Too many login requests`, in the shape of every `err_code!` answer.
pub(crate) fn check_login_limit<S: BwStore>(app: &App<S>, ip: IpAddr) -> BwResult<()> {
    app.login_limit
        .check(ip, app.now_secs())
        .map_err(|_| too_many_logins())
}

/// The wrong-password tries of an account, kept apart from its second-step tries.
const PASSWORD_KIND: &str = "password";
/// An account refuses every password check once it holds this many times the limit in a window,
/// the right password included, until the window runs out.
const PASSWORD_CAP_FACTOR: u32 = 10;

/// Checks the master password hash of `account` for `user`, counting the try against the account
/// whichever address it comes from (the address limit only stops one source). The try is counted
/// before the hash is looked at, so tries that arrive together each count. Past the account's
/// limit in a window, each try is held back, 1 second then 2 then 3, so guessing costs time and
/// the owner's own right password still gets through; past ten times the limit the account refuses
/// every try until the window ends. A right password clears the count. The hash itself is
/// checked off the async workers, a few at a time (see [`App::hashing`]).
async fn check_password<S: BwStore>(
    app: &App<S>,
    user: &User,
    account: &BwAccount,
    password: &str,
) -> BwResult<()> {
    let limit = app.settings.password_limit();
    let tries = BwTryRepo::count_try(
        &app.store,
        user.id,
        PASSWORD_KIND,
        app.now_secs(),
        TRIES_WINDOW_SECS,
    )
    .await?;
    if tries > limit.saturating_mul(PASSWORD_CAP_FACTOR) {
        return Err(too_many_logins());
    }
    if tries > limit {
        let wait = 1u64 << (tries - limit - 1).min(8);
        tokio::time::sleep(std::time::Duration::from_secs(
            wait.min(app.settings.password_slowdown_secs),
        ))
        .await;
    }
    if !app.password_matches(account, password).await? {
        return Err(BwError::msg(BAD_LOGIN));
    }
    BwTryRepo::forget_tries(&app.store, user.id, PASSWORD_KIND).await?;
    Ok(())
}

async fn password_login<S: BwStore>(
    app: &App<S>,
    data: ConnectData,
    caller: &Caller,
    attempt: &mut Attempt,
) -> BwResult<Value> {
    match data.scope.as_deref() {
        None => return Err(BwError::msg("Missing scope")),
        Some(PASSWORD_SCOPE) => {}
        Some(other) => {
            return Err(BwError::msg(format!(
                "Scope ({}) not supported",
                other.escape_debug()
            )));
        }
    }
    check_login_limit(app, caller.ip)?;

    attempt.checked = true;
    let username = data
        .username
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let user = match Email::parse(&username) {
        Ok(email) => UserRepo::by_email(&app.store, &email).await?,
        Err(_) => None,
    };
    let password = data.password.as_deref().unwrap_or_default();
    let account = match &user {
        Some(user) => account_of(app, user).await?,
        None => None,
    };
    let (Some(user), Some(mut account)) = (user, account) else {
        // The work of a check is done all the same, so the time of the answer does not say whether
        // the address has an account.
        if data.auth_request.is_none() {
            app.password_decoy(password).await?;
        }
        return Err(BwError::msg(BAD_LOGIN));
    };
    // A login approved on another device isn't supported: Kemlock never starts one.
    if data.auth_request.is_some() {
        return Err(BwError::msg("Auth request not found. Try again."));
    }
    check_password(app, &user, &account, password).await?;
    attempt.proved = true;
    attempt.user = Some(user.id);
    // As Vaultwarden does (`_password_login`, identity.rs): the disabled check comes after the
    // password check, so a wrong password is the same answer for a disabled account as for any
    // other, and only whoever holds the password hears the account is disabled.
    if UserRepo::account_disabled(&app.store, user.id).await? {
        return Err(BwError::msg(DISABLED));
    }
    refuse_pending_erasure(app, &user).await?;
    crate::signup_hold::refuse_if_held(app, &user).await?;
    require_sso(app, &user, SignInMethod::Password).await?;
    kdf_upgrade(app, &mut account, password).await?;

    let device_type = requested_device_type(&data, caller);
    let (device, is_new) = app
        .device_for(
            user.id,
            data.device_identifier.as_deref().unwrap_or_default(),
            data.device_name.as_deref().unwrap_or_default(),
            device_type,
        )
        .await?;
    attempt.device = Some(device.id);
    attempt.second_step = true;

    let remember = app.second_step(&user, &device, &data, caller).await?;
    if is_new {
        app.announce_new_device(&user, &device, caller.ip).await?;
    }

    DeviceRepo::upsert(&app.store, &device).await?;
    app.record_use(device.id).await;
    let identifier = app
        .note_device(
            &device,
            data.device_identifier.as_deref().unwrap_or_default(),
            device_type,
        )
        .await;
    let access = app.access_token(
        &user,
        &device,
        device_type,
        identifier,
        data.client_id.clone(),
        PASSWORD_SCOPE,
    )?;
    let ttl = if matches!(device_type, 0 | 1) {
        MOBILE_REFRESH_TTL
    } else {
        REFRESH_TTL
    };
    let refresh = app.new_refresh_token(user.id, device.id, None, ttl).await?;

    let mut result = json!({
        "access_token": access,
        "expires_in": ACCESS_TTL.whole_seconds(),
        "token_type": "Bearer",
        "refresh_token": refresh,
        "PrivateKey": account.private_key,
        "Kdf": account.kdf_type,
        "KdfIterations": account.kdf_iterations,
        "KdfMemory": account.kdf_memory,
        "KdfParallelism": account.kdf_parallelism,
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": identity_master_password_policy(),
        "scope": PASSWORD_SCOPE,
        "AccountKeys": token_account_keys(&account),
        "UserDecryptionOptions": user_decryption_options(&user, &account),
    });
    if !account.akey.is_empty() {
        result["Key"] = Value::String(account.akey.clone());
    }
    if let Some(remember) = remember {
        result["TwoFactorToken"] = Value::String(remember);
    }
    Ok(result)
}

/// A refresh token trades for a new access token and a new refresh token. Presenting a token
/// again within a minute of its use gets the same answer (a lost reply, retried); later, the
/// whole sign-in's tokens are revoked.
async fn refresh_login<S: BwStore>(
    app: &App<S>,
    data: &ConnectData,
    attempt: &mut Attempt,
) -> BwResult<Value> {
    attempt.checked = true;
    let raw = data
        .refresh_token
        .as_deref()
        // The move from Vaultwarden keeps its refresh tokens, 64 bytes, padded or not.
        .and_then(|t| b64url::decode(t.trim().trim_end_matches('=')))
        .filter(|raw| matches!(raw.len(), 32 | 64))
        .ok_or_else(invalid_grant)?;
    let now = app.now();
    let Some(token) = TokenRepo::take(&app.store, hash::sha256(&raw), now).await? else {
        return Err(invalid_grant());
    };
    attempt.user = Some(token.user);
    attempt.device = Some(token.device);
    if token.expires_at <= now {
        return Err(invalid_grant());
    }
    if let Some(used) = token.used_at
        && now - used > REFRESH_GRACE
    {
        TokenRepo::revoke_family(&app.store, token.family).await?;
        return Err(invalid_grant());
    }
    let device = DeviceRepo::get(&app.store, token.device)
        .await?
        .filter(|d| d.user == token.user)
        .ok_or_else(invalid_grant)?;
    let user = UserRepo::by_id(&app.store, token.user)
        .await?
        .ok_or_else(invalid_grant)?;
    // Disabling an account from the admin console ends its sessions, but one Vaultwarden had
    // disabled keeps its refresh tokens: neither gets a new access token.
    if UserRepo::account_disabled(&app.store, user.id).await? {
        TokenRepo::revoke_family(&app.store, token.family).await?;
        return Err(BwError::msg(DISABLED));
    }
    // A password change, a key replacement or an admin reset moved the stamp after this token was
    // issued: the Bitwarden app signs in again, as Vaultwarden has it. The whole sign-in goes.
    if user.security_stamp != token.security_stamp {
        TokenRepo::revoke_family(&app.store, token.family).await?;
        return Err(invalid_grant());
    }
    refuse_pending_erasure(app, &user).await?;
    crate::signup_hold::refuse_if_held(app, &user).await?;
    if account_of(app, &user).await?.is_none() {
        return Err(invalid_grant());
    }

    DeviceRepo::upsert(
        &app.store,
        &Device {
            last_seen_at: now,
            ..device.clone()
        },
    )
    .await?;
    app.record_use(device.id).await;
    // What the device kept at its sign-in; a device from before that has only its kind to go by.
    let known = BwDeviceRepo::bw_device(&app.store, device.id)
        .await
        .ok()
        .flatten();
    let identifier = known.as_ref().map(|k| k.identifier);
    let device_type = known.map_or_else(
        || match device.kind {
            DeviceKind::KemlockAndroid => 0,
            DeviceKind::KemlockIos => 1,
            DeviceKind::KemlockCli => 25,
            DeviceKind::Amethystora => 8,
            _ => 14,
        },
        |k| k.device_type,
    );
    let access = app.access_token(
        &user,
        &device,
        device_type,
        identifier,
        data.client_id.clone(),
        PASSWORD_SCOPE,
    )?;
    let ttl = token.expires_at - token.created_at;
    let refresh = app
        .new_refresh_token(user.id, device.id, Some(token.family), ttl)
        .await?;
    Ok(json!({
        "refresh_token": refresh,
        "access_token": access,
        "expires_in": ACCESS_TTL.whole_seconds(),
        "token_type": "Bearer",
        "scope": PASSWORD_SCOPE,
    }))
}

async fn api_key_login<S: BwStore>(
    app: &App<S>,
    data: ConnectData,
    caller: &Caller,
    attempt: &mut Attempt,
) -> BwResult<Value> {
    check_login_limit(app, caller.ip)?;
    match data.scope.as_deref() {
        Some(API_KEY_SCOPE) => {
            check_is_some(
                data.device_identifier.as_ref(),
                "device_identifier cannot be blank",
            )?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(
                data.device_type
                    .as_ref()
                    .or(caller.device_type_header.as_ref()),
                "device_type cannot be blank",
            )?;
            user_api_key_login(app, data, caller, attempt).await
        }
        Some(crate::orgs::api_key::SCOPE) => {
            let client_id = data.client_id.as_deref().unwrap_or_default();
            let secret = data.client_secret.as_deref().unwrap_or_default();
            crate::orgs::api_key::login(app, client_id, secret).await
        }
        _ => Err(BwError::msg("Scope not supported")),
    }
}

async fn user_api_key_login<S: BwStore>(
    app: &App<S>,
    data: ConnectData,
    caller: &Caller,
    attempt: &mut Attempt,
) -> BwResult<Value> {
    attempt.checked = true;
    let client_id = data.client_id.as_deref().unwrap_or_default();
    let Some(user_id) = client_id.strip_prefix("user.") else {
        return Err(BwError::msg("Malformed client_id"));
    };
    let user = match Uuid::parse_str(user_id) {
        Ok(id) => UserRepo::by_id(&app.store, UserId(id)).await?,
        Err(_) => None,
    };
    let Some(user) = user else {
        return Err(BwError::msg("Invalid client_id"));
    };
    // As Vaultwarden's `user_api_key_login` has it, the account is checked before the secret
    // (unlike the password grant): anyone who knows a user id is told the account is disabled.
    if UserRepo::account_disabled(&app.store, user.id).await? {
        return Err(BwError::msg(DISABLED_API_KEY));
    }
    let Some(account) = account_of(app, &user).await? else {
        return Err(BwError::msg("Invalid client_id"));
    };

    // The key opens the account without its second step, as in Vaultwarden.
    let secret = data.client_secret.as_deref().unwrap_or_default();
    let right = account
        .api_key
        .as_deref()
        .is_some_and(|key| hash::ct_eq(key.as_bytes(), secret.as_bytes()));
    if !right {
        return Err(BwError::msg("Incorrect client_secret"));
    }
    attempt.proved = true;
    attempt.user = Some(user.id);
    refuse_pending_erasure(app, &user).await?;
    crate::signup_hold::refuse_if_held(app, &user).await?;
    require_sso(app, &user, SignInMethod::ApiKey).await?;

    let device_type = requested_device_type(&data, caller);
    let (device, is_new) = app
        .device_for(
            user.id,
            data.device_identifier.as_deref().unwrap_or_default(),
            data.device_name.as_deref().unwrap_or_default(),
            device_type,
        )
        .await?;
    attempt.device = Some(device.id);
    if is_new {
        app.announce_new_device(&user, &device, caller.ip).await?;
    }
    DeviceRepo::upsert(&app.store, &device).await?;
    app.record_use(device.id).await;
    let identifier = app
        .note_device(
            &device,
            data.device_identifier.as_deref().unwrap_or_default(),
            device_type,
        )
        .await;
    let access = app.access_token(
        &user,
        &device,
        device_type,
        identifier,
        data.client_id.clone(),
        API_KEY_SCOPE,
    )?;

    // No refresh token: a client signs in with its key again when this one runs out.
    Ok(json!({
        "access_token": access,
        "expires_in": ACCESS_TTL.whole_seconds(),
        "token_type": "Bearer",
        "Key": account.akey,
        "PrivateKey": account.private_key,
        "Kdf": account.kdf_type,
        "KdfIterations": account.kdf_iterations,
        "KdfMemory": account.kdf_memory,
        "KdfParallelism": account.kdf_parallelism,
        "ForcePasswordReset": false,
        "scope": API_KEY_SCOPE,
        "AccountKeys": token_account_keys(&account),
        "UserDecryptionOptions": user_decryption_options(&user, &account),
    }))
}

/// `POST /api/two-factor/send-email-login`: checks who is asking, then has the mailer send the
/// code. A password hash identifies the account, as in Vaultwarden. Anyone can call it, and it
/// runs the server's password hash on every call, so it is limited like a sign-in: by the client
/// address, and by account once the password is right (the mails an account may ask for in a
/// window, which stops someone who has the password from filling the owner's mailbox). An address with no account,
/// an account with no hash sent and a wrong hash get one answer, so the route can't be used to
/// find out who has an account.
pub(crate) async fn send_email_login<S: BwStore>(
    app: &App<S>,
    ip: IpAddr,
    email: Option<&str>,
    master_password_hash: Option<&str>,
) -> BwResult<()> {
    check_login_limit(app, ip)?;
    if !app.two_step.settings.email_enabled {
        return Err(BwError::msg("Email 2FA is disabled"));
    }
    let email = email.filter(|e| !e.is_empty());
    let password_hash = master_password_hash.filter(|h| !h.is_empty());
    let Some(email) = email else {
        return Err(BwError::msg("No device identifier has been submitted."));
    };
    let user = match Email::parse(&email.trim().to_lowercase()) {
        Ok(parsed) => UserRepo::by_email(&app.store, &parsed).await?,
        Err(_) => None,
    };
    let account = match &user {
        Some(user) => account_of(app, user).await?,
        None => None,
    };
    let (Some(user), Some(account), Some(hash)) = (user, account, password_hash) else {
        // A hash was sent for an address with no account: the work of a check is done all the
        // same, so the time of the answer does not say who has an account.
        if let Some(hash) = password_hash {
            app.password_decoy(hash).await?;
        }
        return Err(BwError::msg(BAD_LOGIN));
    };
    check_password(app, &user, &account, hash).await?;
    // Only a request that knows the password is counted, so a stranger can neither use the count
    // to tell who has an account nor use up the owner's mails; the client address limit above is
    // what stops guesses.
    let tries = BwTryRepo::count_try(
        &app.store,
        user.id,
        EMAIL_LOGIN_KIND,
        app.now_secs(),
        TRIES_WINDOW_SECS,
    )
    .await?;
    if tries > EMAIL_LOGIN_MAX_TRIES {
        return Err(too_many_logins());
    }
    crate::two_step::steps(app)
        .email_send_login_code(&user)
        .await
        .map_err(crate::two_step::failed)
}

/// Whether the device an `X-Device-Identifier` names is one the account's `X-Request-Email`
/// has signed in from: Bitwarden clients ask before they decide to show a new-device notice.
pub(crate) async fn known_device<S: BwStore>(
    app: &App<S>,
    email: &str,
    identifier: &str,
) -> BwResult<bool> {
    let Ok(parsed) = Email::parse(email.trim()) else {
        return Ok(false);
    };
    let Some(user) = UserRepo::by_email(&app.store, &parsed).await? else {
        return Ok(false);
    };
    let id = device_id_for(user.id, identifier);
    Ok(DeviceRepo::get(&app.store, id)
        .await?
        .is_some_and(|d| d.user == user.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_names_are_read_without_regard_to_case_or_underscores() {
        let body = b"grant_type=password&clientId=cli&client_secret=s&Password=a%2Bb%3D&scope=api+offline_access&username=ada%40example.com&deviceIdentifier=d1&deviceName=Amethystora+Vault&deviceType=8&twoFactorProvider=0&twoFactorToken=123456&twoFactorRemember=1&device_push_token=x";
        let d = ConnectData::from_form(body).expect("parses");
        assert_eq!(d.grant_type, "password");
        assert_eq!(d.client_id.as_deref(), Some("cli"));
        assert_eq!(d.client_secret.as_deref(), Some("s"));
        assert_eq!(d.password.as_deref(), Some("a+b="));
        assert_eq!(d.scope.as_deref(), Some("api offline_access"));
        assert_eq!(d.username.as_deref(), Some("ada@example.com"));
        assert_eq!(d.device_identifier.as_deref(), Some("d1"));
        assert_eq!(d.device_name.as_deref(), Some("Amethystora Vault"));
        assert_eq!(d.device_type.as_deref(), Some("8"));
        assert_eq!(d.two_factor_provider, Some(0));
        assert_eq!(d.two_factor_token.as_deref(), Some("123456"));
        assert_eq!(d.two_factor_remember, Some(1));
    }

    #[test]
    fn a_form_needs_a_grant_and_numbers_that_are_numbers() {
        assert!(ConnectData::from_form(b"client_id=cli").is_none());
        assert!(ConnectData::from_form(b"grant_type=password&twoFactorProvider=x").is_none());
        assert!(ConnectData::from_form(b"GrantType=refresh_token&refreshToken=t").is_some());
    }

    #[test]
    fn device_types_have_bitwardens_names() {
        assert_eq!(device_type_name(0), "Android");
        assert_eq!(device_type_name(1), "iOS");
        assert_eq!(device_type_name(8), "Linux");
        assert_eq!(device_type_name(15), "Android");
        assert_eq!(device_type_name(14), "Unknown Browser");
        assert_eq!(device_type_name(99), "Unknown Browser");
    }

    #[test]
    fn the_apps_are_told_apart_by_device_name() {
        assert_eq!(device_kind("Amethystora Vault", 8), DeviceKind::Amethystora);
        assert_eq!(device_kind("Kemlock", 0), DeviceKind::KemlockAndroid);
        assert_eq!(device_kind("Kemlock", 1), DeviceKind::KemlockIos);
        assert_eq!(device_kind("Chrome", 9), DeviceKind::Bitwarden);
    }

    #[test]
    fn one_identifier_on_two_accounts_is_two_devices() {
        let (a, b) = (UserId::random(), UserId::random());
        assert_eq!(device_id_for(a, "phone"), device_id_for(a, "phone"));
        assert_ne!(device_id_for(a, "phone"), device_id_for(b, "phone"));
        assert_ne!(device_id_for(a, "phone"), device_id_for(a, "laptop"));
    }

    #[test]
    fn the_second_step_lists_providers_both_ways() {
        let BwError::Json(body) = two_factor_required(&[0]) else {
            panic!("a JSON error");
        };
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(body["error_description"], "Two factor required.");
        assert_eq!(body["TwoFactorProviders"], json!(["0"]));
        assert_eq!(body["TwoFactorProviders2"], json!({"0": null}));
        assert_eq!(
            body["MasterPasswordPolicy"],
            json!({"Object": "masterPasswordPolicy"})
        );
    }
}
