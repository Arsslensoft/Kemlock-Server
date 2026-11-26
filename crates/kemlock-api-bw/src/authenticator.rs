//! Authenticator apps (TOTP) as Bitwarden's second step, type 0, as Vaultwarden's
//! `api/core/two_factor/authenticator.rs` and `auth/two_factor.rs` have it.
//!
//! - `POST /api/two-factor/get-authenticator` checks the master password (or a mailed one-time
//!   code) and answers the account's key (or a new one, not stored yet) with a
//!   `userVerificationToken` that names the user, the key and whether the method is on.
//! - `PUT` (or `POST`) `/api/two-factor/authenticator` takes the key, a code from it and that
//!   token, and turns the method on. The token must say the method is off.
//! - `DELETE /api/two-factor/authenticator` takes the key and a token that says the method is on,
//!   and turns it off.
//!
//! The secret is kept the way the Kemlock API keeps it, sealed under `server.key` (purpose
//! `totp`) as the raw bytes, so one enrolment serves both APIs and the token endpoint's second
//! step. The proof is the master password or a mailed one-time code (`protected`).

use crate::app::{App, Authed, BwStore};
use crate::env::random_bytes;
use crate::error::{BwError, BwResult};
use crate::identity::time_of_day;
use crate::routes::{EmptyResult, JsonResult, Peer, parse};
use crate::webauthn::SealRef;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{post, put};
use kemlock_app::enrol_totp::{SECRET_LEN, base32};
use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::sealed::{PURPOSE_TOTP, open_bound, seal_bound};
use kemlock_crypto::totp;
use kemlock_domain::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::Duration;

/// How long a `userVerificationToken` lives, as Vaultwarden's five minutes.
const TOKEN_TTL: Duration = Duration::minutes(5);

/// Vaultwarden's claims of a verification token: the user, whether the method is on, and what the
/// provider adds (here the key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StateClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    /// The user id.
    sub: String,
    enabled: bool,
    claims: KeyClaims,
}

/// A token made for another provider doesn't parse as this one, as in Vaultwarden.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyClaims {
    authenticator_key: String,
}

fn issue_token<S: BwStore>(
    app: &App<S>,
    user: UserId,
    key: &str,
    enabled: bool,
) -> BwResult<String> {
    let now = app.now_secs();
    app.keys
        .encode(&StateClaims {
            nbf: now,
            exp: now + TOKEN_TTL.whole_seconds(),
            iss: app.settings.issuer("api.2fa"),
            sub: user.to_string(),
            enabled,
            claims: KeyClaims {
                authenticator_key: key.to_owned(),
            },
        })
        .map_err(|e| BwError::Server(e.to_string()))
}

/// Vaultwarden's `validate_authenticator`, with its messages.
fn validate_token<S: BwStore>(
    app: &App<S>,
    token: &str,
    user: UserId,
    key: &str,
    enabled: bool,
) -> BwResult<()> {
    let claims: StateClaims = app
        .keys
        .decode(token, &app.settings.issuer("api.2fa"), app.now_secs())
        .map_err(|e| BwError::msg(format!("Failed to decode verification token: {e}")))?;
    if claims.sub != user.to_string() {
        return Err(BwError::msg("Invalid verification token: Invalid user"));
    }
    if claims.enabled != enabled {
        return Err(BwError::msg("Invalid verification token: Invalid state"));
    }
    if claims.claims.authenticator_key != key {
        return Err(BwError::msg("Invalid verification token: Invalid key"));
    }
    Ok(())
}

/// RFC 4648 base32 as `data_encoding::BASE32` reads it: upper case only, and padded to a multiple
/// of eight characters when the length needs it.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|b| **b == b'=').count();
    let body = &bytes[..bytes.len() - padding];
    // A body of 2, 4, 5 or 7 characters over the last block takes 6, 4, 3 or 1 characters of
    // padding; a body that ends a block takes none.
    let wanted = match body.len() % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return None,
    };
    if padding != wanted {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &c in body {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
            buffer &= (1 << bits) - 1;
        }
    }
    // The bits left over are padding and must be zero.
    (buffer == 0).then_some(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordOrOtp {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableData {
    key: String,
    /// A number or a string, as Vaultwarden's `NumberOrString`.
    token: Value,
    user_verification_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableData {
    key: String,
    user_verification_token: String,
}

/// The text of a `NumberOrString`: a string as it is, a whole number in decimal. Anything else is
/// a 422, as Vaultwarden's JSON guard has it.
fn token_text(value: &Value) -> BwResult<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        _ => Err(BwError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Entity",
        )),
    }
}

/// The user's TOTP enrolment, when it is on.
async fn enabled_enrolment<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Option<TwoFactor>> {
    Ok(TwoFactorRepo::list(&app.store, user)
        .await?
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::Totp && t.enabled))
}

/// `POST /api/two-factor/get-authenticator`.
async fn get_authenticator<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: PasswordOrOtp = parse(&body)?;
    // The password or a mailed code; the code stays good for the calls that follow.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        false,
    )
    .await?;
    let (enabled, key) = match enabled_enrolment(&app, authed.user.id).await? {
        Some(enrolment) => {
            let secret = open_bound(
                &SealRef(&app.seal),
                PURPOSE_TOTP,
                authed.user.id,
                &enrolment.sealed_secret,
            )
            .map_err(|_| BwError::Server("a stored TOTP secret doesn't open".to_owned()))?
            .value;
            (true, base32(&secret))
        }
        None => (false, base32(&random_bytes::<SECRET_LEN>(app.env.as_ref()))),
    };
    Ok(Json(json!({
        "authenticator": {
            "enabled": enabled,
            "key": key,
        },
        "userVerificationToken": issue_token(&app, authed.user.id, &key, enabled)?,
    })))
}

/// `PUT` and `POST /api/two-factor/authenticator`.
async fn activate_authenticator<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Peer(ip): Peer,
    body: Bytes,
) -> JsonResult {
    let data: EnableData = parse(&body)?;
    let token = token_text(&data.token)?;
    let user = authed.user.id;
    // The token says what state the method was in when it was issued; it must still be that state,
    // as in Vaultwarden, so a token from before the method was turned on can't turn it on again.
    let enabled_now = enabled_enrolment(&app, user).await?.is_some();
    validate_token(
        &app,
        &data.user_verification_token,
        user,
        &data.key,
        enabled_now,
    )?;

    let Some(secret) = base32_decode(&data.key) else {
        return Err(BwError::msg("Invalid totp secret"));
    };
    if secret.len() != SECRET_LEN {
        return Err(BwError::msg("Invalid key length"));
    }

    // The code must be one the key makes now, and its step is spent, so the same code can't be
    // used to sign in right after.
    let now = app.now();
    let invalid = || {
        BwError::msg(format!(
            "Invalid TOTP code! Server time: {} IP: {ip}",
            time_of_day(now)
        ))
    };
    let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
    let step = totp::verify_step(&secret, &token, unix).ok_or_else(invalid)?;
    let before = TwoFactorRepo::list(&app.store, user)
        .await?
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::Totp);
    TwoFactorRepo::put(
        &app.store,
        &TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: seal_bound(&SealRef(&app.seal), PURPOSE_TOTP, user, &secret),
            enabled: true,
            created_at: now,
        },
    )
    .await?;
    if !TwoFactorRepo::accept_totp_step(&app.store, user, step).await? {
        // A step this enrolment already spent: nothing changes, so what was there before stays
        // (an account that is on keeps its method and its key).
        match before {
            Some(before) => TwoFactorRepo::put(&app.store, &before).await?,
            None => TwoFactorRepo::remove(&app.store, user, TwoFactorMethod::Totp).await?,
        }
        return Err(invalid());
    }
    // The first second step an account turns on gives it a recovery code, as in Vaultwarden.
    crate::two_step::ensure_recovery_code(&app, user).await?;

    Ok(Json(json!({
        "authenticator": {
            "enabled": true,
            "key": data.key,
        },
    })))
}

/// `DELETE /api/two-factor/authenticator`.
async fn disable_authenticator<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: DisableData = parse(&body)?;
    let user = authed.user.id;
    let enabled_now = enabled_enrolment(&app, user).await?.is_some();
    validate_token(
        &app,
        &data.user_verification_token,
        user,
        &data.key,
        enabled_now,
    )?;

    if let Some(enrolment) = enabled_enrolment(&app, user).await? {
        let secret = open_bound(
            &SealRef(&app.seal),
            PURPOSE_TOTP,
            user,
            &enrolment.sealed_secret,
        )
        .map_err(|_| BwError::Server("a stored TOTP secret doesn't open".to_owned()))?
        .value;
        if base32(&secret) != data.key {
            return Err(BwError::msg(format!(
                "TOTP key for user {} does not match recorded value, cannot deactivate",
                authed.user.email.as_str()
            )));
        }
        TwoFactorRepo::remove(&app.store, user, TwoFactorMethod::Totp).await?;
    }
    Ok(StatusCode::OK)
}

/// The routes of this module, merged into the Bitwarden router.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route(
            "/api/two-factor/get-authenticator",
            post(get_authenticator::<S>),
        )
        .route(
            "/api/two-factor/authenticator",
            put(activate_authenticator::<S>)
                .post(activate_authenticator::<S>)
                .delete(disable_authenticator::<S>),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_reads_what_the_app_shows_and_nothing_looser() {
        // 20 bytes are 32 characters with no padding.
        let key = base32(&[7u8; 20]);
        assert_eq!(key.len(), 32);
        assert_eq!(base32_decode(&key), Some(vec![7u8; 20]));
        assert_eq!(base32_decode("MZXW6YTB"), Some(b"fooba".to_vec()));
        assert_eq!(base32_decode("MZXW6==="), Some(b"foo".to_vec()));
        // Lower case, a length that needs padding and doesn't have it, a stray character.
        assert_eq!(base32_decode("mzxw6ytb"), None);
        assert_eq!(base32_decode("MZXW6"), None);
        assert_eq!(base32_decode("MZXW1YTB"), None);
        assert_eq!(base32_decode("MZXW6YT!"), None);
        assert_eq!(base32_decode(""), Some(Vec::new()));
    }

    #[test]
    fn a_code_is_a_string_or_a_whole_number() {
        assert_eq!(token_text(&json!("012345")).ok().as_deref(), Some("012345"));
        assert_eq!(token_text(&json!(123_456)).ok().as_deref(), Some("123456"));
        assert!(token_text(&json!(1.5)).is_err());
        assert!(token_text(&json!(null)).is_err());
    }
}
