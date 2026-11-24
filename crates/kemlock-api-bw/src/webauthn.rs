//! Security keys (WebAuthn) as Bitwarden's second step, type 7, as Vaultwarden does it.
//!
//! - `POST /api/two-factor/get-webauthn` checks the master password and answers the account's keys
//!   with a `userVerificationToken`, which stands in for the password in the next two calls.
//! - `POST /api/two-factor/get-webauthn-challenge` answers the creation options (`options`) for a
//!   new key; the token is required (without one the answer is 422).
//! - `PUT` (or `POST`) `/api/two-factor/webauthn` takes the browser's `deviceResponse` and stores
//!   the key in the slot (1 to 5) the client names; `DELETE` removes the key in a slot.
//! - The token endpoint lists provider 7 when the account has a key, with the request options under
//!   `TwoFactorProviders2["7"]` (the server's own relying party id, an `appid` of its
//!   `/app-id.json`), and takes the key's answer as `twoFactorToken` of provider 7.
//!
//! What the apps depend on, from `tests/fixtures/webauthn`: a refused answer uses its challenge up
//! (the same challenge answered correctly afterwards is "Can't recover login challenge"), an
//! accepted answer sent again is too, an answer to an older challenge after a newer one is refused,
//! a counter that didn't grow is refused, and the answer is read with `clientDataJson` or
//! `clientDataJSON`. The ceremonies and the stored keys are `kemlock_app::passkeys::SecurityKeys`,
//! the same the Kemlock API uses.

use crate::account::check_valid_password;
use crate::app::{App, Authed, BwStore};
use crate::env::Env;
use crate::error::{BwError, BwResult};
use crate::routes::parse;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use kemlock_app::AuthConfig;
use kemlock_app::error::AppError;
use kemlock_app::passkeys::{KeyList, SecurityKeyError, SecurityKeys, WebAuthn};
use kemlock_app::platform::Hasher;
use kemlock_app::ports::{Clock, CryptoError, Random, SecretSeal, Zeroizing};
use kemlock_crypto::hash;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// How long a `userVerificationToken` stands in for the master password.
const VERIFICATION_TTL: Duration = Duration::minutes(10);

/// The token `get-webauthn` hands out and the next calls take instead of the master password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct VerificationClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    /// The user id.
    sub: String,
}

/// The server's seal as a `SecretSeal`, borrowed for one request.
pub(crate) struct SealRef<'a>(pub(crate) &'a ServerSeal);

impl SecretSeal for SealRef<'_> {
    fn seal(&self, purpose: &str, value: &[u8]) -> Vec<u8> {
        self.0.seal(purpose, value)
    }

    fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.0
            .open(purpose, sealed)
            .map_err(|_| CryptoError::Invalid)
    }
}

/// The API's clock and random source as the app crate's platform ports.
pub(crate) struct EnvPlatform(pub(crate) Arc<dyn Env>);

impl Clock for EnvPlatform {
    fn now(&self) -> OffsetDateTime {
        self.0.now()
    }
}

impl Random for EnvPlatform {
    fn fill(&self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

impl Hasher for EnvPlatform {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        hash::sha256(data)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        hash::hmac_sha256(key, data)
    }
}

type Keys<'a, S> = SecurityKeys<S, S, S, Arc<dyn WebAuthn>, SealRef<'a>, EnvPlatform>;

/// The security key use case over this API's ports, or Vaultwarden's refusal when no relying
/// party is configured.
fn keys<S: BwStore>(app: &App<S>) -> BwResult<Keys<'_, S>> {
    let webauthn = app.webauthn.clone().ok_or_else(|| {
        BwError::msg("`DOMAIN` environment variable is not set. Webauthn disabled")
    })?;
    Ok(SecurityKeys {
        users: app.store.clone(),
        two_factor: app.store.clone(),
        challenges: app.store.clone(),
        webauthn,
        seal: SealRef(&app.seal),
        env: EnvPlatform(app.env.clone()),
        config: AuthConfig::default(),
    })
}

fn app_error(e: AppError) -> BwError {
    match e {
        AppError::NotFound => BwError::msg("Webauthn entry not found"),
        other => BwError::Server(other.to_string()),
    }
}

/// A key's answer to a registration, as Vaultwarden words the refusals.
fn registration_error(e: SecurityKeyError) -> BwError {
    match e {
        SecurityKeyError::NoChallenge => BwError::msg("Can't recover challenge"),
        SecurityKeyError::Refused => BwError::msg("Webauthn"),
        SecurityKeyError::TooMany => BwError::msg("An account may have at most five security keys"),
        SecurityKeyError::Duplicate => BwError::msg("That security key is already registered"),
        SecurityKeyError::App(e) => app_error(e),
    }
}

/// The `keys` of Vaultwarden's answers.
fn keys_json(list: &KeyList) -> Value {
    Value::Array(
        list.keys
            .iter()
            .map(|k| json!({"id": k.id, "name": k.name, "migrated": false}))
            .collect(),
    )
}

// --- the token endpoint ----------------------------------------------------------------------

/// The request options of the second step for the account's keys, `TwoFactorProviders2["7"]`. The
/// challenge is stored, replacing any earlier one.
pub(crate) async fn login_options<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Value> {
    keys(app)?.start_login(user).await.map_err(|e| match e {
        AppError::NotFound => BwError::msg("No Webauthn devices registered"),
        other => app_error(other),
    })
}

/// Checks a key's answer, the `twoFactorToken` of provider 7. The challenge is used up whether the
/// answer is right or not.
pub(crate) async fn validate_login<S: BwStore>(
    app: &App<S>,
    user: UserId,
    token: &str,
) -> BwResult<()> {
    keys(app)?
        .finish_login(user, token.as_bytes())
        .await
        .map_err(|e| match e {
            SecurityKeyError::NoChallenge => BwError::msg("Can't recover login challenge"),
            SecurityKeyError::App(e) => app_error(e),
            _ => BwError::msg("Webauthn"),
        })
}

// --- the account routes ----------------------------------------------------------------------

type JsonResult = Result<Json<Value>, BwError>;

/// What the routes that change keys accept in place of the password.
pub(crate) fn issue_token<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<String> {
    let now = app.now_secs();
    app.keys
        .encode(&VerificationClaims {
            nbf: now,
            exp: now + VERIFICATION_TTL.whole_seconds(),
            iss: app.settings.issuer("userverification"),
            sub: user.to_string(),
        })
        .map_err(|e| BwError::Server(e.to_string()))
}

pub(crate) fn token_is_valid<S: BwStore>(app: &App<S>, user: UserId, token: &str) -> bool {
    app.keys
        .decode::<VerificationClaims>(
            token,
            &app.settings.issuer("userverification"),
            app.now_secs(),
        )
        .is_ok_and(|claims| claims.sub == user.to_string())
}

/// The master password, or (where the call allows one) a `userVerificationToken` this server made
/// for this account.
pub(crate) fn verify<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    master_password_hash: Option<&str>,
    token: Option<&str>,
) -> BwResult<()> {
    match (master_password_hash, token) {
        (Some(hash), _) => {
            if check_valid_password(&authed.account, hash) {
                Ok(())
            } else {
                Err(BwError::msg("Invalid password"))
            }
        }
        (None, Some(token)) => {
            if token_is_valid(app, authed.user.id, token) {
                Ok(())
            } else {
                Err(BwError::msg("Invalid user verification token"))
            }
        }
        (None, None) => Err(BwError::msg("No validation provided")),
    }
}

/// A slot as a client writes it: a number or a string of digits, 1 to 5.
fn slot_of(value: &Value) -> BwResult<u8> {
    let number = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    number
        .and_then(|n| u8::try_from(n).ok())
        .filter(|n| (1..=5).contains(n))
        .ok_or_else(|| BwError::msg("Invalid key slot"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeData {
    master_password_hash: Option<String>,
    /// Required: a request without one is a 422.
    user_verification_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableData {
    id: Value,
    name: String,
    device_response: Value,
    master_password_hash: Option<String>,
    user_verification_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteData {
    id: Value,
    master_password_hash: String,
}

/// `POST /api/two-factor/get-webauthn`.
async fn get_webauthn<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: PasswordData = parse(&body)?;
    let keys = keys(&app)?;
    // The password or a mailed one-time code, which stays good for the calls that follow.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        false,
    )
    .await?;
    let list = keys.keys(authed.user.id).await.map_err(app_error)?;
    Ok(Json(json!({
        "userVerificationToken": issue_token(&app, authed.user.id)?,
        "webAuthn": {
            "enabled": list.enabled,
            "keys": keys_json(&list),
            "object": "twoFactorWebAuthn",
        },
    })))
}

/// `POST /api/two-factor/get-webauthn-challenge`.
async fn get_webauthn_challenge<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: ChallengeData = parse(&body)?;
    let keys = keys(&app)?;
    verify(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        Some(&data.user_verification_token),
    )?;
    let mut options = keys
        .start_registration(authed.user.id)
        .await
        .map_err(app_error)?;
    options["status"] = json!("ok");
    options["errorMessage"] = json!("");
    Ok(Json(json!({"options": options})))
}

/// `PUT` and `POST /api/two-factor/webauthn`.
async fn activate_webauthn<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: EnableData = parse(&body)?;
    let keys = keys(&app)?;
    verify(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.user_verification_token.as_deref(),
    )?;
    let slot = slot_of(&data.id)?;
    let response = serde_json::to_vec(&data.device_response)
        .map_err(|_| BwError::msg("Invalid device response"))?;
    let list = keys
        .finish_registration(authed.user.id, Some(slot), &data.name, &response)
        .await
        .map_err(registration_error)?;
    crate::two_step::ensure_recovery_code(&app, authed.user.id).await?;
    Ok(Json(json!({
        "enabled": list.enabled,
        "keys": keys_json(&list),
        "object": "twoFactorU2f",
    })))
}

/// `DELETE /api/two-factor/webauthn`.
async fn delete_webauthn<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: DeleteData = parse(&body)?;
    let keys = keys(&app)?;
    verify(&app, &authed, Some(&data.master_password_hash), None)?;
    let list = keys
        .remove(authed.user.id, slot_of(&data.id)?)
        .await
        .map_err(app_error)?;
    Ok(Json(json!({
        "enabled": list.enabled,
        "keys": keys_json(&list),
        "object": "twoFactorU2f",
    })))
}

/// `GET /app-id.json`: the FIDO facets list the `appid` extension of a security key's challenge
/// points at, naming this server's origin.
async fn app_id<S: BwStore>(State(app): State<App<S>>) -> impl IntoResponse {
    let body = json!({
        "trustedFacets": [{
            "version": {"major": 1, "minor": 0},
            "ids": [app.settings.origin],
        }],
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/fido.trusted-apps+json")],
        body.to_string(),
    )
}

/// The routes of this module, merged into the Bitwarden router.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/api/two-factor/get-webauthn", post(get_webauthn::<S>))
        .route(
            "/api/two-factor/get-webauthn-challenge",
            post(get_webauthn_challenge::<S>),
        )
        .route(
            "/api/two-factor/webauthn",
            put(activate_webauthn::<S>)
                .post(activate_webauthn::<S>)
                .delete(delete_webauthn::<S>),
        )
        .route("/app-id.json", get(app_id::<S>))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_a_number_or_digits_from_one_to_five() {
        assert_eq!(slot_of(&json!(1)).ok(), Some(1));
        assert_eq!(slot_of(&json!("5")).ok(), Some(5));
        assert_eq!(slot_of(&json!(" 3 ")).ok(), Some(3));
        for bad in [
            json!(0),
            json!(6),
            json!("six"),
            json!(null),
            json!(1.5),
            json!(-1),
        ] {
            assert!(slot_of(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_are_listed_with_their_slot_name_and_a_false_migrated() {
        let list = KeyList {
            enabled: true,
            keys: vec![kemlock_app::passkeys::SecurityKeyInfo {
                id: 2,
                name: "Yubi".to_owned(),
            }],
        };
        assert_eq!(
            keys_json(&list),
            json!([{"id": 2, "name": "Yubi", "migrated": false}])
        );
    }
}
