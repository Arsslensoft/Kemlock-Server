//! Emailed codes (type 1), Duo (2) and YubiKeys (3) as Bitwarden's second step, as Vaultwarden
//! 1.37.5 serves them, beside security keys (7, in `webauthn`) and authenticator apps (0).
//!
//! - `GET /api/two-factor` lists the account's usable providers.
//! - Recovery code: `POST /api/two-factor/get-recover` shows it; every method's setup makes it.
//! - Email: `POST /api/two-factor/get-email`, `send-email`, `PUT .../email` (which takes the code
//!   that was mailed), `DELETE .../email`; and `POST /api/two-factor/send-email-login`, which the
//!   web vault calls at sign-in to have the code mailed.
//! - Duo: `POST .../get-duo`, `POST`/`PUT .../duo`, `DELETE .../duo`.
//! - YubiKey: `POST .../get-yubikey`, `POST`/`PUT .../yubikey`, `DELETE .../yubikey`.
//!
//! The `get-*` calls check the master password (or a mailed one-time code) and hand out a
//! `userVerificationToken` that the calls after stand in for it. Their answers are Vaultwarden's,
//! quirks included: Duo's keys are shown as `<global_secret>` or hidden but four characters, and
//! an account with no keys of its own that could use the server's is shown a note to leave the
//! fields alone.
//!
//! At sign-in the 400 that asks for a second step carries, under `TwoFactorProviders2`, the hidden
//! address of an email (`Email`), whether a YubiKey reads over NFC (`Nfc`) and the address of Duo's
//! prompt (`AuthUrl`); the answer is the `twoFactorToken` of that provider (a Duo answer is
//! `<code>|<state>`). The use cases are `kemlock_app::two_step::TwoStep`, the same the Kemlock API
//! runs.

use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::routes::parse;
use crate::webauthn::{EnvPlatform, SealRef, issue_token, token_is_valid};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post, put};
use kemlock_app::error::AppError;
use kemlock_app::notices::Notices;
use kemlock_app::ports::{TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    Duo, DuoKeys, DuoStatus, GLOBAL_KEYS_MARK, NoDuo, NoYubico, RecoveryCodes, TwoStep,
    TwoStepSettings, Yubico, YubikeyData, provider_type,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// What the web vault shows in place of the global Duo keys' fields when an account could use them.
const DISABLED_MESSAGE: &str = "<To use the global Duo keys, please leave these fields untouched>";

/// The second steps beyond an authenticator app and a security key, as the Bitwarden API is given
/// them: whether each is offered, and the services they call.
#[derive(Clone)]
pub struct TwoStepParts {
    pub settings: TwoStepSettings,
    /// Sends the emailed codes.
    pub notices: Notices,
    pub yubico: Arc<dyn Yubico>,
    pub duo: Arc<dyn Duo>,
}

impl Default for TwoStepParts {
    /// Nothing offered: no mail, no Yubico, no Duo.
    fn default() -> Self {
        TwoStepParts {
            settings: TwoStepSettings::default(),
            notices: Notices::logging(),
            yubico: Arc::new(NoYubico),
            duo: Arc::new(NoDuo),
        }
    }
}

impl std::fmt::Debug for TwoStepParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoStepParts")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The use case over this API's ports.
pub(crate) type Steps<'a, S> = TwoStep<S, SealRef<'a>, EnvPlatform, S>;

pub(crate) fn steps<S: BwStore>(app: &App<S>) -> Steps<'_, S> {
    TwoStep {
        two_factor: app.store.clone(),
        seal: SealRef(&app.seal),
        env: EnvPlatform(app.env.clone()),
        challenges: app.store.clone(),
        notices: app.two_step.notices.clone(),
        yubico: app.two_step.yubico.clone(),
        duo: app.two_step.duo.clone(),
        settings: app.two_step.settings.clone(),
    }
}

/// The recovery code use case over this API's ports.
pub(crate) type Recovery<'a, S> = RecoveryCodes<S, S, SealRef<'a>, EnvPlatform>;

pub(crate) fn recovery_codes<S: BwStore>(app: &App<S>) -> Recovery<'_, S> {
    RecoveryCodes {
        recovery: app.store.clone(),
        two_factor: app.store.clone(),
        seal: SealRef(&app.seal),
        env: EnvPlatform(app.env.clone()),
    }
}

/// Vaultwarden's `generate_recover_code`, which every method's setup calls: the account has a
/// recovery code once it has a second step.
pub(crate) async fn ensure_recovery_code<S: BwStore>(
    app: &App<S>,
    user: kemlock_domain::UserId,
) -> BwResult<()> {
    recovery_codes(app).ensure(user).await.map_err(failed)
}

/// What a use case's refusal is to a Bitwarden client.
pub(crate) fn failed(e: AppError) -> BwError {
    match e {
        AppError::Invalid(message) => BwError::msg(message),
        AppError::NotFound => BwError::msg("Two factor not found"),
        AppError::Unauthorized => BwError::msg("Token is invalid"),
        other => BwError::Server(other.to_string()),
    }
}

type JsonResult = Result<Json<Value>, BwError>;

/// The call that needs only the verification token the `get-*` calls handed out.
fn check_token<S: BwStore>(app: &App<S>, authed: &Authed, token: &str) -> BwResult<()> {
    if token_is_valid(app, authed.user.id, token) {
        Ok(())
    } else {
        Err(BwError::msg("Invalid user verification token"))
    }
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
struct TokenData {
    user_verification_token: String,
}

// --- the list --------------------------------------------------------------------------------

/// `GET /api/two-factor`: the account's two-step providers that this server can answer.
async fn list<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    let steps = steps(&app);
    let mut providers: Vec<(i32, bool)> = TwoFactorRepo::list(&app.store, authed.user.id)
        .await?
        .iter()
        .filter(|f| match f.method {
            TwoFactorMethod::WebAuthn => app.webauthn.is_some(),
            _ => steps.usable(f) || !f.enabled,
        })
        .map(|f| (provider_type(f.method), f.enabled))
        .collect();
    providers.sort_unstable();
    let data: Vec<Value> = providers
        .into_iter()
        .map(|(kind, enabled)| json!({"enabled": enabled, "type": kind, "object": "twoFactorProvider"}))
        .collect();
    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })))
}

// --- the recovery code -----------------------------------------------------------------------

/// `POST /api/two-factor/get-recover`: the account's recovery code (`null` before it has a second
/// step), for the master password or a mailed code (which this call uses up). Vaultwarden 1.37.5
/// serves it as a `POST`; entering the code at sign-in (provider 8) is what spends it.
async fn get_recover<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: PasswordData = parse(&body)?;
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        true,
    )
    .await?;
    let code = recovery_codes(&app)
        .show(authed.user.id)
        .await
        .map_err(failed)?;
    Ok(Json(json!({"code": code, "object": "twoFactorRecover"})))
}

// --- email -----------------------------------------------------------------------------------

/// `POST /api/two-factor/get-email`.
async fn get_email<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: PasswordData = parse(&body)?;
    // The password or a mailed one-time code, which stays good for the calls that follow.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        false,
    )
    .await?;
    let address = steps(&app)
        .email_address(authed.user.id)
        .await
        .map_err(failed)?;
    Ok(Json(json!({
        "email": {"enabled": address.is_some(), "email": address},
        "userVerificationToken": issue_token(&app, authed.user.id)?,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailData {
    email: String,
    user_verification_token: String,
}

/// `POST /api/two-factor/send-email`: mails a first code to the address, to check it is one the
/// person reads.
async fn send_email<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: SendEmailData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    steps(&app)
        .email_begin(authed.user.id, &data.email)
        .await
        .map_err(failed)?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailData {
    email: String,
    token: String,
    user_verification_token: String,
}

/// `PUT /api/two-factor/email`: turns the method on with the code that was mailed.
async fn activate_email<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: EmailData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    steps(&app)
        .email_confirm(authed.user.id, &data.email, &data.token)
        .await
        .map_err(failed)?;
    ensure_recovery_code(&app, authed.user.id).await?;
    Ok(Json(json!({})))
}

/// `DELETE /api/two-factor/email`.
async fn disable_email<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> Result<axum::http::StatusCode, BwError> {
    let data: TokenData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    steps(&app)
        .email_disable(authed.user.id)
        .await
        .map_err(failed)?;
    Ok(axum::http::StatusCode::OK)
}

// --- Duo -------------------------------------------------------------------------------------

/// The fields the web vault shows for an account's Duo setup, and whether the method is on.
fn duo_shown(status: &DuoStatus) -> (bool, Option<DuoKeys>) {
    let mark = |text: &str| DuoKeys {
        host: text.to_owned(),
        ik: text.to_owned(),
        sk: text.to_owned(),
    };
    match status {
        DuoStatus::Global(_) => (true, Some(mark(GLOBAL_KEYS_MARK))),
        DuoStatus::User(keys) => (true, Some(keys.obscured())),
        DuoStatus::Disabled {
            global_available: true,
        } => (false, Some(mark(DISABLED_MESSAGE))),
        DuoStatus::Disabled {
            global_available: false,
        } => (false, None),
    }
}

fn duo_json(enabled: bool, shown: Option<&DuoKeys>) -> Value {
    json!({
        "enabled": enabled,
        "host": shown.map(|k| k.host.as_str()),
        "clientSecret": shown.map(|k| k.sk.as_str()),
        "clientId": shown.map(|k| k.ik.as_str()),
    })
}

/// `POST /api/two-factor/get-duo`.
async fn get_duo<S: BwStore>(State(app): State<App<S>>, authed: Authed, body: Bytes) -> JsonResult {
    let data: PasswordData = parse(&body)?;
    // The password or a mailed one-time code, which stays good for the calls that follow.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        false,
    )
    .await?;
    let status = steps(&app)
        .duo_status(authed.user.id)
        .await
        .map_err(failed)?;
    let (enabled, shown) = duo_shown(&status);
    Ok(Json(json!({
        "duo": duo_json(enabled, shown.as_ref()),
        "userVerificationToken": issue_token(&app, authed.user.id)?,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DuoData {
    host: String,
    client_secret: String,
    client_id: String,
    user_verification_token: String,
}

/// Whether a field is blank or the note the web vault shows in place of the global keys.
fn untouched(text: &str) -> bool {
    text.trim().is_empty() || text == DISABLED_MESSAGE
}

/// `POST` and `PUT /api/two-factor/duo`: keys of the account's own (checked with Duo), or, with
/// the fields left alone, the server's.
async fn activate_duo<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: DuoData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    let custom =
        if untouched(&data.host) || untouched(&data.client_secret) || untouched(&data.client_id) {
            None
        } else {
            Some(DuoKeys {
                host: data.host.clone(),
                ik: data.client_id.clone(),
                sk: data.client_secret.clone(),
            })
        };
    let status = steps(&app)
        .duo_set(authed.user.id, custom)
        .await
        .map_err(failed)?;
    ensure_recovery_code(&app, authed.user.id).await?;
    let (_, shown) = duo_shown(&status);
    Ok(Json(json!({"duo": duo_json(true, shown.as_ref())})))
}

/// `DELETE /api/two-factor/duo`.
async fn disable_duo<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> Result<axum::http::StatusCode, BwError> {
    let data: TokenData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    steps(&app)
        .duo_remove(authed.user.id)
        .await
        .map_err(failed)?;
    Ok(axum::http::StatusCode::OK)
}

// --- YubiKey ---------------------------------------------------------------------------------

/// The keys as the web vault reads them: `Key1`, `Key2`, ... beside `enabled` and `nfc`.
fn yubikey_json(keys: &[String], nfc: bool) -> Value {
    let mut out = serde_json::Map::new();
    for (index, key) in keys.iter().enumerate() {
        out.insert(format!("Key{}", index + 1), Value::String(key.clone()));
    }
    out.insert("enabled".to_owned(), Value::Bool(!keys.is_empty()));
    out.insert("nfc".to_owned(), Value::Bool(nfc));
    Value::Object(out)
}

fn yubico_on<S: BwStore>(app: &App<S>) -> BwResult<()> {
    if app.two_step.settings.yubico_enabled {
        Ok(())
    } else {
        Err(BwError::msg("Yubico support is disabled"))
    }
}

/// `POST /api/two-factor/get-yubikey`.
async fn get_yubikey<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    yubico_on(&app)?;
    let data: PasswordData = parse(&body)?;
    // The password or a mailed one-time code, which stays good for the calls that follow.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        false,
    )
    .await?;
    let keys = steps(&app)
        .yubikey_keys(authed.user.id)
        .await
        .map_err(failed)?;
    let shown = match keys {
        Some(YubikeyData { keys, nfc }) => yubikey_json(&keys, nfc),
        None => json!({"enabled": false}),
    };
    Ok(Json(json!({
        "yubiKey": shown,
        "userVerificationToken": issue_token(&app, authed.user.id)?,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct YubikeyForm {
    key1: Option<String>,
    key2: Option<String>,
    key3: Option<String>,
    key4: Option<String>,
    key5: Option<String>,
    nfc: bool,
    user_verification_token: String,
}

/// `POST` and `PUT /api/two-factor/yubikey`: registers the keys that made these OTPs.
async fn activate_yubikey<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: YubikeyForm = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    let entries: Vec<String> = [data.key1, data.key2, data.key3, data.key4, data.key5]
        .into_iter()
        .flatten()
        .filter(|k| !k.is_empty())
        .collect();
    let saved = steps(&app)
        .yubikey_set(authed.user.id, &entries, data.nfc)
        .await
        .map_err(failed)?;
    ensure_recovery_code(&app, authed.user.id).await?;
    Ok(Json(
        json!({"yubiKey": yubikey_json(&saved.keys, saved.nfc)}),
    ))
}

/// `DELETE /api/two-factor/yubikey`.
async fn delete_yubikeys<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> Result<axum::http::StatusCode, BwError> {
    let data: TokenData = parse(&body)?;
    check_token(&app, &authed, &data.user_verification_token)?;
    steps(&app)
        .yubikey_remove(authed.user.id)
        .await
        .map_err(failed)?;
    Ok(axum::http::StatusCode::OK)
}

/// The routes of this module, merged into the Bitwarden router.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/api/two-factor", get(list::<S>))
        .route("/api/two-factor/get-recover", post(get_recover::<S>))
        .route("/api/two-factor/get-email", post(get_email::<S>))
        .route("/api/two-factor/send-email", post(send_email::<S>))
        .route(
            "/api/two-factor/email",
            put(activate_email::<S>).delete(disable_email::<S>),
        )
        .route("/api/two-factor/get-duo", post(get_duo::<S>))
        .route(
            "/api/two-factor/duo",
            put(activate_duo::<S>)
                .post(activate_duo::<S>)
                .delete(disable_duo::<S>),
        )
        .route("/api/two-factor/get-yubikey", post(get_yubikey::<S>))
        .route(
            "/api/two-factor/yubikey",
            put(activate_yubikey::<S>)
                .post(activate_yubikey::<S>)
                .delete(delete_yubikeys::<S>),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duo_is_shown_as_vaultwarden_shows_it() {
        let own = DuoKeys {
            host: "api-1234.duosecurity.com".to_owned(),
            ik: "DIXXXXXXXXXXXXXXXXXX".to_owned(),
            sk: "secret-secret".to_owned(),
        };
        let (enabled, shown) = duo_shown(&DuoStatus::User(own.clone()));
        assert!(enabled);
        assert_eq!(
            duo_json(enabled, shown.as_ref()),
            json!({
                "enabled": true,
                "host": "api-************",
                "clientSecret": "secr************",
                "clientId": "DIXX************",
            })
        );
        let (enabled, shown) = duo_shown(&DuoStatus::Global(own));
        assert_eq!(
            duo_json(enabled, shown.as_ref()),
            json!({
                "enabled": true,
                "host": "<global_secret>",
                "clientSecret": "<global_secret>",
                "clientId": "<global_secret>",
            })
        );
        let (enabled, shown) = duo_shown(&DuoStatus::Disabled {
            global_available: true,
        });
        assert!(!enabled);
        assert_eq!(duo_json(enabled, shown.as_ref())["host"], DISABLED_MESSAGE);
        let (enabled, shown) = duo_shown(&DuoStatus::Disabled {
            global_available: false,
        });
        assert_eq!(
            duo_json(enabled, shown.as_ref()),
            json!({"enabled": false, "host": null, "clientSecret": null, "clientId": null})
        );
    }

    #[test]
    fn untouched_fields_are_blank_or_the_note() {
        assert!(untouched(""));
        assert!(untouched("  "));
        assert!(untouched(DISABLED_MESSAGE));
        assert!(!untouched("api-1234.duosecurity.com"));
    }

    #[test]
    fn yubikeys_are_listed_as_numbered_keys() {
        assert_eq!(
            yubikey_json(
                &["cccccccccccc".to_owned(), "dddddddddddd".to_owned()],
                true
            ),
            json!({"Key1": "cccccccccccc", "Key2": "dddddddddddd", "enabled": true, "nfc": true})
        );
        assert_eq!(
            yubikey_json(&[], false),
            json!({"enabled": false, "nfc": false})
        );
    }

    #[test]
    fn refusals_are_vaultwardens_messages() {
        assert_eq!(
            failed(AppError::Invalid("A key is required.")),
            BwError::msg("A key is required.")
        );
        assert_eq!(
            failed(AppError::Unauthorized),
            BwError::msg("Token is invalid")
        );
        assert!(matches!(
            failed(AppError::Store("x".to_owned())),
            BwError::Server(_)
        ));
    }
}
