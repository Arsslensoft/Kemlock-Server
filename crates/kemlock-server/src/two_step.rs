//! The second steps beyond an authenticator app and a security key, wired: emailed codes, YubiKey
//! OTPs and Duo, for both APIs.
//!
//! The settings are Vaultwarden's, read from the environment first and then from `config.json` in
//! the data folder (the file Vaultwarden's admin page writes, so a server moved with its data folder
//! keeps its Duo and Yubico setup; its names are the lower-case ones):
//!
//! | setting | default |
//! |---|---|
//! | `_ENABLE_EMAIL_2FA` | on when `SMTP_HOST` is set |
//! | `EMAIL_TOKEN_SIZE` | 6 (at least 6) |
//! | `EMAIL_EXPIRATION_TIME` | 600 seconds |
//! | `EMAIL_ATTEMPTS_LIMIT` | 3 |
//! | `_ENABLE_YUBICO` | on; needs `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` (`YUBICO_SERVER` is the verify endpoint, Yubico's by default) |
//! | `_ENABLE_DUO` | on; the global integration needs `DUO_HOST`, `DUO_IKEY` and `DUO_SKEY` |
//!
//! An account that saved Duo keys of its own uses those; one moved from Vaultwarden without any uses
//! the global ones.

use crate::app::RunError;
use crate::config::Config;
use kemlock_api_bw::TwoStepParts;
use kemlock_api_kem::TwoStepRuntime;
use kemlock_app::notices::Notices;
use kemlock_app::two_step::{Duo, DuoKeys, NoYubico, TwoStepSettings, Yubico};
use kemlock_identity::{DuoClient, YubicoClient};
use kemlock_notify::mail::SmtpConfig;
use kemlock_store_sql::SqlStore;
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::Arc;

/// The lowest number of digits Vaultwarden accepts for an emailed code.
const MIN_TOKEN_SIZE: u8 = 6;

/// A setting's text: a string that isn't blank, or a number or boolean written as one.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `config.json` of the data folder as Vaultwarden writes it: one object of lower-case names.
/// A missing file is no settings; one that can't be read is said so and ignored.
fn read_config_json(data_folder: &Path) -> Map<String, Value> {
    let path = data_folder.join("config.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Map::new();
    };
    match serde_json::from_str::<Value>(&content) {
        Ok(Value::Object(map)) => map
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect(),
        _ => {
            tracing::warn!(path = %path.display(), "config.json isn't a JSON object; its two-step settings are not read");
            Map::new()
        }
    }
}

/// A lookup that asks the environment first and then `file`, by the setting's name.
fn layered<'a>(
    env: &'a dyn Fn(&str) -> Option<String>,
    file: &'a Map<String, Value>,
) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| {
        env(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .or_else(|| file.get(&name.to_ascii_lowercase()).and_then(text))
    }
}

fn flag(get: &dyn Fn(&str) -> Option<String>, name: &'static str) -> Result<Option<bool>, String> {
    match get(name) {
        None => Ok(None),
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(Some(true)),
            "false" | "0" | "no" | "off" => Ok(Some(false)),
            _ => Err(format!("{name} must be true or false, not {value:?}")),
        },
    }
}

fn number<T: std::str::FromStr>(
    get: &dyn Fn(&str) -> Option<String>,
    name: &'static str,
    default: T,
) -> Result<T, String> {
    match get(name) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .map_err(|_| format!("{name} must be a number, not {value:?}")),
    }
}

/// The settings of the second steps from a lookup. `mail_configured` says whether the server can
/// send mail, which turns emailed codes on unless `_ENABLE_EMAIL_2FA` says otherwise.
pub fn settings_from(
    get: &dyn Fn(&str) -> Option<String>,
    mail_configured: bool,
) -> Result<TwoStepSettings, String> {
    let email_enabled = flag(get, "_ENABLE_EMAIL_2FA")?.unwrap_or(mail_configured);
    let email_token_size = number(get, "EMAIL_TOKEN_SIZE", 6u8)?;
    if email_enabled && email_token_size < MIN_TOKEN_SIZE {
        return Err(format!(
            "EMAIL_TOKEN_SIZE must be at least {MIN_TOKEN_SIZE}"
        ));
    }
    let yubico_enabled = flag(get, "_ENABLE_YUBICO")?.unwrap_or(true)
        && get("YUBICO_CLIENT_ID").is_some()
        && get("YUBICO_SECRET_KEY").is_some();
    let duo_global = if flag(get, "_ENABLE_DUO")?.unwrap_or(true) {
        match (get("DUO_HOST"), get("DUO_IKEY"), get("DUO_SKEY")) {
            (Some(host), Some(ik), Some(sk)) => Some(DuoKeys { host, ik, sk }),
            _ => None,
        }
    } else {
        None
    };
    Ok(TwoStepSettings {
        email_enabled,
        email_token_size,
        email_expiration_secs: number(get, "EMAIL_EXPIRATION_TIME", 600u32)?,
        email_attempts_limit: number(get, "EMAIL_ATTEMPTS_LIMIT", 3u8)?,
        yubico_enabled,
        duo_global,
    })
}

/// What both APIs are given for the second steps.
pub struct TwoStepWiring {
    pub settings: TwoStepSettings,
    pub notices: Notices,
    pub yubico: Arc<dyn Yubico>,
    pub duo: Arc<dyn Duo>,
}

impl std::fmt::Debug for TwoStepWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoStepWiring")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl TwoStepWiring {
    /// For the Bitwarden API.
    pub fn bitwarden(&self) -> TwoStepParts {
        TwoStepParts {
            settings: self.settings.clone(),
            notices: self.notices.clone(),
            yubico: self.yubico.clone(),
            duo: self.duo.clone(),
        }
    }

    /// For the Kemlock API's routes.
    pub fn runtime(&self, store: SqlStore) -> TwoStepRuntime<SqlStore> {
        TwoStepRuntime {
            challenges: store,
            notices: self.notices.clone(),
            yubico: self.yubico.clone(),
            duo: self.duo.clone(),
            settings: self.settings.clone(),
        }
    }
}

/// Reads the settings and makes the clients. `notices` is the sender the mail goes out through.
pub fn wire(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
    notices: Notices,
) -> Result<TwoStepWiring, RunError> {
    let file = read_config_json(&config.data_folder);
    let get = layered(env, &file);
    // Mail is set up from the environment alone, so a code is only offered when one can go out.
    let mail = matches!(SmtpConfig::from_lookup(env), Ok(Some(_)));
    let mut settings = settings_from(&get, mail)
        .map_err(|e| RunError::Config(format!("two-step settings: {e}")))?;

    let yubico: Arc<dyn Yubico> = if settings.yubico_enabled {
        match YubicoClient::new(
            &get("YUBICO_CLIENT_ID").unwrap_or_default(),
            &get("YUBICO_SECRET_KEY").unwrap_or_default(),
            get("YUBICO_SERVER").as_deref(),
        ) {
            Ok(client) => Arc::new(client),
            Err(why) => {
                tracing::warn!(%why, "YubiKeys are off: Yubico isn't set up correctly");
                settings.yubico_enabled = false;
                Arc::new(NoYubico)
            }
        }
    } else {
        Arc::new(NoYubico)
    };
    let duo = DuoClient::new(&config.domain)
        .map_err(|e| RunError::Config(format!("DOMAIN (Duo): {e}")))?;
    if settings.email_enabled {
        tracing::info!("emailed two-step codes are on");
    }
    Ok(TwoStepWiring {
        settings,
        notices,
        yubico,
        duo: Arc::new(duo),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn lookup<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        move |name| map.get(name).map(|v| (*v).to_owned())
    }

    #[test]
    fn nothing_is_offered_without_settings_but_the_defaults() {
        let settings = settings_from(&lookup(&[]), false).expect("valid");
        assert_eq!(settings, TwoStepSettings::default());
        assert_eq!(settings.email_token_size, 6);
        assert_eq!(settings.email_expiration_secs, 600);
        assert_eq!(settings.email_attempts_limit, 3);
    }

    #[test]
    fn emailed_codes_follow_the_mailer_unless_set() {
        assert!(
            settings_from(&lookup(&[]), true)
                .expect("valid")
                .email_enabled
        );
        assert!(
            !settings_from(&lookup(&[("_ENABLE_EMAIL_2FA", "false")]), true)
                .expect("valid")
                .email_enabled
        );
        assert!(
            settings_from(&lookup(&[("_ENABLE_EMAIL_2FA", "true")]), false)
                .expect("valid")
                .email_enabled
        );
        let tuned = settings_from(
            &lookup(&[
                ("EMAIL_TOKEN_SIZE", "8"),
                ("EMAIL_EXPIRATION_TIME", "120"),
                ("EMAIL_ATTEMPTS_LIMIT", "5"),
            ]),
            true,
        )
        .expect("valid");
        assert_eq!(
            (
                tuned.email_token_size,
                tuned.email_expiration_secs,
                tuned.email_attempts_limit
            ),
            (8, 120, 5)
        );
    }

    #[test]
    fn bad_values_are_said_so() {
        let short = settings_from(&lookup(&[("EMAIL_TOKEN_SIZE", "4")]), true).expect_err("short");
        assert!(short.contains("at least 6"), "{short}");
        // A short size doesn't matter while codes are off.
        assert!(settings_from(&lookup(&[("EMAIL_TOKEN_SIZE", "4")]), false).is_ok());
        let flag = settings_from(&lookup(&[("_ENABLE_DUO", "maybe")]), false).expect_err("flag");
        assert!(flag.contains("_ENABLE_DUO"), "{flag}");
        let count =
            settings_from(&lookup(&[("EMAIL_ATTEMPTS_LIMIT", "many")]), false).expect_err("count");
        assert!(count.contains("EMAIL_ATTEMPTS_LIMIT"), "{count}");
    }

    #[test]
    fn yubikeys_need_both_halves_of_the_yubico_account() {
        let id = ("YUBICO_CLIENT_ID", "12345");
        let key = ("YUBICO_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert!(
            !settings_from(&lookup(&[id]), false)
                .expect("valid")
                .yubico_enabled
        );
        assert!(
            !settings_from(&lookup(&[key]), false)
                .expect("valid")
                .yubico_enabled
        );
        assert!(
            settings_from(&lookup(&[id, key]), false)
                .expect("valid")
                .yubico_enabled
        );
        assert!(
            !settings_from(&lookup(&[id, key, ("_ENABLE_YUBICO", "false")]), false)
                .expect("valid")
                .yubico_enabled
        );
    }

    #[test]
    fn the_global_duo_integration_needs_all_three_parts() {
        let host = ("DUO_HOST", "api-1234.duosecurity.com");
        let ik = ("DUO_IKEY", "DIXXXXXXXXXXXXXXXXXX");
        let sk = ("DUO_SKEY", "secret");
        assert_eq!(
            settings_from(&lookup(&[host, ik]), false)
                .expect("valid")
                .duo_global,
            None
        );
        let global = settings_from(&lookup(&[host, ik, sk]), false)
            .expect("valid")
            .duo_global
            .expect("an integration");
        assert_eq!(
            (global.host.as_str(), global.ik.as_str(), global.sk.as_str()),
            ("api-1234.duosecurity.com", "DIXXXXXXXXXXXXXXXXXX", "secret")
        );
        assert_eq!(
            settings_from(&lookup(&[host, ik, sk, ("_ENABLE_DUO", "false")]), false)
                .expect("valid")
                .duo_global,
            None
        );
    }

    #[test]
    fn the_environment_wins_over_config_json_which_fills_what_it_leaves() {
        let file = match json!({
            "duo_host": "api-file.duosecurity.com",
            "duo_ikey": "DIFILE",
            "duo_skey": "file-secret",
            "email_token_size": 8,
            "_enable_email_2fa": true,
            "yubico_client_id": 12345,
            "yubico_secret_key": ""
        }) {
            Value::Object(map) => map,
            other => panic!("an object, got {other}"),
        };
        let env = lookup(&[("DUO_HOST", "api-env.duosecurity.com")]);
        let get = layered(&env, &file);
        let settings = settings_from(&get, false).expect("valid");
        let duo = settings.duo_global.expect("an integration");
        assert_eq!(duo.host, "api-env.duosecurity.com");
        assert_eq!(
            (duo.ik.as_str(), duo.sk.as_str()),
            ("DIFILE", "file-secret")
        );
        assert_eq!(settings.email_token_size, 8);
        assert!(settings.email_enabled);
        // A number is read as text; an empty string is no value at all.
        assert_eq!(get("YUBICO_CLIENT_ID").as_deref(), Some("12345"));
        assert_eq!(get("YUBICO_SECRET_KEY"), None);
        assert!(!settings.yubico_enabled);
    }

    #[test]
    fn config_json_is_read_from_the_data_folder_by_its_lower_case_names() {
        let dir = tempfile::tempdir().expect("a temp folder");
        assert!(read_config_json(dir.path()).is_empty());
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"DUO_IKEY": "DIFILE", "duo_host": "h", "smtp_host": null}"#,
        )
        .expect("writes");
        let file = read_config_json(dir.path());
        assert_eq!(file.get("duo_ikey"), Some(&json!("DIFILE")));
        assert_eq!(
            layered(&lookup(&[]), &file)("DUO_HOST").as_deref(),
            Some("h")
        );
        std::fs::write(dir.path().join("config.json"), "not json").expect("writes");
        assert!(read_config_json(dir.path()).is_empty());
    }
}
