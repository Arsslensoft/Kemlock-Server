//! `config.json` into Kemlock Server's settings.
//!
//! Vaultwarden's admin page saves the settings an admin changed into `<data>/config.json`, as one
//! JSON object keyed by the lower-case names of its environment variables (`signups_allowed`,
//! `smtp_host`, ...). They are carried over by those names, which Kemlock reads too, except:
//!
//! - secrets (the settings Vaultwarden types as `Pass`), which Kemlock keeps elsewhere and the
//!   admin enters again. Their names are listed so the plan can say so; their values are never
//!   copied;
//! - `admin_token` and the other settings Kemlock has no use for, which are listed as ignored, so
//!   the server can log each once;
//! - settings about where files live, which belong to the new installation.

use crate::error::MapError;
use serde_json::Value;
use std::collections::BTreeMap;

/// Settings Vaultwarden types as `Pass` in `src/config.rs`: shown as dots in its admin page.
pub const SECRET_SETTINGS: &[&str] = &[
    "hibp_api_key",
    "push_installation_id",
    "push_installation_key",
    "sso_client_secret",
    "yubico_secret_key",
    "duo_skey",
    "smtp_password",
];

/// Settings Kemlock Server has no use for. `ADMIN_TOKEN` is not used: the first run sets up the
/// first admin with a one-time code (design, Decisions, "Admins").
pub const IGNORED_SETTINGS: &[&str] = &[
    "admin_token",
    "disable_admin_token",
    "enable_websocket",
    "websocket_enabled",
    "websocket_address",
    "websocket_port",
    "rocket_workers",
    "rocket_tls",
    "reload_templates",
    "use_syslog",
    "log_file",
];

/// Settings about where the old installation kept its files.
const LOCATION_SETTINGS: &[&str] = &[
    "data_folder",
    "database_url",
    "icon_cache_folder",
    "attachments_folder",
    "sends_folder",
    "tmp_folder",
    "templates_folder",
    "rsa_key_filename",
    "web_vault_folder",
];

/// What `config.json` becomes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MappedSettings {
    /// Setting name (lower case, Vaultwarden's) to its value, ready to be saved as a server
    /// setting.
    pub values: BTreeMap<String, Value>,
    /// Settings that were present and are not used.
    pub ignored: Vec<String>,
    /// Secrets that were present and must be entered again.
    pub secrets: Vec<String>,
}

/// Maps the text of `config.json`; `None` (no file) maps to nothing.
pub fn map_settings(config_json: Option<&str>) -> Result<MappedSettings, MapError> {
    let mut out = MappedSettings::default();
    let Some(text) = config_json else {
        return Ok(out);
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
        return Err(MapError::BadConfig);
    };
    for (name, value) in map {
        let key = name.to_ascii_lowercase();
        if SECRET_SETTINGS.contains(&key.as_str()) {
            // Only a secret that was set is worth entering again.
            if !is_blank(&value) {
                out.secrets.push(key);
            }
        } else if IGNORED_SETTINGS.contains(&key.as_str()) {
            if !is_blank(&value) {
                out.ignored.push(key);
            }
        } else if LOCATION_SETTINGS.contains(&key.as_str()) {
            out.ignored.push(key);
        } else {
            out.values.insert(key, value);
        }
    }
    out.secrets.sort();
    out.ignored.sort();
    Ok(out)
}

fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn settings_are_carried_except_secrets_and_the_admin_token() {
        let config = r#"{
            "domain": "https://vault.example.org",
            "signups_allowed": false,
            "smtp_host": "mail.example.org",
            "smtp_password": "hunter2",
            "sso_client_secret": "abc",
            "push_installation_key": "key",
            "duo_skey": "",
            "admin_token": "$argon2id$v=19$m=65540,t=3,p=4$x",
            "enable_websocket": true,
            "database_url": "mysql://x",
            "org_events_enabled": true
        }"#;
        let mapped = map_settings(Some(config)).expect("maps");
        assert_eq!(
            mapped.values,
            BTreeMap::from([
                ("domain".to_owned(), json!("https://vault.example.org")),
                ("org_events_enabled".to_owned(), json!(true)),
                ("signups_allowed".to_owned(), json!(false)),
                ("smtp_host".to_owned(), json!("mail.example.org")),
            ])
        );
        assert_eq!(
            mapped.secrets,
            vec![
                "push_installation_key",
                "smtp_password",
                "sso_client_secret"
            ]
        );
        assert_eq!(
            mapped.ignored,
            vec!["admin_token", "database_url", "enable_websocket"]
        );
        // No value of a secret or the admin token is anywhere in the output.
        let printed = format!("{mapped:?}");
        for leaked in ["hunter2", "argon2id", "abc"] {
            assert!(!printed.contains(leaked), "{leaked}");
        }
    }

    #[test]
    fn no_file_means_no_settings() {
        assert_eq!(map_settings(None).expect("maps"), MappedSettings::default());
    }

    #[test]
    fn config_that_isnt_an_object_is_refused() {
        assert_eq!(map_settings(Some("[1]")), Err(MapError::BadConfig));
        assert_eq!(map_settings(Some("nope")), Err(MapError::BadConfig));
    }

    #[test]
    fn names_are_matched_case_insensitively() {
        let mapped =
            map_settings(Some(r#"{"ADMIN_TOKEN":"x","Signups_Allowed":true}"#)).expect("maps");
        assert_eq!(mapped.ignored, vec!["admin_token"]);
        assert_eq!(mapped.values.get("signups_allowed"), Some(&json!(true)));
    }
}
