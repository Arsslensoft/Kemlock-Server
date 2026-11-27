//! `config.json` into Kemlock Server's settings.
//!
//! Vaultwarden's admin page saves the settings an admin changed into `<data>/config.json`, as one
//! JSON object keyed by the lower-case names of its environment variables (`signups_allowed`,
//! `smtp_host`, ...). Only the names on [`CARRIED_SETTINGS`] are carried, by those names, which
//! Kemlock reads too. Everything else is left out and listed as ignored, so a `config.json` can
//! never set a Kemlock-only security, backup, push or federation setting (the source is not
//! trusted to do that). Besides that:
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

/// The settings of a `config.json` that are carried over: genuine Vaultwarden setting names whose
/// meaning is the same here, and nothing else. A move reads a file written by another program, and
/// Kemlock's own security, backup, push and federation settings (`federation_promotion`,
/// `bw_invites_auto_accept`, `backup_recipient`, `push_relay_uri`, ...) must never be set by it,
/// even when the name happens to be one Kemlock has. The plan shows each value carried and the
/// move's audit entries name each one.
pub const CARRIED_SETTINGS: &[&str] = &[
    "signups_allowed",
    "signups_verify",
    "signups_domains_whitelist",
    "invitations_allowed",
    "smtp_host",
    "smtp_port",
    "smtp_security",
    "smtp_username",
    "smtp_from",
    "smtp_from_name",
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
        } else if CARRIED_SETTINGS.contains(&key.as_str()) {
            out.values.insert(key, value);
        } else if !is_blank(&value) {
            // Not a setting a source may set here: left out, and listed so the plan says so.
            out.ignored.push(key);
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
    fn only_the_listed_settings_are_carried_and_never_secrets_or_the_admin_token() {
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
            vec![
                "admin_token",
                "database_url",
                "domain",
                "enable_websocket",
                "org_events_enabled"
            ]
        );
        // No value of a secret or the admin token is anywhere in the output.
        let printed = format!("{mapped:?}");
        for leaked in ["hunter2", "argon2id", "abc"] {
            assert!(!printed.contains(leaked), "{leaked}");
        }
    }

    #[test]
    fn kemlock_only_settings_in_a_config_file_are_never_carried() {
        let config = r#"{
            "signups_allowed": true,
            "federation_promotion": "auto",
            "bw_invites_auto_accept": true,
            "backup_recipient": "age1attacker",
            "backup_destination": "s3://evil",
            "push_relay_uri": "https://evil.example",
            "push_enabled": true,
            "kemlock_push_relay_url": "https://evil.example",
            "space_chain_external_changes": "unchained",
            "rate_sign_in_per_minute": 1000,
            "SECURITY_CONTACT": "evil@example.org",
            "backup_keep": ""
        }"#;
        let mapped = map_settings(Some(config)).expect("maps");
        assert_eq!(
            mapped.values.keys().collect::<Vec<_>>(),
            vec!["signups_allowed"]
        );
        for name in [
            "federation_promotion",
            "bw_invites_auto_accept",
            "backup_recipient",
            "backup_destination",
            "push_relay_uri",
            "push_enabled",
            "kemlock_push_relay_url",
            "space_chain_external_changes",
            "rate_sign_in_per_minute",
            "security_contact",
        ] {
            assert!(mapped.ignored.contains(&name.to_owned()), "{name}");
        }
        // A blank one is not worth listing.
        assert!(!mapped.ignored.contains(&"backup_keep".to_owned()));
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
