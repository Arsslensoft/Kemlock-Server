//! Configuration: environment variables first (Vaultwarden's names, so an existing compose file
//! mostly works), then an optional TOML file, then defaults. The settings the admin console saves
//! rank after the file and before the defaults, and are read by `live`, which also reads the
//! settings the file sets under the console's names (`trash_days`, `smtp_host`, …).
//!
//! Read: `DOMAIN`, `DATABASE_URL`, `DATA_FOLDER`, `ROCKET_ADDRESS`, `ROCKET_PORT`,
//! `SIGNUPS_ALLOWED`, `LOG_LEVEL` and `IP_HEADER` from Vaultwarden; `KEMLOCK_CONFIG` (the TOML
//! file, default `<DATA_FOLDER>/kemlock.toml`), `KEMLOCK_LOG_FORMAT` (`text` or `json`),
//! `KEMLOCK_TRUSTED_PROXIES` (comma-separated addresses), `KEMLOCK_BROWSER_EXTENSION_IDS`
//! (comma-separated ids of the Kemlock browser extensions that may take an SSO code),
//! `KEMLOCK_FEDERATION_PROBE_SECONDS` (how often peers are probed, default 60, 0 is off),
//! `KEMLOCK_SOURCE_URL` (where the source
//! of the running code is offered, see `source`) and `KEMLOCK_SERVER_KEY` (see `keys`) of
//! Kemlock's own. A Vaultwarden name with no use here, such as `ADMIN_TOKEN`, is listed in
//! [`Config::ignored`] so it can be logged once.
//!
//! The TOML file uses the lower-case names without the `KEMLOCK_` prefix: `domain`,
//! `database_url`, `data_folder`, `address` (or `rocket_address`), `port` (or `rocket_port`),
//! `signups_allowed`, `log_level`, `log_format`, `trusted_proxies`, `ip_header`, `browser_extension_ids`, `source_url` and `federation_probe_seconds`.

use kemlock_app::admin::settings::DEFINITIONS;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Vaultwarden settings that Kemlock Server has no use for, or doesn't support yet. Each one that
/// is set gets one line in the log.
pub const IGNORED_VAULTWARDEN_VARS: &[&str] = &[
    "ADMIN_TOKEN",
    "DISABLE_ADMIN_TOKEN",
    "ENABLE_WEBSOCKET",
    "WEBSOCKET_ENABLED",
    "WEBSOCKET_ADDRESS",
    "WEBSOCKET_PORT",
    "ROCKET_WORKERS",
    "ROCKET_TLS",
    "LOG_FILE",
];

/// How many connections the server serves at once unless `KEMLOCK_MAX_CONNECTIONS` says otherwise.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{name} must be {expected}, not {value:?}")]
    Bad {
        name: &'static str,
        expected: &'static str,
        value: String,
    },
    #[error("can't read the config file {path}: {message}")]
    File { path: String, message: String },
    #[error("the config file {path} isn't valid: {message}")]
    Toml { path: String, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `DOMAIN`: the address clients use. Defaults to `http://localhost:<port>`.
    pub domain: String,
    /// `DATABASE_URL`: `sqlite://…`, `postgres://…` or `mysql://…`; a bare path is a SQLite file,
    /// as in Vaultwarden. Defaults to `<DATA_FOLDER>/db.sqlite3`.
    pub database_url: String,
    /// `DATA_FOLDER`, default `data`: `server.key`, the sealed setup files and the SQLite file.
    pub data_folder: PathBuf,
    /// `ROCKET_ADDRESS`, default `::` (every interface, IPv6 and IPv4).
    pub address: String,
    /// `ROCKET_PORT`, default 8080.
    pub port: u16,
    /// `SIGNUPS_ALLOWED`, default false.
    pub signups_allowed: bool,
    /// `LOG_LEVEL`, default `info`: a level or a `tracing` filter.
    pub log_level: String,
    /// `KEMLOCK_LOG_FORMAT`, default text.
    pub log_format: LogFormat,
    /// `KEMLOCK_SERVER_KEY`: the server key itself (hex or base64url), instead of the file.
    pub server_key: Option<String>,
    /// `KEMLOCK_TRUSTED_PROXIES`.
    pub trusted_proxies: Vec<IpAddr>,
    /// `IP_HEADER`.
    pub ip_header: Option<String>,
    /// `KEMLOCK_BROWSER_EXTENSION_IDS`: the ids of the Kemlock browser extensions whose redirect
    /// addresses (`https://<id>.chromiumapp.org/`, `https://<hash>.extensions.allizom.org/`) a
    /// `KemlockBrowser` device may use for SSO, lower case. Default empty: none may.
    pub browser_extension_ids: Vec<String>,
    /// `KEMLOCK_SOURCE_URL`: where the Corresponding Source of the code this server runs can be
    /// had, when it isn't the project's own (AGPL-3.0 section 13). `None` offers the project's
    /// repository at the commit or release this build is from (see `source`).
    pub source_url: Option<String>,
    /// `KEMLOCK_FEDERATION_PROBE_SECONDS`: how often this server probes each paired peer's health, in
    /// seconds; 0 turns the probes off. Default 60. Failed probes back off up to ten minutes.
    pub federation_probe_seconds: u64,
    /// `KEMLOCK_MAX_CONNECTIONS`: how many connections the server serves at once; further ones wait
    /// in the operating system's queue until one ends. 0 turns the limit off. Default 1024.
    pub max_connections: usize,
    /// Vaultwarden settings that were set and are not used.
    pub ignored: Vec<String>,
    /// The TOML file that was read, if any.
    pub config_file: Option<PathBuf>,
    /// The variables the admin console's settings can be set by (`SIGNUPS_ALLOWED`,
    /// `SMTP_HOST`, the rate limits, ...) that were set in the sources this was read from. `live`
    /// layers them over the file and the saved settings, so they follow the sources and not the
    /// process environment: the two are the same for `kemlock-server`, but not for a server
    /// started inside another process.
    pub settings_env: BTreeMap<String, String>,
    /// The Bitwarden API's own variables (`KEMLOCK_BITWARDEN_COMPAT` and Vaultwarden's rate
    /// limits) as `env` sets them, read through the same lookup for the same reason.
    pub bitwarden_env: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    domain: Option<String>,
    database_url: Option<String>,
    data_folder: Option<String>,
    #[serde(alias = "rocket_address")]
    address: Option<String>,
    #[serde(alias = "rocket_port")]
    port: Option<u16>,
    signups_allowed: Option<bool>,
    log_level: Option<String>,
    log_format: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    ip_header: Option<String>,
    browser_extension_ids: Option<Vec<String>>,
    source_url: Option<String>,
    federation_probe_seconds: Option<u64>,
    max_connections: Option<usize>,
}

fn parse_bool(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Bad {
            name,
            expected: "true or false",
            value: value.to_owned(),
        }),
    }
}

fn parse_port(value: &str) -> Result<u16, ConfigError> {
    value.trim().parse().map_err(|_| ConfigError::Bad {
        name: "ROCKET_PORT",
        expected: "a port number",
        value: value.to_owned(),
    })
}

fn parse_proxies<'a>(items: impl IntoIterator<Item = &'a str>) -> Result<Vec<IpAddr>, ConfigError> {
    items
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse().map_err(|_| ConfigError::Bad {
                name: "KEMLOCK_TRUSTED_PROXIES",
                expected: "a list of IP addresses",
                value: s.to_owned(),
            })
        })
        .collect()
}

/// `KEMLOCK_BROWSER_EXTENSION_IDS`: extension ids, each 1 to 64 letters and digits (a Chrome id is 32
/// letters, a Firefox hash 40 hex digits), so a dot, a slash or a scheme can't widen what they
/// allow. Lower-cased, deduplicated, blanks skipped.
fn parse_extension_ids<'a>(
    items: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, ConfigError> {
    let mut ids: Vec<String> = Vec::new();
    for item in items.into_iter().map(str::trim).filter(|s| !s.is_empty()) {
        if item.len() > 64 || !item.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ConfigError::Bad {
                name: "KEMLOCK_BROWSER_EXTENSION_IDS",
                expected: "a list of extension ids (letters and digits)",
                value: item.to_owned(),
            });
        }
        let id = item.to_ascii_lowercase();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// `KEMLOCK_SOURCE_URL`: an `http://` or `https://` address with no blanks or control characters,
/// since clients put it in a link and the web vault sends the person there.
fn parse_source_url(value: &str) -> Result<String, ConfigError> {
    let value = value.trim();
    let scheme_ok = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .is_some_and(|rest| !rest.is_empty());
    if !scheme_ok || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ConfigError::Bad {
            name: "KEMLOCK_SOURCE_URL",
            expected: "an http:// or https:// address",
            value: value.to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn parse_log_format(value: &str) -> Result<LogFormat, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        _ => Err(ConfigError::Bad {
            name: "KEMLOCK_LOG_FORMAT",
            expected: "text or json",
            value: value.to_owned(),
        }),
    }
}

/// Vaultwarden's `DATABASE_URL` is often a bare SQLite path; the store wants a URL.
fn database_url(raw: &str) -> String {
    let raw = raw.trim();
    if raw.contains("://") || raw.starts_with("sqlite:") {
        raw.to_owned()
    } else {
        format!("sqlite://{raw}?mode=rwc")
    }
}

/// An environment lookup that treats an empty value as unset.
fn lookup(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name).filter(|v| !v.trim().is_empty())
}

/// The Bitwarden API's variables that `env` sets.
pub fn bitwarden_env(env: &dyn Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    kemlock_api_bw::ENV_VARS
        .iter()
        .filter_map(|name| env(name).map(|v| ((*name).to_owned(), v)))
        .collect()
}

/// The settings' variables that `env` sets.
pub fn settings_env(env: &dyn Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    DEFINITIONS
        .iter()
        .filter_map(|d| lookup(env, d.env).map(|v| (d.env.to_owned(), v)))
        .collect()
}

/// Where the TOML file is: `KEMLOCK_CONFIG`, else `kemlock.toml` in the data folder.
pub fn config_file_path(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    match lookup(env, "KEMLOCK_CONFIG") {
        Some(path) => PathBuf::from(path),
        None => Path::new(&lookup(env, "DATA_FOLDER").unwrap_or_else(|| "data".to_owned()))
            .join("kemlock.toml"),
    }
}

impl Config {
    /// Reads the process environment and the TOML file, if there is one.
    pub fn load() -> Result<Config, ConfigError> {
        let env = |name: &str| std::env::var(name).ok();
        let path = config_file_path(&env);
        let (text, file) = match std::fs::read_to_string(&path) {
            Ok(text) => (Some(text), Some(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(e) => {
                return Err(ConfigError::File {
                    path: path.display().to_string(),
                    message: e.to_string(),
                });
            }
        };
        let mut config =
            Config::from_sources(&env, text.as_deref()).map_err(|e| match (e, &file) {
                (ConfigError::Toml { message, .. }, Some(path)) => ConfigError::Toml {
                    path: path.display().to_string(),
                    message,
                },
                (other, _) => other,
            })?;
        config.config_file = file;
        Ok(config)
    }

    /// Builds the configuration from an environment lookup and the TOML file's text. Environment
    /// wins over the file, which wins over the defaults.
    pub fn from_sources(
        env: &dyn Fn(&str) -> Option<String>,
        file: Option<&str>,
    ) -> Result<Config, ConfigError> {
        let file: FileConfig = match file {
            None => FileConfig::default(),
            Some(text) => toml::from_str(text).map_err(|e| ConfigError::Toml {
                path: String::new(),
                message: e.to_string(),
            })?,
        };

        let data_folder = PathBuf::from(
            lookup(env, "DATA_FOLDER")
                .or(file.data_folder)
                .unwrap_or_else(|| "data".to_owned()),
        );
        let port = match lookup(env, "ROCKET_PORT") {
            Some(value) => parse_port(&value)?,
            None => file.port.unwrap_or(8080),
        };
        let address = lookup(env, "ROCKET_ADDRESS")
            .or(file.address)
            .unwrap_or_else(|| "::".to_owned());
        let domain = lookup(env, "DOMAIN")
            .or(file.domain)
            .unwrap_or_else(|| format!("http://localhost:{port}"))
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let database_url = match lookup(env, "DATABASE_URL").or(file.database_url) {
            Some(raw) => database_url(&raw),
            None => database_url(&data_folder.join("db.sqlite3").display().to_string()),
        };
        let signups_allowed = match lookup(env, "SIGNUPS_ALLOWED") {
            Some(value) => parse_bool("SIGNUPS_ALLOWED", &value)?,
            None => file.signups_allowed.unwrap_or(false),
        };
        let log_format = match lookup(env, "KEMLOCK_LOG_FORMAT").or(file.log_format) {
            Some(value) => parse_log_format(&value)?,
            None => LogFormat::Text,
        };
        let trusted_proxies = match lookup(env, "KEMLOCK_TRUSTED_PROXIES") {
            Some(value) => parse_proxies(value.split(','))?,
            None => parse_proxies(file.trusted_proxies.iter().flatten().map(String::as_str))?,
        };
        let browser_extension_ids = match lookup(env, "KEMLOCK_BROWSER_EXTENSION_IDS") {
            Some(value) => parse_extension_ids(value.split(','))?,
            None => parse_extension_ids(
                file.browser_extension_ids
                    .iter()
                    .flatten()
                    .map(String::as_str),
            )?,
        };
        let source_url = lookup(env, "KEMLOCK_SOURCE_URL")
            .or(file.source_url.filter(|v| !v.trim().is_empty()))
            .map(|value| parse_source_url(&value))
            .transpose()?;
        let federation_probe_seconds = match lookup(env, "KEMLOCK_FEDERATION_PROBE_SECONDS") {
            Some(value) => value.trim().parse().map_err(|_| ConfigError::Bad {
                name: "KEMLOCK_FEDERATION_PROBE_SECONDS",
                expected: "a number of seconds, 0 to turn the probes off",
                value: value.clone(),
            })?,
            None => file.federation_probe_seconds.unwrap_or(60),
        };
        let max_connections = match lookup(env, "KEMLOCK_MAX_CONNECTIONS") {
            Some(value) => value.trim().parse().map_err(|_| ConfigError::Bad {
                name: "KEMLOCK_MAX_CONNECTIONS",
                expected: "a number of connections, 0 for no limit",
                value: value.clone(),
            })?,
            None => file.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        };
        let ignored = IGNORED_VAULTWARDEN_VARS
            .iter()
            .filter(|name| lookup(env, name).is_some())
            .map(|name| (*name).to_owned())
            .collect();

        let settings_env = settings_env(env);
        let bitwarden_env = bitwarden_env(env);

        Ok(Config {
            domain,
            database_url,
            data_folder,
            address,
            port,
            signups_allowed,
            log_level: lookup(env, "LOG_LEVEL")
                .or(file.log_level)
                .unwrap_or_else(|| "info".to_owned()),
            log_format,
            server_key: lookup(env, "KEMLOCK_SERVER_KEY"),
            trusted_proxies,
            ip_header: lookup(env, "IP_HEADER").or(file.ip_header),
            browser_extension_ids,
            source_url,
            federation_probe_seconds,
            max_connections,
            ignored,
            config_file: None,
            settings_env,
            bitwarden_env,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)], file: Option<&str>) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_sources(&|name| map.get(name).cloned(), file)
    }

    #[test]
    fn defaults() {
        let c = config(&[], None).expect("defaults are valid");
        assert_eq!(c.domain, "http://localhost:8080");
        assert_eq!(c.data_folder, PathBuf::from("data"));
        assert_eq!(c.database_url, "sqlite://data/db.sqlite3?mode=rwc");
        assert_eq!(c.address, "::");
        assert_eq!(c.port, 8080);
        assert!(!c.signups_allowed);
        assert_eq!(c.log_level, "info");
        assert_eq!(c.log_format, LogFormat::Text);
        assert_eq!(c.server_key, None);
        assert!(c.trusted_proxies.is_empty());
        assert!(c.ignored.is_empty());
    }

    #[test]
    fn the_settings_variables_are_kept_for_the_live_settings() {
        let c = config(
            &[
                ("SIGNUPS_ALLOWED", "true"),
                ("SMTP_HOST", "  "),
                ("DOMAIN", "https://vault.example.org"),
            ],
            None,
        )
        .expect("valid");
        assert_eq!(
            c.settings_env.get("SIGNUPS_ALLOWED").map(String::as_str),
            Some("true")
        );
        // An empty value is unset, and a name that is no setting is not kept
        assert!(!c.settings_env.contains_key("SMTP_HOST"));
        assert!(!c.settings_env.contains_key("DOMAIN"));
    }

    #[test]
    fn vaultwarden_names_are_read() {
        let c = config(
            &[
                ("DOMAIN", "https://vault.example.org/"),
                ("DATABASE_URL", "postgres://u:p@db/kemlock"),
                ("DATA_FOLDER", "/data"),
                ("ROCKET_ADDRESS", "127.0.0.1"),
                ("ROCKET_PORT", "8000"),
                ("SIGNUPS_ALLOWED", "TRUE"),
                ("LOG_LEVEL", "debug"),
                ("IP_HEADER", "X-Forwarded-For"),
            ],
            None,
        )
        .expect("valid");
        assert_eq!(c.domain, "https://vault.example.org");
        assert_eq!(c.database_url, "postgres://u:p@db/kemlock");
        assert_eq!(c.data_folder, PathBuf::from("/data"));
        assert_eq!(c.address, "127.0.0.1");
        assert_eq!(c.port, 8000);
        assert!(c.signups_allowed);
        assert_eq!(c.log_level, "debug");
        assert_eq!(c.ip_header.as_deref(), Some("X-Forwarded-For"));
    }

    #[test]
    fn the_default_domain_follows_the_port() {
        let c = config(&[("ROCKET_PORT", "9090")], None).expect("valid");
        assert_eq!(c.domain, "http://localhost:9090");
    }

    #[test]
    fn a_bare_database_path_is_a_sqlite_file_as_in_vaultwarden() {
        let c = config(&[("DATABASE_URL", "data/db.sqlite3")], None).expect("valid");
        assert_eq!(c.database_url, "sqlite://data/db.sqlite3?mode=rwc");
        let memory = config(&[("DATABASE_URL", "sqlite::memory:")], None).expect("valid");
        assert_eq!(memory.database_url, "sqlite::memory:");
    }

    #[test]
    fn empty_variables_count_as_unset() {
        let c = config(&[("DOMAIN", ""), ("ROCKET_PORT", " ")], None).expect("valid");
        assert_eq!(c.domain, "http://localhost:8080");
    }

    #[test]
    fn the_toml_file_fills_what_the_environment_leaves() {
        let file = r#"
            domain = "https://from-file.example.org"
            port = 9000
            rocket_address = "0.0.0.0"
            signups_allowed = true
            log_format = "json"
            trusted_proxies = ["10.0.0.1", "::1"]
            ip_header = "X-Real-IP"
            unknown_key = 1
        "#;
        let c = config(&[], Some(file)).expect("valid");
        assert_eq!(c.domain, "https://from-file.example.org");
        assert_eq!(c.port, 9000);
        assert_eq!(c.address, "0.0.0.0");
        assert!(c.signups_allowed);
        assert_eq!(c.log_format, LogFormat::Json);
        assert_eq!(c.trusted_proxies.len(), 2);
        assert_eq!(c.ip_header.as_deref(), Some("X-Real-IP"));
    }

    #[test]
    fn the_environment_wins_over_the_file() {
        let file = "domain = \"https://file.example.org\"\nport = 9000\nsignups_allowed = true\n";
        let c = config(
            &[
                ("DOMAIN", "https://env.example.org"),
                ("SIGNUPS_ALLOWED", "false"),
            ],
            Some(file),
        )
        .expect("valid");
        assert_eq!(c.domain, "https://env.example.org");
        assert!(!c.signups_allowed);
        assert_eq!(
            c.port, 9000,
            "the file still fills what the environment doesn't"
        );
    }

    #[test]
    fn bad_values_say_which_setting() {
        for (name, value) in [
            ("ROCKET_PORT", "eighty"),
            ("ROCKET_PORT", "70000"),
            ("SIGNUPS_ALLOWED", "maybe"),
            ("KEMLOCK_LOG_FORMAT", "yaml"),
            ("KEMLOCK_TRUSTED_PROXIES", "10.0.0.1, nope"),
        ] {
            let error = config(&[(name, value)], None).expect_err("refused");
            assert!(error.to_string().contains(name), "{name}: {error}");
        }
        assert!(matches!(
            config(&[], Some("port = [")),
            Err(ConfigError::Toml { .. })
        ));
    }

    #[test]
    fn no_browser_extension_is_allowed_by_default() {
        assert!(
            config(&[], None)
                .expect("valid")
                .browser_extension_ids
                .is_empty()
        );
        assert!(
            config(&[("KEMLOCK_BROWSER_EXTENSION_IDS", "  ")], None)
                .expect("valid")
                .browser_extension_ids
                .is_empty()
        );
    }

    #[test]
    fn browser_extension_ids_are_a_comma_list_in_lower_case() {
        let c = config(
            &[(
                "KEMLOCK_BROWSER_EXTENSION_IDS",
                "abcdefghijklmnopabcdefghijklmnop, 0123ABCD ,,0123abcd",
            )],
            None,
        )
        .expect("valid");
        assert_eq!(
            c.browser_extension_ids,
            vec!["abcdefghijklmnopabcdefghijklmnop", "0123abcd"]
        );
    }

    #[test]
    fn browser_extension_ids_come_from_the_file_when_the_environment_has_none() {
        let from_file = config(&[], Some("browser_extension_ids = [\"abc123\"]\n")).expect("valid");
        assert_eq!(from_file.browser_extension_ids, vec!["abc123"]);
        let env_wins = config(
            &[("KEMLOCK_BROWSER_EXTENSION_IDS", "def456")],
            Some("browser_extension_ids = [\"abc123\"]\n"),
        )
        .expect("valid");
        assert_eq!(env_wins.browser_extension_ids, vec!["def456"]);
    }

    #[test]
    fn a_browser_extension_id_that_could_widen_the_allowlist_is_refused() {
        let long = "a".repeat(65);
        for bad in [
            "evil.example",
            "a/b",
            "https://abc.chromiumapp.org/",
            "abc@evil",
            "a b",
            "*",
            long.as_str(),
        ] {
            let error =
                config(&[("KEMLOCK_BROWSER_EXTENSION_IDS", bad)], None).expect_err("refused");
            assert!(
                error.to_string().contains("KEMLOCK_BROWSER_EXTENSION_IDS"),
                "{bad}: {error}"
            );
        }
    }

    #[test]
    fn trusted_proxies_are_a_comma_list() {
        let c = config(
            &[("KEMLOCK_TRUSTED_PROXIES", "10.0.0.1, 192.168.1.2")],
            None,
        )
        .expect("valid");
        assert_eq!(
            c.trusted_proxies,
            vec![
                "10.0.0.1".parse::<IpAddr>().expect("ip"),
                "192.168.1.2".parse::<IpAddr>().expect("ip")
            ]
        );
    }

    #[test]
    fn peers_are_probed_every_minute_unless_the_operator_says_otherwise() {
        assert_eq!(
            config(&[], None).expect("valid").federation_probe_seconds,
            60
        );
        let c = config(&[("KEMLOCK_FEDERATION_PROBE_SECONDS", " 15 ")], None).expect("valid");
        assert_eq!(c.federation_probe_seconds, 15);
        let c = config(&[], Some("federation_probe_seconds = 120\n")).expect("valid");
        assert_eq!(c.federation_probe_seconds, 120);
        // The environment outranks the file, and 0 turns the probes off.
        let c = config(
            &[("KEMLOCK_FEDERATION_PROBE_SECONDS", "0")],
            Some("federation_probe_seconds = 120\n"),
        )
        .expect("valid");
        assert_eq!(c.federation_probe_seconds, 0);
        assert!(matches!(
            config(&[("KEMLOCK_FEDERATION_PROBE_SECONDS", "often")], None),
            Err(ConfigError::Bad {
                name: "KEMLOCK_FEDERATION_PROBE_SECONDS",
                ..
            })
        ));
    }

    #[test]
    fn connections_are_limited_unless_the_operator_says_otherwise() {
        let c = config(&[], None).expect("valid");
        assert_eq!(c.max_connections, DEFAULT_MAX_CONNECTIONS);
        let c = config(&[("KEMLOCK_MAX_CONNECTIONS", " 200 ")], None).expect("valid");
        assert_eq!(c.max_connections, 200);
        let c = config(&[], Some("max_connections = 300\n")).expect("valid");
        assert_eq!(c.max_connections, 300);
        // The environment outranks the file, and 0 turns the limit off.
        let c = config(
            &[("KEMLOCK_MAX_CONNECTIONS", "0")],
            Some("max_connections = 300\n"),
        )
        .expect("valid");
        assert_eq!(c.max_connections, 0);
        assert!(matches!(
            config(&[("KEMLOCK_MAX_CONNECTIONS", "many")], None),
            Err(ConfigError::Bad {
                name: "KEMLOCK_MAX_CONNECTIONS",
                ..
            })
        ));
    }

    #[test]
    fn the_source_url_is_unset_unless_the_operator_sets_it() {
        assert_eq!(config(&[], None).expect("valid").source_url, None);
        let c = config(
            &[("KEMLOCK_SOURCE_URL", " https://git.example.org/me/kemlock ")],
            None,
        )
        .expect("valid");
        assert_eq!(
            c.source_url.as_deref(),
            Some("https://git.example.org/me/kemlock")
        );
        let c = config(&[], Some("source_url = \"http://git.lan/kemlock\"\n")).expect("valid");
        assert_eq!(c.source_url.as_deref(), Some("http://git.lan/kemlock"));
        let c = config(&[("KEMLOCK_SOURCE_URL", "")], Some("source_url = \"\"\n")).expect("valid");
        assert_eq!(c.source_url, None, "an empty value counts as unset");
    }

    #[test]
    fn the_source_url_from_the_environment_wins_over_the_file() {
        let c = config(
            &[("KEMLOCK_SOURCE_URL", "https://env.example.org/src")],
            Some("source_url = \"https://file.example.org/src\"\n"),
        )
        .expect("valid");
        assert_eq!(c.source_url.as_deref(), Some("https://env.example.org/src"));
    }

    #[test]
    fn a_source_url_that_is_not_a_web_address_is_refused() {
        for value in [
            "git.example.org/me/kemlock",
            "ftp://git.example.org/kemlock",
            "javascript:alert(1)",
            "https://",
            "https://git.example.org/a b",
            "https://git.example.org/a\nb",
        ] {
            let error = config(&[("KEMLOCK_SOURCE_URL", value)], None).expect_err("refused");
            assert!(
                error.to_string().contains("KEMLOCK_SOURCE_URL"),
                "{value:?}: {error}"
            );
        }
        let error = config(&[], Some("source_url = \"nope\"\n")).expect_err("refused");
        assert!(error.to_string().contains("KEMLOCK_SOURCE_URL"), "{error}");
    }

    #[test]
    fn ignored_vaultwarden_names_are_listed() {
        let c = config(
            &[("ADMIN_TOKEN", "secret"), ("ENABLE_WEBSOCKET", "true")],
            None,
        )
        .expect("valid");
        assert_eq!(c.ignored, vec!["ADMIN_TOKEN", "ENABLE_WEBSOCKET"]);
        assert!(
            !format!("{c:?}").contains("secret"),
            "values are never kept"
        );
    }

    #[test]
    fn the_config_file_is_looked_up_by_env_then_data_folder() {
        let find = |vars: &'static [(&'static str, &'static str)]| {
            config_file_path(&|name| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            })
        };
        assert_eq!(find(&[]), Path::new("data").join("kemlock.toml"));
        assert_eq!(
            find(&[("DATA_FOLDER", "/d")]),
            Path::new("/d").join("kemlock.toml")
        );
        assert_eq!(
            find(&[("DATA_FOLDER", "/d"), ("KEMLOCK_CONFIG", "/etc/k.toml")]),
            PathBuf::from("/etc/k.toml")
        );
    }
}
