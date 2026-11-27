//! The typed settings store behind the console's Settings screen: SMTP, sign-ups, file limits,
//! the trash, retention and rate limits.
//!
//! Each setting has a name, a type and bounds, written down once in [`DEFINITIONS`]. A value
//! comes from the first of these that has one: the environment (Vaultwarden's variable names
//! where it has one, `KEMLOCK_<NAME>` otherwise), what the console saved, the default. A value
//! the environment sets is shown but can't be changed from the console. Secrets (the SMTP
//! password) are sealed under `server.key` before they are stored and are never read back out:
//! the console learns only that one is set.
//!
//! Saved values live in the `settings` table under `setting.<name>`, as text.

use super::error::AdminError;
use super::ports::SettingsRepo;
use crate::b64url;
use crate::ports::SecretSeal;
use std::collections::BTreeMap;

/// Every saved setting's key in the `settings` table starts with this.
pub const KEY_PREFIX: &str = "setting.";

/// What a setting holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    /// A whole number within the bounds.
    Int {
        min: i64,
        max: i64,
    },
    /// Text of at most this many characters; empty means unset.
    Text {
        max_len: usize,
    },
    /// One of these words.
    Choice(&'static [&'static str]),
    /// Text kept sealed and never shown again.
    Secret,
    /// An email address, or empty for unset.
    Email,
    /// Comma-separated domain names, or empty for none.
    Domains,
}

/// One setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Definition {
    pub key: &'static str,
    /// The console's section: `smtp`, `signups`, `files`, `trash`, `retention`, `rate-limits`, `security`, `federation`.
    pub group: &'static str,
    pub kind: Kind,
    /// The value when nothing sets one; empty for "unset".
    pub default: &'static str,
    /// The environment variable that sets it.
    pub env: &'static str,
}

/// The SMTP security choices, as Vaultwarden spells them.
const SMTP_SECURITY: &[&str] = &["starttls", "force_tls", "off"];

/// How often backups run: `nightly` is 03:00 UTC, `6h` is 03:00, 09:00, 15:00 and 21:00 UTC.
const BACKUP_SCHEDULES: &[&str] = &["off", "nightly", "6h"];

/// Every setting the console can change.
pub const DEFINITIONS: &[Definition] = &[
    Definition {
        key: "smtp_host",
        group: "smtp",
        kind: Kind::Text { max_len: 253 },
        default: "",
        env: "SMTP_HOST",
    },
    Definition {
        key: "smtp_port",
        group: "smtp",
        kind: Kind::Int { min: 1, max: 65535 },
        default: "587",
        env: "SMTP_PORT",
    },
    Definition {
        key: "smtp_security",
        group: "smtp",
        kind: Kind::Choice(SMTP_SECURITY),
        default: "starttls",
        env: "SMTP_SECURITY",
    },
    Definition {
        key: "smtp_username",
        group: "smtp",
        kind: Kind::Text { max_len: 254 },
        default: "",
        env: "SMTP_USERNAME",
    },
    Definition {
        key: "smtp_password",
        group: "smtp",
        kind: Kind::Secret,
        default: "",
        env: "SMTP_PASSWORD",
    },
    Definition {
        key: "smtp_from",
        group: "smtp",
        kind: Kind::Email,
        default: "",
        env: "SMTP_FROM",
    },
    Definition {
        key: "smtp_from_name",
        group: "smtp",
        kind: Kind::Text { max_len: 64 },
        default: "Kemlock Server",
        env: "SMTP_FROM_NAME",
    },
    Definition {
        key: "signups_allowed",
        group: "signups",
        kind: Kind::Bool,
        default: "false",
        env: "SIGNUPS_ALLOWED",
    },
    Definition {
        key: "signups_verify",
        group: "signups",
        kind: Kind::Bool,
        default: "false",
        env: "SIGNUPS_VERIFY",
    },
    Definition {
        key: "bw_invites_auto_accept",
        group: "signups",
        kind: Kind::Bool,
        default: "false",
        env: "KEMLOCK_BW_INVITES_AUTO_ACCEPT",
    },
    Definition {
        key: "signups_domains_whitelist",
        group: "signups",
        kind: Kind::Domains,
        default: "",
        env: "SIGNUPS_DOMAINS_WHITELIST",
    },
    Definition {
        key: "invitations_allowed",
        group: "signups",
        kind: Kind::Bool,
        default: "true",
        env: "INVITATIONS_ALLOWED",
    },
    Definition {
        key: "user_attachment_limit_kib",
        group: "files",
        kind: Kind::Int {
            min: 0,
            max: 1_073_741_824,
        },
        default: "0",
        env: "USER_ATTACHMENT_LIMIT",
    },
    Definition {
        key: "space_attachment_limit_kib",
        group: "files",
        kind: Kind::Int {
            min: 0,
            max: 1_073_741_824,
        },
        default: "0",
        env: "ORG_ATTACHMENT_LIMIT",
    },
    Definition {
        key: "send_file_limit_kib",
        group: "files",
        kind: Kind::Int {
            min: 0,
            max: 1_073_741_824,
        },
        default: "0",
        env: "USER_SEND_LIMIT",
    },
    Definition {
        key: "max_file_size_mib",
        group: "files",
        kind: Kind::Int { min: 1, max: 5120 },
        default: "100",
        env: "KEMLOCK_MAX_FILE_SIZE_MIB",
    },
    Definition {
        key: "trash_days",
        group: "trash",
        kind: Kind::Int { min: 1, max: 365 },
        default: "30",
        env: "TRASH_AUTO_DELETE_DAYS",
    },
    Definition {
        key: "event_log_days",
        group: "retention",
        kind: Kind::Int { min: 90, max: 2557 },
        default: "365",
        env: "EVENTS_DAYS_RETAIN",
    },
    Definition {
        key: "sign_in_log_days",
        group: "retention",
        kind: Kind::Int { min: 7, max: 365 },
        default: "90",
        env: "KEMLOCK_SIGN_IN_LOG_DAYS",
    },
    Definition {
        key: "email_log_days",
        group: "retention",
        kind: Kind::Int { min: 7, max: 90 },
        default: "30",
        env: "KEMLOCK_EMAIL_LOG_DAYS",
    },
    Definition {
        key: "backup_days",
        group: "retention",
        kind: Kind::Int { min: 7, max: 365 },
        default: "30",
        env: "KEMLOCK_BACKUP_DAYS",
    },
    Definition {
        key: "deleted_account_grace_days",
        group: "retention",
        kind: Kind::Int { min: 0, max: 30 },
        default: "0",
        env: "KEMLOCK_DELETED_ACCOUNT_GRACE_DAYS",
    },
    Definition {
        key: "rate_sign_in_per_minute",
        group: "rate-limits",
        kind: Kind::Int { min: 1, max: 1000 },
        default: "10",
        env: "KEMLOCK_RATE_SIGN_IN_PER_MINUTE",
    },
    Definition {
        key: "rate_password_failures_per_15_minutes",
        group: "rate-limits",
        kind: Kind::Int { min: 1, max: 1000 },
        default: "10",
        env: "KEMLOCK_RATE_PASSWORD_FAILURES",
    },
    Definition {
        key: "rate_second_step_failures_per_15_minutes",
        group: "rate-limits",
        kind: Kind::Int { min: 1, max: 1000 },
        default: "5",
        env: "KEMLOCK_RATE_SECOND_STEP_FAILURES",
    },
    Definition {
        key: "rate_second_step_challenges_per_5_minutes",
        group: "rate-limits",
        kind: Kind::Int { min: 1, max: 1000 },
        default: "10",
        env: "KEMLOCK_RATE_SECOND_STEP_CHALLENGES",
    },
    Definition {
        key: "rate_register_per_hour",
        group: "rate-limits",
        kind: Kind::Int { min: 1, max: 1000 },
        default: "10",
        env: "KEMLOCK_RATE_REGISTER_PER_HOUR",
    },
    // Bitwarden's push relay, under Vaultwarden's names (`PUSH_*`), and Kemlock's own relay
    // (`KEMLOCK_PUSH_RELAY*`). The installation id and key are secrets, sealed like the SMTP
    // password. The running server follows them (`live`): no restart.
    Definition {
        key: "push_enabled",
        group: "push",
        kind: Kind::Bool,
        default: "false",
        env: "PUSH_ENABLED",
    },
    Definition {
        key: "push_installation_id",
        group: "push",
        kind: Kind::Secret,
        default: "",
        env: "PUSH_INSTALLATION_ID",
    },
    Definition {
        key: "push_installation_key",
        group: "push",
        kind: Kind::Secret,
        default: "",
        env: "PUSH_INSTALLATION_KEY",
    },
    Definition {
        key: "push_relay_uri",
        group: "push",
        kind: Kind::Text { max_len: 512 },
        default: "https://push.bitwarden.com",
        env: "PUSH_RELAY_URI",
    },
    Definition {
        key: "push_identity_uri",
        group: "push",
        kind: Kind::Text { max_len: 512 },
        default: "https://identity.bitwarden.com",
        env: "PUSH_IDENTITY_URI",
    },
    // Registers this server with Kemlock's relay when it isn't yet. Turning the relay off, which
    // erases the installation at the relay, stays the console's own action.
    Definition {
        key: "kemlock_push_relay",
        group: "push",
        kind: Kind::Bool,
        default: "false",
        env: "KEMLOCK_PUSH_RELAY",
    },
    // Empty means Kemlock's own relay.
    Definition {
        key: "kemlock_push_relay_url",
        group: "push",
        kind: Kind::Text { max_len: 512 },
        default: "",
        env: "KEMLOCK_PUSH_RELAY_URL",
    },
    // Backups: the schedule (`off` turns them off), how many to keep, where they go inside the
    // data folder and the age recipient they are encrypted to. The scheduler reads them again
    // as it wakes, so a change counts without a restart.
    Definition {
        key: "backup_schedule",
        group: "backups",
        kind: Kind::Choice(BACKUP_SCHEDULES),
        default: "off",
        env: "KEMLOCK_BACKUP_SCHEDULE",
    },
    Definition {
        key: "backup_keep",
        group: "backups",
        kind: Kind::Choice(&["7", "14", "30"]),
        default: "30",
        env: "KEMLOCK_BACKUP_KEEP",
    },
    // A folder inside the data folder; empty means `backups`. The environment variable may name
    // any folder, or a bucket (`s3://`); what the console saves can't leave the data folder.
    Definition {
        key: "backup_destination",
        group: "backups",
        kind: Kind::Text { max_len: 200 },
        default: "",
        env: "KEMLOCK_BACKUP_DEST",
    },
    Definition {
        key: "backup_recipient",
        group: "backups",
        kind: Kind::Text { max_len: 200 },
        default: "",
        env: "KEMLOCK_BACKUP_RECIPIENT",
    },
    // The operator's half of `/.well-known/security.txt` (RFC 9116): who to tell about a problem
    // with this server, and where their PGP key is. Kemlock's own contact is always listed too.
    Definition {
        key: "security_contact",
        group: "security",
        kind: Kind::Text { max_len: 254 },
        default: "",
        env: "KEMLOCK_SECURITY_CONTACT",
    },
    Definition {
        key: "security_encryption",
        group: "security",
        kind: Kind::Text { max_len: 254 },
        default: "",
        env: "KEMLOCK_SECURITY_ENCRYPTION",
    },
    // What happens to a member or group change that comes from outside Kemlock clients (the
    // Bitwarden-compatible routes, SSO group sync) on a space that has a chain: keep it for an
    // Owner's or Admin's app to sign (the default), refuse it, or hide chained spaces from those clients
    // (docs/crypto.md, "Changes from outside Kemlock clients").
    Definition {
        key: "space_chain_external_changes",
        group: "security",
        kind: Kind::Choice(&["queue", "refuse", "unchained"]),
        default: "queue",
        env: "KEMLOCK_SPACE_CHAIN_EXTERNAL_CHANGES",
    },
    // What this server does with a promotion a replica signed for itself and announces unasked
    // (docs/federation.md, "Home epochs, promotion and the fence"): keep it for this server's admin
    // to accept or refuse (the default), or apply it at once. The home of a vault always holds a
    // promotion that would take the vault from it.
    Definition {
        key: "federation_promotion",
        group: "federation",
        kind: Kind::Choice(&["hold", "auto"]),
        default: "hold",
        env: "KEMLOCK_FEDERATION_PROMOTION",
    },
];

/// The definition of a setting, by name.
pub fn definition(key: &str) -> Option<&'static Definition> {
    DEFINITIONS.iter().find(|d| d.key == key)
}

/// The environment, as far as settings are concerned: an unset or empty variable is `None`.
pub trait EnvSettings: Send + Sync {
    fn get(&self, name: &str) -> Option<String>;
}

/// An environment read through a function, such as `|name| std::env::var(name).ok()`.
#[derive(Clone, Copy, Debug)]
pub struct FnEnv<F>(pub F);

impl<F> EnvSettings for FnEnv<F>
where
    F: Fn(&str) -> Option<String> + Send + Sync,
{
    fn get(&self, name: &str) -> Option<String> {
        (self.0)(name)
    }
}

impl<T: EnvSettings + ?Sized> EnvSettings for std::sync::Arc<T> {
    fn get(&self, name: &str) -> Option<String> {
        (**self).get(name)
    }
}

/// An environment with nothing in it.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEnv;

impl EnvSettings for NoEnv {
    fn get(&self, _name: &str) -> Option<String> {
        None
    }
}

/// Where a setting's value comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Default,
    /// Saved from the console.
    Saved,
    /// Set by an environment variable: read-only here.
    Env,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::Saved => "saved",
            Source::Env => "env",
        }
    }
}

/// A setting as the console shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingView {
    pub definition: &'static Definition,
    /// The value in effect, as text. `None` for a secret, and for a text setting that is unset.
    pub value: Option<String>,
    /// For a secret: whether one is set (by the environment or the console).
    pub secret_set: bool,
    pub source: Source,
    pub read_only: bool,
}

/// What a request to change one setting says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Save this value.
    Set(String),
    /// Forget the saved value, so the default (or the environment) applies again.
    Reset,
}

fn is_true(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn is_false(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "false" | "0" | "no" | "off"
    )
}

/// A domain list in its stored form: lower-case, comma-separated, no blanks, no repeats.
fn clean_domains(raw: &str) -> Result<String, AdminError> {
    let mut seen: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let domain = part.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        let ok = domain.len() <= 253
            && domain.contains('.')
            && domain.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        if !ok {
            return Err(AdminError::Invalid(format!("{part:?} isn't a domain name")));
        }
        if !seen.contains(&domain) {
            seen.push(domain);
        }
    }
    Ok(seen.join(","))
}

/// Whether `value` is an address the push relays may be reached at: https, or plain http on the
/// loopback address (the installation key travels with every request).
fn is_relay_url(value: &str) -> bool {
    crate::push::is_relay_url(value)
}

/// What the store keeps in the data folder, by the start of the name: a backup folder saved in the
/// console may not be, or lie in, any of them.
pub const RESERVED_DATA_NAMES: &[&str] = &[
    "attachments",
    "sends",
    "files",
    "db",
    "tmp",
    "icon_cache",
    "unpacked",
    "data",
    "server",
    "kemlock",
    "config",
    "rsa_key",
    "import",
];

/// A folder inside the data folder: relative, with no `..` and no drive or `s3://` prefix.
fn is_folder_inside(value: &str) -> bool {
    let value = value.replace('\\', "/");
    let parts: Vec<&str> = value.split('/').filter(|p| !p.is_empty()).collect();
    let Some(first) = parts.first() else {
        // Empty means the default, backups.
        return value.is_empty();
    };
    let first = first.to_ascii_lowercase();
    !value.starts_with('/')
        && !value.contains(':')
        && parts.iter().all(|part| *part != ".." && *part != ".")
        && !RESERVED_DATA_NAMES
            .iter()
            .any(|name| first.starts_with(name))
}

/// What a few text settings need beyond their length. `value` is trimmed.
fn check_text(key: &str, value: &str) -> Result<(), &'static str> {
    match key {
        "push_relay_uri" | "push_identity_uri" | "kemlock_push_relay_url"
            if !value.is_empty() && !is_relay_url(value) =>
        {
            Err("must be an https address")
        }
        "backup_destination" if !is_folder_inside(value) => {
            Err("must be a folder inside the data folder, such as backups")
        }
        "backup_recipient" if !value.is_empty() && !value.starts_with("age1") => {
            Err("must be an age recipient, starting with age1")
        }
        _ => Ok(()),
    }
}

/// Checks `value` against the setting's type and returns it in its stored form.
pub fn validate(definition: &Definition, value: &str) -> Result<String, AdminError> {
    let key = definition.key;
    let bad = |why: &str| AdminError::Invalid(format!("{key}: {why}"));
    if value.chars().any(char::is_control) {
        return Err(bad("must not contain control characters"));
    }
    match definition.kind {
        Kind::Bool => {
            if is_true(value) {
                Ok("true".to_owned())
            } else if is_false(value) {
                Ok("false".to_owned())
            } else {
                Err(bad("must be true or false"))
            }
        }
        Kind::Int { min, max } => {
            let n: i64 = value
                .trim()
                .parse()
                .map_err(|_| bad("must be a whole number"))?;
            if (min..=max).contains(&n) {
                Ok(n.to_string())
            } else {
                Err(bad(&format!("must be from {min} to {max}")))
            }
        }
        Kind::Text { max_len } => {
            let value = value.trim();
            if value.chars().count() > max_len {
                return Err(bad(&format!("must be at most {max_len} characters")));
            }
            check_text(key, value).map_err(bad)?;
            Ok(value.to_owned())
        }
        Kind::Choice(choices) => {
            let value = value.trim().to_ascii_lowercase();
            if choices.contains(&value.as_str()) {
                Ok(value)
            } else {
                Err(bad(&format!("must be one of {}", choices.join(", "))))
            }
        }
        Kind::Secret => {
            if value.is_empty() || value.len() > 1024 {
                Err(bad("must be 1 to 1024 characters"))
            } else {
                Ok(value.to_owned())
            }
        }
        Kind::Email => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(String::new());
            }
            kemlock_domain::Email::parse(value)
                .map(|e| e.as_str().to_owned())
                .map_err(|_| bad("must be an email address"))
        }
        Kind::Domains => clean_domains(value),
    }
}

/// The typed settings store.
#[derive(Debug)]
pub struct Settings<R, S, E> {
    pub repo: R,
    pub seal: S,
    pub env: E,
}

fn purpose(key: &str) -> String {
    format!("setting:{key}")
}

impl<R: SettingsRepo, S: SecretSeal, E: EnvSettings> Settings<R, S, E> {
    fn env_value(&self, definition: &Definition) -> Option<String> {
        self.env
            .get(definition.env)
            .filter(|v| !v.trim().is_empty())
    }

    async fn saved(&self) -> Result<BTreeMap<String, String>, AdminError> {
        Ok(self
            .repo
            .settings_with_prefix(KEY_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(key, value)| key.strip_prefix(KEY_PREFIX).map(|k| (k.to_owned(), value)))
            .collect())
    }

    /// Every setting, in the order of [`DEFINITIONS`].
    pub async fn list(&self) -> Result<Vec<SettingView>, AdminError> {
        let saved = self.saved().await?;
        Ok(DEFINITIONS
            .iter()
            .map(|d| self.view(d, saved.get(d.key)))
            .collect())
    }

    fn view(&self, d: &'static Definition, saved: Option<&String>) -> SettingView {
        let secret = d.kind == Kind::Secret;
        let (value, source) = if let Some(v) = self.env_value(d) {
            (Some(v), Source::Env)
        } else if let Some(v) = saved {
            (Some(v.clone()), Source::Saved)
        } else if d.default.is_empty() {
            (None, Source::Default)
        } else {
            (Some(d.default.to_owned()), Source::Default)
        };
        SettingView {
            definition: d,
            secret_set: secret && source != Source::Default,
            value: if secret { None } else { value },
            source,
            read_only: source == Source::Env,
        }
    }

    /// The value in effect for `key`, as text. A secret is never returned here: see
    /// [`Settings::secret`].
    pub async fn get(&self, key: &str) -> Result<Option<String>, AdminError> {
        let d = definition(key).ok_or(AdminError::NotFound)?;
        if d.kind == Kind::Secret {
            return Ok(None);
        }
        if let Some(v) = self.env_value(d) {
            return Ok(Some(v));
        }
        let saved = self.saved().await?;
        Ok(saved
            .get(key)
            .cloned()
            .or_else(|| (!d.default.is_empty()).then(|| d.default.to_owned())))
    }

    /// The integer value in effect for `key`, for a setting of integer type.
    pub async fn get_int(&self, key: &str) -> Result<i64, AdminError> {
        let d = definition(key).ok_or(AdminError::NotFound)?;
        let Kind::Int { min, max } = d.kind else {
            return Err(AdminError::Invalid(format!("{key} isn't a number")));
        };
        // An environment value that doesn't parse falls back to the default, so a typo in a
        // compose file never turns a limit off.
        let from_text = |v: Option<String>| {
            v.and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|n| (min..=max).contains(n))
        };
        let value = from_text(self.get(key).await?)
            .or_else(|| from_text(Some(d.default.to_owned())))
            .unwrap_or(min);
        Ok(value)
    }

    /// A secret, opened. For the code that sends mail; never for a response.
    pub async fn secret(
        &self,
        key: &str,
    ) -> Result<Option<crate::ports::Zeroizing<Vec<u8>>>, AdminError> {
        let d = definition(key).ok_or(AdminError::NotFound)?;
        if d.kind != Kind::Secret {
            return Err(AdminError::Invalid(format!("{key} isn't a secret")));
        }
        if let Some(v) = self.env_value(d) {
            return Ok(Some(crate::ports::Zeroizing::new(v.into_bytes())));
        }
        let saved = self.saved().await?;
        let Some(text) = saved.get(key) else {
            return Ok(None);
        };
        let sealed = b64url::decode(text).ok_or_else(|| {
            AdminError::App(crate::AppError::Store(format!("{key} isn't sealed")))
        })?;
        let plain = self
            .seal
            .open(&purpose(key), &sealed)
            .map_err(|_| AdminError::App(crate::AppError::Store(format!("{key} doesn't open"))))?;
        Ok(Some(plain))
    }

    /// What `key` will be once `changes` are saved, as text: empty when unset.
    async fn after(
        &self,
        changes: &BTreeMap<String, Change>,
        key: &str,
    ) -> Result<String, AdminError> {
        Ok(match changes.get(key) {
            Some(Change::Set(value)) => value.trim().to_owned(),
            Some(Change::Reset) => String::new(),
            None => self.get(key).await?.unwrap_or_default().trim().to_owned(),
        })
    }

    /// Refuses unless the SMTP settings, as they will be, make a mail server: the same rules
    /// `SmtpConfig` applies at the server (a host, a sender, and a user name with its password or
    /// neither).
    async fn check_mail_is_set_up(
        &self,
        changes: &BTreeMap<String, Change>,
    ) -> Result<(), AdminError> {
        let refuse = |why: &str| {
            Err(AdminError::Invalid(format!(
                "verifying new accounts needs mail: {why}"
            )))
        };
        if self.after(changes, "smtp_host").await?.is_empty() {
            return refuse("set the SMTP host first");
        }
        if self.after(changes, "smtp_from").await?.is_empty() {
            return refuse("set the SMTP sender address (smtp_from) too");
        }
        let user = !self.after(changes, "smtp_username").await?.is_empty();
        let password = match changes.get("smtp_password") {
            Some(Change::Set(value)) => !value.is_empty(),
            Some(Change::Reset) => false,
            None => self
                .secret("smtp_password")
                .await?
                .is_some_and(|value| !value.is_empty()),
        };
        if user != password {
            return refuse("the SMTP user name and password go together");
        }
        Ok(())
    }

    /// Applies `changes`, all or none: every change is checked before any is stored. A setting
    /// the environment sets is refused with [`AdminError::ReadOnly`], an unknown name with
    /// [`AdminError::Invalid`].
    pub async fn apply(&self, changes: &BTreeMap<String, Change>) -> Result<(), AdminError> {
        let mut writes: Vec<(&'static str, Option<String>)> = Vec::with_capacity(changes.len());
        let mut verifies = false;
        for (key, change) in changes {
            let d = definition(key)
                .ok_or_else(|| AdminError::Invalid(format!("{key} isn't a setting")))?;
            if self.env_value(d).is_some() {
                return Err(AdminError::ReadOnly(d.key.to_owned()));
            }
            match change {
                Change::Reset => writes.push((d.key, None)),
                Change::Set(value) => {
                    let value = validate(d, value)?;
                    if d.key == "signups_verify" && value == "true" {
                        verifies = true;
                    }
                    let stored = if d.kind == Kind::Secret {
                        b64url::encode(&self.seal.seal(&purpose(d.key), value.as_bytes()))
                    } else {
                        value
                    };
                    writes.push((d.key, Some(stored)));
                }
            }
        }
        // A password kept across a new mail host would be sent to whoever answers there, and an
        // admin could point the host at a server of their own to read it: a new host takes a new
        // password (or none) in the same save.
        if let Some(change) = changes.get("smtp_host") {
            let new_host = match change {
                Change::Set(value) => value.trim().to_ascii_lowercase(),
                Change::Reset => String::new(),
            };
            let old_host = self
                .get("smtp_host")
                .await?
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let kept = !changes.contains_key("smtp_password")
                && self.saved().await?.contains_key("smtp_password");
            if new_host != old_host && kept {
                return Err(AdminError::Invalid(
                    "smtp_host changed: enter the SMTP password again, or clear it \
                     (smtp_password), in the same save"
                        .to_owned(),
                ));
            }
        }
        // A link can't be mailed without a mail server, and an account held back for one that never
        // comes can't be used: turning the setting on needs the SMTP settings the server needs to
        // make a mail server, saved with it or already set (a host and a sender, and a user name
        // with its password or neither).
        if verifies {
            self.check_mail_is_set_up(changes).await?;
        }
        for (key, value) in writes {
            let stored_key = format!("{KEY_PREFIX}{key}");
            match value {
                Some(v) => self.repo.put_setting(&stored_key, &v).await?,
                None => self.repo.delete_setting(&stored_key).await?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(key: &str) -> &'static Definition {
        definition(key).expect("a defined setting")
    }

    #[test]
    fn every_definition_has_a_valid_default() {
        for d in DEFINITIONS {
            if d.default.is_empty() {
                continue;
            }
            assert!(validate(d, d.default).is_ok(), "{}", d.key);
        }
    }

    #[test]
    fn bitwarden_invitations_are_not_taken_for_accepted_unless_the_operator_says_so() {
        let d = def("bw_invites_auto_accept");
        assert_eq!(d.kind, Kind::Bool);
        assert_eq!(d.default, "false");
        assert_eq!(d.env, "KEMLOCK_BW_INVITES_AUTO_ACCEPT");
    }

    #[test]
    fn names_and_variables_are_unique() {
        for (i, a) in DEFINITIONS.iter().enumerate() {
            for b in &DEFINITIONS[i + 1..] {
                assert_ne!(a.key, b.key);
                assert_ne!(a.env, b.env);
            }
        }
    }

    #[test]
    fn booleans_numbers_and_choices_are_checked() {
        assert_eq!(validate(def("signups_allowed"), " Yes "), Ok("true".into()));
        assert!(validate(def("signups_allowed"), "maybe").is_err());
        assert_eq!(validate(def("trash_days"), "45"), Ok("45".into()));
        assert!(validate(def("trash_days"), "0").is_err());
        assert!(validate(def("trash_days"), "366").is_err());
        assert!(validate(def("trash_days"), "ten").is_err());
        assert_eq!(
            validate(def("smtp_security"), "StartTLS"),
            Ok("starttls".into())
        );
        assert!(validate(def("smtp_security"), "ssl3").is_err());
    }

    #[test]
    fn retention_follows_the_design_bounds() {
        assert!(validate(def("event_log_days"), "89").is_err());
        assert!(validate(def("event_log_days"), "90").is_ok());
        assert!(validate(def("event_log_days"), "2557").is_ok());
        assert!(validate(def("sign_in_log_days"), "6").is_err());
        assert!(validate(def("sign_in_log_days"), "365").is_ok());
        assert!(validate(def("email_log_days"), "91").is_err());
        assert!(validate(def("backup_days"), "7").is_ok());
        assert!(validate(def("deleted_account_grace_days"), "31").is_err());
    }

    #[test]
    fn email_and_domain_lists_are_cleaned() {
        assert_eq!(validate(def("smtp_from"), ""), Ok(String::new()));
        assert_eq!(
            validate(def("smtp_from"), " Ops@Example.org "),
            Ok("ops@example.org".into())
        );
        assert!(validate(def("smtp_from"), "not an address").is_err());
        assert_eq!(
            validate(
                def("signups_domains_whitelist"),
                "Example.org, example.org ,corp.example.com."
            ),
            Ok("example.org,corp.example.com".into())
        );
        assert!(validate(def("signups_domains_whitelist"), "bad domain").is_err());
    }

    #[test]
    fn the_security_contact_and_key_are_short_text_and_unset_by_default() {
        for key in ["security_contact", "security_encryption"] {
            let d = def(key);
            assert_eq!(d.group, "security");
            assert_eq!(d.default, "");
            assert_eq!(
                validate(d, " mailto:ops@example.org "),
                Ok("mailto:ops@example.org".into())
            );
            assert!(validate(d, &"x".repeat(255)).is_err());
            assert!(validate(d, "a\nb").is_err());
        }
    }

    #[test]
    fn a_promotion_is_held_for_the_admin_unless_the_setting_says_auto() {
        let d = def("federation_promotion");
        assert_eq!((d.default, d.env), ("hold", "KEMLOCK_FEDERATION_PROMOTION"));
        assert_eq!(d.group, "federation");
        assert_eq!(validate(d, " Auto "), Ok("auto".into()));
        assert_eq!(validate(d, "hold"), Ok("hold".into()));
        assert!(validate(d, "yes").is_err());
    }

    #[test]
    fn push_settings_are_in_their_group_and_the_id_and_key_are_secrets() {
        for key in ["push_installation_id", "push_installation_key"] {
            assert_eq!(def(key).kind, Kind::Secret);
            assert_eq!(def(key).group, "push");
        }
        assert_eq!(def("push_enabled").env, "PUSH_ENABLED");
        assert_eq!(def("kemlock_push_relay").env, "KEMLOCK_PUSH_RELAY");
        assert_eq!(validate(def("push_enabled"), "on"), Ok("true".into()));
    }

    #[test]
    fn push_addresses_must_be_https() {
        for key in [
            "push_relay_uri",
            "push_identity_uri",
            "kemlock_push_relay_url",
        ] {
            let d = def(key);
            assert!(validate(d, "https://push.example.org").is_ok(), "{key}");
            assert!(validate(d, "http://127.0.0.1:9000").is_ok(), "{key}");
            assert!(validate(d, "http://push.example.org").is_err(), "{key}");
        }
        assert!(validate(def("kemlock_push_relay_url"), "").is_ok());
    }

    #[test]
    fn backups_follow_the_environment_names_and_stay_inside_the_data_folder() {
        assert_eq!(def("backup_schedule").env, "KEMLOCK_BACKUP_SCHEDULE");
        assert_eq!(validate(def("backup_schedule"), "6h"), Ok("6h".into()));
        assert!(validate(def("backup_schedule"), "weekly").is_err());
        assert!(validate(def("backup_keep"), "14").is_ok());
        assert!(validate(def("backup_keep"), "10").is_err());
        let dest = def("backup_destination");
        assert!(validate(dest, "").is_ok());
        assert!(validate(dest, "nas/backups").is_ok());
        for bad in [
            "/mnt/nas",
            "../outside",
            "a/../../b",
            "s3://bucket/x",
            r"C:\backups",
            r"..\x",
            ".",
            "./",
            "db",
            "Attachments/x",
            "sends",
            "server.key",
            "import",
            "Import/old",
            "backups/../db",
        ] {
            assert!(validate(dest, bad).is_err(), "{bad}");
        }
        assert!(validate(def("backup_recipient"), "age1abc").is_ok());
        assert!(validate(def("backup_recipient"), "ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(validate(def("smtp_host"), "mail\n.example.org").is_err());
        assert!(validate(def("smtp_password"), "").is_err());
    }
}
