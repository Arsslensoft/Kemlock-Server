//! Saved settings, live: what the admin console saves (sign-ups, file limits, the trash,
//! retention, rate limits, SMTP) is read at start and again when it changes, into the running
//! server.
//!
//! A setting's value is the first of these that has one: the environment, the TOML file
//! ([`file_settings`]), what the console saved, the default. [`Layered`] is the first two as one
//! `EnvSettings`, so a value either of them sets shows in the console as read-only and wins over
//! a saved one.
//!
//! [`SettingsWatch`] holds the effective values as a [`Snapshot`] in a `tokio::sync::watch`
//! channel. It reads them at start, and again when it is nudged (the console just saved) or every
//! [`POLL_EVERY`]: the poll is how a change saved on another replica reaches this one, so every
//! replica is at most that far behind. A snapshot that equals the last one is not published.
//! [`apply`] puts a snapshot into the running parts: the shared [`Live`] handle (sign-ups, the
//! domain whitelist, invitations, the largest file), the rate limiters, the mail sender
//! ([`SwitchMailer`]) and the retention settings every reader of them sees
//! ([`SettingsWatch::overlay_retention`]).

use crate::adapters::ServerCrypto;
use crate::config::Config;
use kemlock_api_kem::Limits;
use kemlock_app::admin::settings::{DEFINITIONS, Kind, SettingView, Source};
use kemlock_app::admin::{AdminError, EnvSettings, Live, Settings, SettingsRepo};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::SecretSeal;
use kemlock_domain::privacy::Retention;
use kemlock_notify::bitwarden::BitwardenPushConfig;
use kemlock_notify::mail::{LogMailer, Mail, MailError, Mailer, SmtpConfig, SmtpMailer};
use kemlock_store_sql::SqlStore;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

/// How often a replica looks for settings another replica saved.
pub const POLL_EVERY: Duration = Duration::from_secs(15);

/// One mebibyte.
const MIB: u64 = 1024 * 1024;

type Lookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The environment, then the TOML file, as the one source the settings store calls "environment":
/// a value either has is shown as set from outside and can't be changed in the console.
#[derive(Clone)]
pub struct Layered {
    env: Lookup,
    file: Arc<BTreeMap<String, String>>,
}

impl std::fmt::Debug for Layered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layered")
            .field("file", &self.file.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Layered {
    /// Reads variables through `env` and settings from `file` (see [`file_settings`]).
    pub fn new(
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
        file: BTreeMap<String, String>,
    ) -> Layered {
        Layered {
            env: Arc::new(env),
            file: Arc::new(file),
        }
    }

    /// The settings' variables as `config` read them (see [`Config::settings_env`]), the process
    /// environment for any other name, and `file`.
    pub fn from_config(config: &Config, file: BTreeMap<String, String>) -> Layered {
        let set = config.settings_env.clone();
        Layered::new(
            move |name| {
                if DEFINITIONS.iter().any(|d| d.env == name) {
                    set.get(name).cloned()
                } else {
                    std::env::var(name).ok()
                }
            },
            file,
        )
    }

    /// A variable of the environment alone: for what isn't a setting, such as `SMTP_TIMEOUT`.
    pub fn var(&self, name: &str) -> Option<String> {
        (self.env)(name).filter(|v| !v.trim().is_empty())
    }
}

impl EnvSettings for Layered {
    fn get(&self, name: &str) -> Option<String> {
        if let Some(value) = self.var(name) {
            return Some(value);
        }
        let definition = DEFINITIONS.iter().find(|d| d.env == name)?;
        self.file
            .get(definition.key)
            .cloned()
            .filter(|v| !v.trim().is_empty())
    }
}

/// The settings a TOML file sets, by the console's names (`signups_allowed`, `trash_days`,
/// `smtp_host`, …), as text. Anything else in the file is somebody else's.
pub fn file_settings(text: &str) -> Result<BTreeMap<String, String>, String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for definition in DEFINITIONS {
        let Some(value) = table.get(definition.key) else {
            continue;
        };
        let text = match value {
            toml::Value::String(s) => s.clone(),
            toml::Value::Boolean(b) => b.to_string(),
            toml::Value::Integer(n) => n.to_string(),
            // A domain list may be written as an array.
            toml::Value::Array(items) => items
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => continue,
        };
        out.insert(definition.key.to_owned(), text);
    }
    Ok(out)
}

/// [`file_settings`] of the file at `path`; none when there is no file.
pub fn read_file_settings(path: Option<&Path>) -> Result<BTreeMap<String, String>, String> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("can't read the config file {}: {e}", path.display()))?;
    file_settings(&text).map_err(|e| format!("the config file {} isn't valid: {e}", path.display()))
}

/// The retention periods a setting other than the default sets. A period that is none is left to
/// the stored retention settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionOverrides {
    pub event_log_days: Option<u32>,
    pub sign_in_log_days: Option<u32>,
    pub trash_days: Option<u32>,
    pub email_log_days: Option<u32>,
    pub backup_days: Option<u32>,
    pub deleted_account_grace_days: Option<u32>,
}

impl RetentionOverrides {
    /// Puts each period that is set over `retention`, kept inside the ranges the design gives
    /// (the console allows a few more days of event log than the 7 years the domain does).
    pub fn apply_to(&self, retention: &mut Retention) {
        fn put(slot: &mut u32, value: Option<u32>, min: u32, max: u32) {
            if let Some(value) = value {
                *slot = value.clamp(min, max);
            }
        }
        put(
            &mut retention.event_log_days,
            self.event_log_days,
            90,
            7 * 365,
        );
        put(
            &mut retention.sign_in_log_days,
            self.sign_in_log_days,
            7,
            365,
        );
        put(&mut retention.trash_days, self.trash_days, 1, 365);
        put(&mut retention.email_log_days, self.email_log_days, 7, 90);
        put(&mut retention.backup_days, self.backup_days, 7, 365);
        put(
            &mut retention.deleted_account_grace_days,
            self.deleted_account_grace_days,
            0,
            30,
        );
    }
}

/// The effective values of every setting the running server follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub signups_allowed: bool,
    /// Lower-case; empty means no whitelist.
    pub signups_domains: Vec<String>,
    pub invitations_allowed: bool,
    /// Bytes. None leaves the routes' own limit (`KEMLOCK_ATTACHMENT_MAX_SIZE` or 100 MiB).
    pub max_file_size: Option<u64>,
    /// Bytes of attachments an account may keep (`USER_ATTACHMENT_LIMIT`, set in KiB): `None` when
    /// nothing sets it, which is no limit, and `Some(0)` when something sets 0, which switches
    /// attachments off, as in Vaultwarden.
    pub user_attachment_limit: Option<u64>,
    /// The same for a space (`ORG_ATTACHMENT_LIMIT`).
    pub space_attachment_limit: Option<u64>,
    /// The same for the file Sends of an account (`USER_SEND_LIMIT`).
    pub send_limit: Option<u64>,
    pub retention: RetentionOverrides,
    pub rate_sign_in_per_minute: u32,
    pub rate_password_failures: u32,
    pub rate_second_step_failures: u32,
    pub rate_register_per_hour: u32,
    /// The SMTP server, or none when no host is set (mail is only logged) or the settings don't
    /// make a valid one: then `smtp_error` says why and the sender in use stays as it was.
    pub smtp: Option<SmtpConfig>,
    pub smtp_error: Option<String>,
    /// Bitwarden's push relay (`PUSH_*`). `push_error` says why they could not be read.
    pub push: PushValues,
    pub push_error: Option<String>,
    /// `KEMLOCK_PUSH_RELAY`: register with Kemlock's relay when the server hasn't.
    pub kemlock_relay: bool,
    /// Kemlock's relay address; empty means the default.
    pub kemlock_relay_url: String,
    /// The backup settings (`KEMLOCK_BACKUP_*`), as text. The folder is relative to the data
    /// folder when `backup_destination_saved`, and as the environment wrote it otherwise.
    pub backup_schedule: String,
    pub backup_keep: String,
    pub backup_destination: String,
    pub backup_destination_saved: bool,
    pub backup_recipient: String,
    /// `federation_promotion` as the server follows it: `hold` or `auto`.
    pub federation_promotion: String,
    /// `space_chain_external_changes`: `queue`, `refuse` or `unchained`.
    pub space_chain_external_changes: String,
}

fn flag(view: &SettingView) -> bool {
    view.value.as_deref().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

/// A whole-number setting's value. One that doesn't parse or is out of bounds (a typo in an
/// environment variable) falls back to the default, so a typo never turns a limit off.
fn int(view: &SettingView) -> i64 {
    let (min, max) = match view.definition.kind {
        Kind::Int { min, max } => (min, max),
        _ => (i64::MIN, i64::MAX),
    };
    let parse = |v: &str| {
        v.trim()
            .parse::<i64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
    };
    view.value
        .as_deref()
        .and_then(parse)
        .or_else(|| parse(view.definition.default))
        .unwrap_or(min)
}

fn count(view: &SettingView) -> u32 {
    u32::try_from(int(view)).unwrap_or(1)
}

/// A storage quota in bytes from a setting in KiB: unset (the default) is no limit, and a 0 that
/// something set is a limit of none, as in Vaultwarden.
fn quota(view: &SettingView) -> Option<u64> {
    (view.source != Source::Default)
        .then(|| u64::try_from(int(view)).unwrap_or(0).saturating_mul(1024))
}

/// A period a setting other than the default sets.
fn period(view: &SettingView) -> Option<u32> {
    (view.source != Source::Default)
        .then(|| u32::try_from(int(view)).ok())
        .flatten()
}

impl Snapshot {
    /// Reads every setting as the server follows it. `process_env` is the environment, for what
    /// is no setting (`SMTP_TIMEOUT`, `KEMLOCK_ATTACHMENT_MAX_SIZE`).
    pub async fn load<R, S, E>(
        settings: &Settings<R, S, E>,
        process_env: &(dyn Fn(&str) -> Option<String> + Sync),
    ) -> Result<Snapshot, AdminError>
    where
        R: SettingsRepo,
        S: SecretSeal,
        E: EnvSettings,
    {
        let views = settings.list().await?;
        let by_key: BTreeMap<&str, &SettingView> =
            views.iter().map(|v| (v.definition.key, v)).collect();
        let view = |key: &str| by_key.get(key).copied().ok_or(AdminError::NotFound);
        let text = |key: &str| view(key).map(|v| v.value.clone().unwrap_or_default());

        let domains = view("signups_domains_whitelist")?
            .value
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        // The size from `KEMLOCK_ATTACHMENT_MAX_SIZE` is already in the routes; only a setting
        // that outranks it replaces it.
        let size = view("max_file_size_mib")?;
        let blob_env =
            process_env("KEMLOCK_ATTACHMENT_MAX_SIZE").is_some_and(|v| !v.trim().is_empty());
        let outranks = match size.source {
            Source::Env => true,
            Source::Saved => !blob_env,
            Source::Default => false,
        };
        let max_file_size =
            outranks.then(|| u64::try_from(int(size)).unwrap_or(1).saturating_mul(MIB));

        let (smtp, smtp_error) = smtp_of(settings, &views, process_env).await;
        let (push, push_error) = match push_of(settings, &views).await {
            Ok(push) => (push, None),
            Err(why) => (PushValues::default(), Some(why)),
        };

        Ok(Snapshot {
            signups_allowed: flag(view("signups_allowed")?),
            signups_domains: domains,
            invitations_allowed: flag(view("invitations_allowed")?),
            max_file_size,
            user_attachment_limit: quota(view("user_attachment_limit_kib")?),
            space_attachment_limit: quota(view("space_attachment_limit_kib")?),
            send_limit: quota(view("send_file_limit_kib")?),
            retention: RetentionOverrides {
                event_log_days: period(view("event_log_days")?),
                sign_in_log_days: period(view("sign_in_log_days")?),
                trash_days: period(view("trash_days")?),
                email_log_days: period(view("email_log_days")?),
                backup_days: period(view("backup_days")?),
                deleted_account_grace_days: period(view("deleted_account_grace_days")?),
            },
            rate_sign_in_per_minute: count(view("rate_sign_in_per_minute")?),
            rate_password_failures: count(view("rate_password_failures_per_15_minutes")?),
            rate_second_step_failures: count(view("rate_second_step_failures_per_15_minutes")?),
            rate_register_per_hour: count(view("rate_register_per_hour")?),
            smtp,
            smtp_error,
            push,
            push_error,
            kemlock_relay: flag(view("kemlock_push_relay")?),
            kemlock_relay_url: view("kemlock_push_relay_url")?
                .value
                .clone()
                .unwrap_or_default(),
            backup_schedule: text("backup_schedule")?,
            backup_keep: text("backup_keep")?,
            backup_destination: text("backup_destination")?,
            backup_destination_saved: view("backup_destination")?.source == Source::Saved,
            backup_recipient: text("backup_recipient")?,
            federation_promotion: text("federation_promotion")?,
            space_chain_external_changes: text("space_chain_external_changes")?,
        })
    }
}

/// The SMTP server the settings describe: through `SmtpConfig::from_lookup`, with the settings'
/// values under the names Vaultwarden gives them, and the environment for the rest.
async fn smtp_of<R, S, E>(
    settings: &Settings<R, S, E>,
    views: &[SettingView],
    process_env: &(dyn Fn(&str) -> Option<String> + Sync),
) -> (Option<SmtpConfig>, Option<String>)
where
    R: SettingsRepo,
    S: SecretSeal,
    E: EnvSettings,
{
    let mut values: BTreeMap<&'static str, String> = BTreeMap::new();
    for view in views.iter().filter(|v| v.definition.group == "smtp") {
        let Some(value) = view.value.as_deref().filter(|v| !v.is_empty()) else {
            continue;
        };
        // The port's default is for STARTTLS; with another security the library's own default
        // for it is the right one.
        if view.definition.key == "smtp_port" && view.source == Source::Default {
            continue;
        }
        values.insert(view.definition.env, value.to_owned());
    }
    match settings.secret("smtp_password").await {
        Ok(Some(password)) => match String::from_utf8(password.to_vec()) {
            Ok(text) => {
                values.insert("SMTP_PASSWORD", text);
            }
            Err(_) => return (None, Some("SMTP_PASSWORD isn't text".to_owned())),
        },
        Ok(None) => {}
        Err(e) => return (None, Some(format!("the saved SMTP password: {e}"))),
    }
    let lookup = |name: &str| values.get(name).cloned().or_else(|| process_env(name));
    match SmtpConfig::from_lookup(&lookup) {
        Ok(smtp) => (smtp, None),
        Err(e) => (None, Some(e.to_string())),
    }
}

/// Bitwarden's push relay settings as saved or set: what `PUSH_*` say. The key stays out of
/// `Debug` output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PushValues {
    pub enabled: bool,
    pub installation_id: String,
    pub installation_key: String,
    pub relay_uri: String,
    pub identity_uri: String,
}

impl std::fmt::Debug for PushValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushValues")
            .field("enabled", &self.enabled)
            .field("relay_uri", &self.relay_uri)
            .field("identity_uri", &self.identity_uri)
            .finish_non_exhaustive()
    }
}

impl PushValues {
    /// The relay the values describe: `Ok(None)` when pushes are off, an error that says what is
    /// missing or wrong when they are on without what they need.
    pub fn config(&self) -> Result<Option<BitwardenPushConfig>, String> {
        let get = |name: &str| -> Option<String> {
            match name {
                "PUSH_ENABLED" => Some(self.enabled.to_string()),
                "PUSH_INSTALLATION_ID" => Some(self.installation_id.clone()),
                "PUSH_INSTALLATION_KEY" => Some(self.installation_key.clone()),
                "PUSH_RELAY_URI" => Some(self.relay_uri.clone()),
                "PUSH_IDENTITY_URI" => Some(self.identity_uri.clone()),
                _ => None,
            }
        };
        BitwardenPushConfig::from_lookup(&get).map_err(|e| e.to_string())
    }
}

/// The push settings in effect, secrets opened. A secret that doesn't open is an error the
/// follower reports, leaving the relay as it was.
async fn push_of<R, S, E>(
    settings: &Settings<R, S, E>,
    views: &[SettingView],
) -> Result<PushValues, String>
where
    R: SettingsRepo,
    S: SecretSeal,
    E: EnvSettings,
{
    let text = |key: &str| {
        views
            .iter()
            .find(|v| v.definition.key == key)
            .and_then(|v| v.value.clone())
            .unwrap_or_default()
    };
    let secret = |key: &'static str| async move {
        match settings.secret(key).await {
            Ok(Some(bytes)) => {
                String::from_utf8(bytes.to_vec()).map_err(|_| format!("{key} isn't text"))
            }
            Ok(None) => Ok(String::new()),
            Err(e) => Err(format!("the saved {key}: {e}")),
        }
    };
    Ok(PushValues {
        enabled: matches!(
            text("push_enabled").trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        installation_id: secret("push_installation_id").await?,
        installation_key: secret("push_installation_key").await?,
        relay_uri: text("push_relay_uri"),
        identity_uri: text("push_identity_uri"),
    })
}

/// A mail sender whose SMTP server can be replaced while the server runs: every sender the
/// server holds is a clone of this one.
#[derive(Clone)]
pub struct SwitchMailer {
    current: Arc<RwLock<Arc<dyn Mailer>>>,
}

impl std::fmt::Debug for SwitchMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwitchMailer").finish_non_exhaustive()
    }
}

impl SwitchMailer {
    /// Starts out sending through `mailer`.
    pub fn new(mailer: Arc<dyn Mailer>) -> SwitchMailer {
        SwitchMailer {
            current: Arc::new(RwLock::new(mailer)),
        }
    }

    /// Sends through `mailer` from now on. A mail already being sent finishes with the old one.
    pub fn set(&self, mailer: Arc<dyn Mailer>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = mailer;
    }

    /// Switches to the SMTP server of `snapshot`: SMTP when it has one, only logging when it has
    /// no host. Settings that don't make a valid server leave the sender as it is.
    pub fn follow(&self, snapshot: &Snapshot) {
        if let Some(why) = &snapshot.smtp_error {
            tracing::warn!(%why, "the SMTP settings are unusable; mail goes out as before");
            return;
        }
        match &snapshot.smtp {
            Some(config) => match SmtpMailer::new(config) {
                Ok(mailer) => {
                    tracing::info!(host = %config.host, "mail goes out over SMTP");
                    self.set(Arc::new(mailer));
                }
                Err(error) => tracing::warn!(%error, "can't set up SMTP; mail goes out as before"),
            },
            None => {
                tracing::info!("no SMTP host is set; mail is only logged");
                self.set(Arc::new(LogMailer));
            }
        }
    }
}

impl Mailer for SwitchMailer {
    fn is_set_up(&self) -> bool {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_set_up()
    }

    fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>> {
        let mailer = self
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Box::pin(async move { mailer.send(mail).await })
    }
}

/// Puts `snapshot` into the running parts.
pub fn apply(snapshot: &Snapshot, live: &Live, limits: &Limits, mailer: &SwitchMailer) {
    live.set_signups_allowed(snapshot.signups_allowed);
    live.set_signup_domains(&snapshot.signups_domains);
    live.set_invitations_allowed(snapshot.invitations_allowed);
    live.set_max_file_size(snapshot.max_file_size.unwrap_or(0));
    live.set_user_attachment_limit(snapshot.user_attachment_limit);
    live.set_space_attachment_limit(snapshot.space_attachment_limit);
    live.set_send_limit(snapshot.send_limit);
    limits.sign_in.set_limit(snapshot.rate_sign_in_per_minute);
    limits.account.set_limit(snapshot.rate_password_failures);
    limits
        .second_step
        .set_limit(snapshot.rate_second_step_failures);
    limits.register.set_limit(snapshot.rate_register_per_hour);
    mailer.follow(snapshot);
}

/// The settings, watched.
pub struct SettingsWatch {
    settings: Settings<SqlStore, ServerCrypto, Layered>,
    tx: watch::Sender<Arc<Snapshot>>,
    nudge: Notify,
}

impl std::fmt::Debug for SettingsWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsWatch").finish_non_exhaustive()
    }
}

impl SettingsWatch {
    /// Reads the settings once, so the first snapshot is there before the server listens.
    pub async fn start(
        store: SqlStore,
        crypto: ServerCrypto,
        env: Layered,
    ) -> Result<Arc<SettingsWatch>, String> {
        let settings = Settings {
            repo: store,
            seal: crypto,
            env,
        };
        let first = Snapshot::load(&settings, &|name| settings.env.var(name))
            .await
            .map_err(|e| format!("can't read the saved settings: {e}"))?;
        let (tx, _) = watch::channel(Arc::new(first));
        Ok(Arc::new(SettingsWatch {
            settings,
            tx,
            nudge: Notify::new(),
        }))
    }

    /// The snapshot now.
    pub fn current(&self) -> Arc<Snapshot> {
        self.tx.borrow().clone()
    }

    /// A receiver that is told of each change.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Snapshot>> {
        self.tx.subscribe()
    }

    /// Asks the poll to read again now, because settings were just saved here.
    pub fn nudge(&self) {
        self.nudge.notify_one();
    }

    /// Reads the settings again and publishes them when they differ from the last snapshot.
    /// `Ok(true)` when they did.
    pub async fn refresh(&self) -> Result<bool, AdminError> {
        let next = Snapshot::load(&self.settings, &|name| self.settings.env.var(name)).await?;
        Ok(self.tx.send_if_modified(|current| {
            let changed = **current != next;
            if changed {
                *current = Arc::new(next);
            }
            changed
        }))
    }

    /// Makes every reader of the retention settings (the retention job, backups, account
    /// erasure) see the periods the settings set, now and as they change.
    pub fn overlay_retention(&self, store: &SqlStore) {
        let rx = self.subscribe();
        store.set_retention_overlay(move |retention| {
            let overrides = rx.borrow().retention;
            overrides.apply_to(retention);
        });
    }

    /// Makes the store's own reads of `federation_promotion` and `space_chain_external_changes`
    /// see the layered values (the environment, then `kemlock.toml`, then what the console saved),
    /// now and as they change.
    pub fn overlay_store_settings(&self, store: &SqlStore) {
        let rx = self.subscribe();
        store.set_setting_overlay(move |key| {
            let snapshot = rx.borrow();
            match key {
                "federation_promotion" => Some(snapshot.federation_promotion.clone()),
                "space_chain_external_changes" => {
                    Some(snapshot.space_chain_external_changes.clone())
                }
                _ => None,
            }
        });
    }

    /// Starts the task that re-reads the settings when nudged and every [`POLL_EVERY`].
    pub fn spawn_poll(self: &Arc<Self>) -> JoinHandle<()> {
        let watch = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(POLL_EVERY) => {}
                    () = watch.nudge.notified() => {}
                }
                match watch.refresh().await {
                    Ok(true) => tracing::info!("the saved settings changed; applying them"),
                    Ok(false) => {}
                    Err(error) => tracing::warn!(%error, "couldn't re-read the saved settings"),
                }
            }
        })
    }

    /// Starts the task that calls `apply` with each new snapshot. The snapshot there was at the
    /// start is applied by the caller, before the server listens.
    pub fn spawn_apply(&self, apply: impl Fn(&Snapshot) + Send + 'static) -> JoinHandle<()> {
        let mut rx = self.subscribe();
        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                let snapshot = rx.borrow_and_update().clone();
                apply(&snapshot);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::admin::{Change, NoEnv};
    use kemlock_app::privacy::PrivacySettings;
    use kemlock_crypto::opaque::OpaqueServer;
    use kemlock_crypto::seal::ServerSeal;
    use std::sync::Mutex;

    fn crypto() -> ServerCrypto {
        ServerCrypto::new(ServerSeal::new(&[7u8; 32]), OpaqueServer::generate())
    }

    fn layered(env: &[(&str, &str)], file: &[(&str, &str)]) -> Layered {
        let env: BTreeMap<String, String> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let file = file
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Layered::new(move |name| env.get(name).cloned(), file)
    }

    async fn new_store() -> SqlStore {
        SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects")
    }

    /// Saves settings the way the console does, and says whether they were taken.
    async fn try_save(store: &SqlStore, pairs: &[(&str, &str)]) -> bool {
        let settings = Settings {
            repo: store.clone(),
            seal: crypto(),
            env: NoEnv,
        };
        let changes = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Change::Set((*v).to_owned())))
            .collect();
        settings.apply(&changes).await.is_ok()
    }

    /// Saves settings the way the console does.
    async fn save(store: &SqlStore, pairs: &[(&str, &str)]) {
        assert!(try_save(store, pairs).await, "saved: {pairs:?}");
    }

    async fn watching(store: &SqlStore, env: Layered) -> Arc<SettingsWatch> {
        SettingsWatch::start(store.clone(), crypto(), env)
            .await
            .expect("the settings are read")
    }

    #[tokio::test]
    async fn backup_settings_follow_the_snapshot_with_the_environment_first_and_a_saved_folder_joined()
     {
        use kemlock_backup::{DestinationConfig, Schedule};
        let dir = tempfile::tempdir().expect("a folder");
        let root = dir.path().canonicalize().expect("resolves");
        let store = new_store().await;
        save(
            &store,
            &[
                ("backup_schedule", "6h"),
                ("backup_keep", "14"),
                ("backup_destination", "nas/b"),
                ("backup_recipient", "age1abc"),
            ],
        )
        .await;
        let saved = watching(&store, layered(&[], &[])).await;
        let s = crate::backups::settings_from_snapshot(&saved.current(), &|_| None, &root)
            .expect("valid");
        assert_eq!(s.schedule, Schedule::EverySixHours);
        assert_eq!(s.keep, 14);
        assert_eq!(s.recipient, "age1abc");
        assert_eq!(
            s.destination,
            DestinationConfig::Local {
                folder: root.join("nas").join("b")
            }
        );
        // The environment wins, and its folder is taken as written.
        let env = watching(
            &store,
            layered(
                &[
                    ("KEMLOCK_BACKUP_SCHEDULE", "nightly"),
                    ("KEMLOCK_BACKUP_DEST", "/mnt/elsewhere"),
                ],
                &[],
            ),
        )
        .await;
        let s = crate::backups::settings_from_snapshot(&env.current(), &|_| None, &root)
            .expect("valid");
        assert_eq!(s.schedule, Schedule::Nightly);
        assert_eq!(
            s.destination,
            DestinationConfig::Local {
                folder: std::path::PathBuf::from("/mnt/elsewhere")
            }
        );
        // One of the store's own folders is refused when it is saved (13c9656), and the saved
        // folder stays the one before.
        assert!(!try_save(&store, &[("backup_destination", "attachments")]).await);
        let saved = watching(&store, layered(&[], &[])).await;
        let s = crate::backups::settings_from_snapshot(&saved.current(), &|_| None, &root)
            .expect("valid");
        assert_eq!(
            s.destination,
            DestinationConfig::Local {
                folder: root.join("nas").join("b")
            }
        );
    }

    #[tokio::test]
    async fn the_stores_own_settings_follow_the_config_file_too() {
        use kemlock_federation::extra::{FedAdminRepo, PromotionMode};
        let store = new_store().await;
        // Nothing sets it: held, as the default says.
        let plain = watching(&store, layered(&[], &[])).await;
        plain.overlay_store_settings(&store);
        assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Hold));
        // `kemlock.toml` says auto, and the store sees it though nothing was saved.
        let from_file =
            watching(&store, layered(&[], &[("federation_promotion", "auto")])).await;
        from_file.overlay_store_settings(&store);
        assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Auto));
        // The environment outranks the file.
        let from_env = watching(
            &store,
            layered(
                &[("KEMLOCK_FEDERATION_PROMOTION", "hold")],
                &[("federation_promotion", "auto")],
            ),
        )
        .await;
        from_env.overlay_store_settings(&store);
        assert_eq!(store.promotion_mode().await, Ok(PromotionMode::Hold));
    }

    #[test]
    fn the_environment_outranks_the_file_and_names_map_to_settings() {
        let env = layered(
            &[("TRASH_AUTO_DELETE_DAYS", "10"), ("SMTP_HOST", "  ")],
            &[("trash_days", "20"), ("smtp_host", "mail.example.org")],
        );
        assert_eq!(env.get("TRASH_AUTO_DELETE_DAYS").as_deref(), Some("10"));
        // An empty variable counts as unset, so the file's value shows.
        assert_eq!(env.get("SMTP_HOST").as_deref(), Some("mail.example.org"));
        assert_eq!(env.get("SIGNUPS_ALLOWED"), None);
        assert_eq!(env.get("NOT_A_SETTING"), None);
        // `var` is the environment alone.
        assert_eq!(env.var("SMTP_HOST"), None);
    }

    #[test]
    fn a_config_file_sets_settings_under_the_consoles_names() {
        let text = r#"
            domain = "https://vault.example.org"
            signups_allowed = true
            trash_days = 45
            smtp_host = "mail.example.org"
            signups_domains_whitelist = ["Example.org", "corp.example.com"]
            event_log_days = { nested = "no" }
            unknown = 1
        "#;
        let found = file_settings(text).expect("valid");
        let get = |key: &str| found.get(key).map(String::as_str);
        assert_eq!(get("signups_allowed"), Some("true"));
        assert_eq!(get("trash_days"), Some("45"));
        assert_eq!(
            get("signups_domains_whitelist"),
            Some("Example.org,corp.example.com")
        );
        assert_eq!(get("domain"), None, "only settings are taken");
        assert_eq!(get("event_log_days"), None, "a table is no value");
        assert!(file_settings("trash_days = [").is_err());
        assert_eq!(read_file_settings(None), Ok(BTreeMap::new()));
    }

    #[tokio::test]
    async fn saved_settings_reach_the_snapshot() {
        let store = new_store().await;
        save(
            &store,
            &[
                ("signups_allowed", "true"),
                ("signups_domains_whitelist", "Example.org, corp.example.com"),
                ("trash_days", "45"),
                ("rate_sign_in_per_minute", "20"),
                ("max_file_size_mib", "250"),
                ("user_attachment_limit_kib", "0"),
                ("space_attachment_limit_kib", "2048"),
                ("send_file_limit_kib", "512"),
                ("invitations_allowed", "false"),
            ],
        )
        .await;
        let snapshot = watching(&store, layered(&[], &[])).await.current();
        assert_eq!(
            snapshot.user_attachment_limit,
            Some(0),
            "a set 0 switches off"
        );
        assert_eq!(snapshot.space_attachment_limit, Some(2048 * 1024));
        assert_eq!(snapshot.send_limit, Some(512 * 1024));
        assert!(snapshot.signups_allowed);
        assert_eq!(
            snapshot.signups_domains,
            ["example.org", "corp.example.com"]
        );
        assert!(!snapshot.invitations_allowed);
        assert_eq!(snapshot.retention.trash_days, Some(45));
        assert_eq!(
            snapshot.retention.event_log_days, None,
            "a default leaves the stored retention settings alone"
        );
        assert_eq!(snapshot.rate_sign_in_per_minute, 20);
        assert_eq!(snapshot.rate_register_per_hour, 10, "the default");
        assert_eq!(snapshot.max_file_size, Some(250 * MIB));
    }

    #[tokio::test]
    async fn nothing_saved_follows_the_defaults_and_leaves_the_routes_limits() {
        let store = new_store().await;
        let snapshot = watching(&store, layered(&[], &[])).await.current();
        assert!(!snapshot.signups_allowed);
        assert!(snapshot.invitations_allowed);
        assert!(snapshot.signups_domains.is_empty());
        assert_eq!(snapshot.max_file_size, None);
        assert_eq!(snapshot.user_attachment_limit, None, "unset is no limit");
        assert_eq!(snapshot.space_attachment_limit, None);
        assert_eq!(snapshot.send_limit, None);
        assert_eq!(snapshot.retention, RetentionOverrides::default());
        assert_eq!(snapshot.rate_sign_in_per_minute, 10);
        assert_eq!(snapshot.rate_password_failures, 10);
        assert_eq!(snapshot.rate_second_step_failures, 5);
        assert_eq!(snapshot.smtp, None);
        assert_eq!(snapshot.smtp_error, None);
    }

    #[tokio::test]
    async fn environment_then_file_then_saved() {
        let store = new_store().await;
        save(
            &store,
            &[
                ("signups_allowed", "true"),
                ("trash_days", "45"),
                ("rate_sign_in_per_minute", "20"),
                ("event_log_days", "200"),
            ],
        )
        .await;
        let env = layered(
            &[
                ("SIGNUPS_ALLOWED", "false"),
                ("KEMLOCK_RATE_REGISTER_PER_HOUR", "lots"),
            ],
            &[("trash_days", "60"), ("signups_allowed", "true")],
        );
        let snapshot = watching(&store, env).await.current();
        assert!(!snapshot.signups_allowed, "the environment wins");
        assert_eq!(
            snapshot.retention.trash_days,
            Some(60),
            "the file outranks what was saved"
        );
        assert_eq!(snapshot.rate_sign_in_per_minute, 20, "saved fills the rest");
        assert_eq!(snapshot.retention.event_log_days, Some(200));
        assert_eq!(
            snapshot.rate_register_per_hour, 10,
            "an environment value that isn't a number never turns a limit off"
        );
    }

    #[tokio::test]
    async fn the_attachment_environment_variable_outranks_a_saved_size() {
        let store = new_store().await;
        save(&store, &[("max_file_size_mib", "250")]).await;
        let blob_env = layered(&[("KEMLOCK_ATTACHMENT_MAX_SIZE", "1000")], &[]);
        let snapshot = watching(&store, blob_env).await.current();
        assert_eq!(snapshot.max_file_size, None);

        let setting_env = layered(
            &[
                ("KEMLOCK_ATTACHMENT_MAX_SIZE", "1000"),
                ("KEMLOCK_MAX_FILE_SIZE_MIB", "5"),
            ],
            &[],
        );
        let snapshot = watching(&store, setting_env).await.current();
        assert_eq!(snapshot.max_file_size, Some(5 * MIB));
    }

    #[tokio::test]
    async fn smtp_settings_make_a_server_and_the_password_stays_sealed() {
        let store = new_store().await;
        save(
            &store,
            &[
                ("smtp_host", "mail.example.org"),
                ("smtp_from", "vault@example.org"),
                ("smtp_security", "force_tls"),
                ("smtp_username", "vault"),
                ("smtp_password", "hunter2"),
            ],
        )
        .await;
        let env = layered(&[("SMTP_TIMEOUT", "30")], &[]);
        let snapshot = watching(&store, env).await.current();
        let smtp = snapshot.smtp.clone().expect("a server");
        assert_eq!(smtp.host, "mail.example.org");
        assert_eq!(smtp.port, 465, "force_tls with no saved port uses its own");
        assert_eq!(smtp.password.as_deref(), Some("hunter2"));
        assert_eq!(smtp.timeout, Duration::from_secs(30));
        assert_eq!(snapshot.smtp_error, None);
        let stored = store
            .setting("setting.smtp_password")
            .await
            .expect("read")
            .expect("stored");
        assert!(!stored.contains("hunter2"), "sealed in the store");
        assert!(!format!("{snapshot:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn smtp_settings_that_make_no_server_say_why() {
        let store = new_store().await;
        save(&store, &[("smtp_host", "mail.example.org")]).await;
        let snapshot = watching(&store, layered(&[], &[])).await.current();
        assert_eq!(snapshot.smtp, None);
        let why = snapshot.smtp_error.as_deref().expect("a reason");
        assert!(why.contains("SMTP_FROM"), "{why}");

        // No host at all is no error: mail is only logged.
        let bare = new_store().await;
        let snapshot = watching(&bare, layered(&[], &[])).await.current();
        assert_eq!(
            (snapshot.smtp.is_none(), snapshot.smtp_error.clone()),
            (true, None)
        );
    }

    #[tokio::test]
    async fn a_change_is_published_once_and_an_unchanged_read_is_not() {
        let store = new_store().await;
        let watch = watching(&store, layered(&[], &[])).await;
        let mut rx = watch.subscribe();
        assert!(!watch.refresh().await.expect("reads"));
        assert!(!rx.has_changed().expect("open"));

        save(&store, &[("trash_days", "45")]).await;
        assert!(watch.refresh().await.expect("reads"));
        assert!(rx.has_changed().expect("open"));
        assert_eq!(rx.borrow_and_update().retention.trash_days, Some(45));

        assert!(!watch.refresh().await.expect("reads"), "nothing new");
        assert!(!rx.has_changed().expect("open"));
    }

    #[tokio::test]
    async fn a_nudge_makes_the_poll_read_at_once() {
        let store = new_store().await;
        let watch = watching(&store, layered(&[], &[])).await;
        let mut rx = watch.subscribe();
        let poll = watch.spawn_poll();
        save(&store, &[("signups_allowed", "true")]).await;
        watch.nudge();
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the poll didn't wait for its interval")
            .expect("open");
        assert!(rx.borrow().signups_allowed);
        poll.abort();
    }

    #[tokio::test]
    async fn the_applier_follows_each_change() {
        let store = new_store().await;
        let watch = watching(&store, layered(&[], &[])).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let task = watch.spawn_apply(move |snapshot| {
            log.lock()
                .expect("lock")
                .push(snapshot.rate_sign_in_per_minute);
        });
        save(&store, &[("rate_sign_in_per_minute", "25")]).await;
        assert!(watch.refresh().await.expect("reads"));
        for _ in 0..100 {
            if !seen.lock().expect("lock").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(*seen.lock().expect("lock"), [25]);
        task.abort();
    }

    #[tokio::test]
    async fn applying_a_snapshot_changes_the_live_parts() {
        let store = new_store().await;
        save(
            &store,
            &[
                ("signups_allowed", "true"),
                ("signups_domains_whitelist", "example.org"),
                ("invitations_allowed", "false"),
                ("max_file_size_mib", "250"),
                ("rate_sign_in_per_minute", "20"),
                ("rate_password_failures_per_15_minutes", "30"),
                ("rate_second_step_failures_per_15_minutes", "8"),
                ("rate_register_per_hour", "40"),
            ],
        )
        .await;
        let snapshot = watching(&store, layered(&[], &[])).await.current();
        let live = Live::new(false);
        let limits = Limits::default();
        let mailer = SwitchMailer::new(Arc::new(LogMailer));
        apply(&snapshot, &live, &limits, &mailer);

        assert!(live.signups_allowed());
        assert!(!live.invitations_allowed());
        assert_eq!(live.max_file_size(), Some(250 * MIB));
        let ada = kemlock_domain::Email::parse("ada@example.org").expect("an email");
        let eve = kemlock_domain::Email::parse("eve@elsewhere.test").expect("an email");
        assert!(live.signups_open_for(&ada));
        assert!(
            !live.signups_open_for(&eve),
            "the whitelist keeps others out"
        );
        assert_eq!(limits.sign_in.limit(), 20);
        assert_eq!(limits.account.limit(), 30);
        assert_eq!(limits.second_step.limit(), 8);
        assert_eq!(limits.register.limit(), 40);

        // Back to the defaults when the saved values are reset.
        let settings = Settings {
            repo: store.clone(),
            seal: crypto(),
            env: NoEnv,
        };
        let resets = [
            "signups_allowed",
            "signups_domains_whitelist",
            "max_file_size_mib",
            "rate_sign_in_per_minute",
        ]
        .into_iter()
        .map(|k| (k.to_owned(), Change::Reset))
        .collect();
        settings.apply(&resets).await.expect("reset");
        let watched = watching(&store, layered(&[], &[])).await;
        apply(&watched.current(), &live, &limits, &mailer);
        assert!(!live.signups_allowed());
        assert_eq!(live.max_file_size(), None);
        assert_eq!(limits.sign_in.limit(), 10);
    }

    /// Notes which of two senders a mail went through.
    struct Tagged(&'static str, Arc<Mutex<Vec<String>>>);

    impl Mailer for Tagged {
        fn send(&self, mail: Mail) -> BoxFuture<'_, Result<(), MailError>> {
            self.1
                .lock()
                .expect("lock")
                .push(format!("{}:{}", self.0, mail.subject));
            Box::pin(async { Ok(()) })
        }
    }

    fn mail(subject: &str) -> Mail {
        Mail {
            to: "ada@example.org".to_owned(),
            subject: subject.to_owned(),
            text: String::new(),
            html: String::new(),
        }
    }

    #[tokio::test]
    async fn the_mail_sender_can_be_replaced_while_in_use() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let switch = SwitchMailer::new(Arc::new(Tagged("old", sent.clone())));
        let clone = switch.clone();
        clone.send(mail("a")).await.expect("sent");
        switch.set(Arc::new(Tagged("new", sent.clone())));
        clone.send(mail("b")).await.expect("sent");
        assert_eq!(*sent.lock().expect("lock"), ["old:a", "new:b"]);
    }

    #[tokio::test]
    async fn unusable_smtp_settings_keep_the_sender_and_no_host_means_log_only() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let switch = SwitchMailer::new(Arc::new(Tagged("old", sent.clone())));
        let store = new_store().await;
        let current = watching(&store, layered(&[], &[])).await.current();
        let mut snapshot = current.as_ref().clone();

        snapshot.smtp_error = Some("SMTP_FROM is not set".to_owned());
        switch.follow(&snapshot);
        switch.send(mail("a")).await.expect("sent");
        assert_eq!(*sent.lock().expect("lock"), ["old:a"]);

        // No host: mail is only logged, so the old sender is gone.
        snapshot.smtp_error = None;
        switch.follow(&snapshot);
        switch.send(mail("b")).await.expect("logged");
        assert_eq!(*sent.lock().expect("lock"), ["old:a"]);
    }

    #[tokio::test]
    async fn the_admin_consoles_mail_turns_on_when_smtp_is_set_up_after_the_start() {
        use kemlock_app::admin::Mailer as _;

        // Started with no SMTP host: the sender only logs.
        let switch = SwitchMailer::new(Arc::new(LogMailer));
        let console = kemlock_notify::mail::AdminMail::new(Some(Arc::new(switch.clone())));
        assert!(!console.configured());

        // SMTP is saved in the settings: the console shows mail as configured.
        let store = new_store().await;
        save(
            &store,
            &[
                ("smtp_host", "mail.example.org"),
                ("smtp_from", "vault@example.org"),
            ],
        )
        .await;
        let snapshot = watching(&store, layered(&[], &[])).await.current();
        assert!(snapshot.smtp.is_some(), "{:?}", snapshot.smtp_error);
        switch.follow(&snapshot);
        assert!(console.configured());

        // And off again when the host is cleared.
        let empty = new_store().await;
        let bare = watching(&empty, layered(&[], &[])).await.current();
        switch.follow(&bare);
        assert!(!console.configured());
    }

    #[tokio::test]
    async fn every_reader_of_the_retention_settings_follows_the_console() {
        let store = new_store().await;
        save(
            &store,
            &[
                ("trash_days", "45"),
                ("event_log_days", "2557"),
                ("deleted_account_grace_days", "7"),
            ],
        )
        .await;
        let env = layered(&[("KEMLOCK_BACKUP_DAYS", "14")], &[]);
        let watch = watching(&store, env).await;
        watch.overlay_retention(&store);

        let read = PrivacySettings::retention(&store).await.expect("read");
        assert_eq!(read.trash_days, 45);
        assert_eq!(
            read.event_log_days, 2555,
            "kept inside the domain's 7 years"
        );
        assert_eq!(read.deleted_account_grace_days, 7);
        assert_eq!(read.backup_days, 14, "from the environment");
        assert_eq!(
            read.sign_in_log_days, 90,
            "a default leaves the stored value"
        );

        // A change reaches the next read.
        save(&store, &[("trash_days", "50"), ("event_log_days", "120")]).await;
        assert!(watch.refresh().await.expect("reads"));
        let read = PrivacySettings::retention(&store).await.expect("read");
        assert_eq!((read.trash_days, read.event_log_days), (50, 120));
    }
}
