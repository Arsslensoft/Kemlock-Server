//! Backups, wired into the server: the settings (from the environment), the schedule, the archive
//! written before a migration on PostgreSQL and MySQL, and `kemlock-cli backup`.
//!
//! Read: `KEMLOCK_BACKUP_SCHEDULE` (`off`, the default, `nightly` for 03:00 UTC or `6h` for 03:00,
//! 09:00, 15:00 and 21:00 UTC), `KEMLOCK_BACKUP_RECIPIENT` (the age public key the archives are
//! encrypted to; `age-keygen` makes the pair, and the secret half stays with the operator),
//! `KEMLOCK_BACKUP_KEEP` (7, 14 or 30, default 30), `KEMLOCK_BACKUP_DEST` (a folder, or
//! `s3://bucket/prefix`; default `<DATA_FOLDER>/backups`), and for a bucket
//! `KEMLOCK_BACKUP_S3_ACCESS_KEY_ID`, `KEMLOCK_BACKUP_S3_SECRET_ACCESS_KEY`,
//! `KEMLOCK_BACKUP_S3_ENDPOINT`, `KEMLOCK_BACKUP_S3_REGION` (default `us-east-1`) and
//! `KEMLOCK_BACKUP_S3_PATH_STYLE` (default true). `KEMLOCK_LOW_MEMORY=true` compresses at zstd
//! level 1. The admin console saves the same four as settings (`backup_schedule`, `backup_keep`,
//! `backup_destination`, `backup_recipient`); the environment still wins, and the schedule follows
//! what is saved without a restart ([`spawn_backups`]).

use crate::config::Config;
use crate::live::{SettingsWatch, Snapshot};
use kemlock_app::privacy::PrivacySettings;
use kemlock_backup::{
    BackupReport, BackupSettings, DataLayout, DestinationConfig, Kind, S3Destination, STATUS_KEY,
    Schedule, Source, create_backup, status_json,
};
use kemlock_blob::{Backend, BlobConfig};
use kemlock_crypto::rand;
use kemlock_store_sql::SqlStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// The lease that makes the backup run on one replica at a time.
pub const BACKUP_LEASE: &str = "backup";
/// How long a replica holds it: longer than a backup takes, so a crashed holder is an obstacle
/// only until it lapses.
const LEASE_TTL: time::Duration = time::Duration::hours(2);

fn lookup(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn flag(env: &dyn Fn(&str) -> Option<String>, name: &str, default: bool) -> Result<bool, String> {
    match lookup(env, name).map(|v| v.to_ascii_lowercase()).as_deref() {
        None => Ok(default),
        Some("true" | "1" | "yes" | "on") => Ok(true),
        Some("false" | "0" | "no" | "off") => Ok(false),
        Some(other) => Err(format!("{name} must be true or false, not {other:?}")),
    }
}

/// The backup settings the environment describes. The recipient may be empty: a server that isn't
/// set up for backups has none, and the job and the CLI say so when they need it.
pub fn settings_from_env(
    env: &dyn Fn(&str) -> Option<String>,
    data_folder: &Path,
) -> Result<BackupSettings, String> {
    let schedule = match lookup(env, "KEMLOCK_BACKUP_SCHEDULE") {
        None => Schedule::Off,
        Some(text) => Schedule::parse(&text).ok_or_else(|| {
            format!("KEMLOCK_BACKUP_SCHEDULE must be off, nightly or 6h, not {text:?}")
        })?,
    };
    let keep = match lookup(env, "KEMLOCK_BACKUP_KEEP") {
        None => 30,
        Some(text) => match text.parse::<u32>() {
            Ok(n @ (7 | 14 | 30)) => n,
            _ => {
                return Err(format!(
                    "KEMLOCK_BACKUP_KEEP must be 7, 14 or 30, not {text:?}"
                ));
            }
        },
    };
    let destination = match lookup(env, "KEMLOCK_BACKUP_DEST") {
        None => DestinationConfig::Local {
            folder: data_folder.join("backups"),
        },
        Some(text) => match text.strip_prefix("s3://") {
            None => DestinationConfig::Local {
                folder: PathBuf::from(text),
            },
            Some(rest) => {
                let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
                if bucket.is_empty() {
                    return Err("KEMLOCK_BACKUP_DEST names no bucket".to_owned());
                }
                let need = |name: &str| {
                    lookup(env, name).ok_or_else(|| {
                        format!("{name} is needed when KEMLOCK_BACKUP_DEST is an s3:// address")
                    })
                };
                DestinationConfig::S3(S3Destination {
                    endpoint: lookup(env, "KEMLOCK_BACKUP_S3_ENDPOINT"),
                    bucket: bucket.to_owned(),
                    region: lookup(env, "KEMLOCK_BACKUP_S3_REGION")
                        .unwrap_or_else(|| "us-east-1".to_owned()),
                    access_key_id: need("KEMLOCK_BACKUP_S3_ACCESS_KEY_ID")?,
                    secret_access_key: need("KEMLOCK_BACKUP_S3_SECRET_ACCESS_KEY")?,
                    path_style: flag(env, "KEMLOCK_BACKUP_S3_PATH_STYLE", true)?,
                    prefix: prefix.trim_matches('/').to_owned(),
                })
            }
        },
    };
    let low_memory = flag(env, "KEMLOCK_LOW_MEMORY", false)?;
    Ok(BackupSettings {
        schedule,
        keep,
        destination,
        recipient: lookup(env, "KEMLOCK_BACKUP_RECIPIENT").unwrap_or_default(),
        zstd_level: if low_memory { 1 } else { 3 },
    })
}

/// The settings from the process environment.
pub fn settings(config: &Config) -> Result<BackupSettings, String> {
    settings_from_env(&|name| std::env::var(name).ok(), &config.data_folder)
}

/// The file of a SQLite database URL (`sqlite://path?mode=rwc`); `None` for another database and
/// for one in memory.
pub fn sqlite_file(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("sqlite://")?;
    let path = rest.split('?').next().unwrap_or(rest);
    if path.is_empty() || path.contains(":memory:") {
        return None;
    }
    Some(PathBuf::from(path))
}

/// A path with `suffix` added to its file name (`db.sqlite3` and `-wal`).
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Where the server's files are: what goes into an archive besides the rows.
pub fn layout(config: &Config) -> Result<DataLayout, String> {
    let blobs = BlobConfig::from_env(&config.data_folder).map_err(|e| e.to_string())?;
    let attachments_folder = match blobs.backend {
        Backend::Local { folder } => Some(folder),
        Backend::S3(_) => None,
    };
    let skip = sqlite_file(&config.database_url)
        .map(|file| vec![with_suffix(&file, "-wal"), with_suffix(&file, "-shm"), file])
        .unwrap_or_default();
    Ok(DataLayout {
        data_folder: config.data_folder.clone(),
        attachments_folder,
        config_file: config.config_file.clone(),
        skip,
    })
}

/// On PostgreSQL and MySQL, writes a backup archive before pending migrations change the schema,
/// when backups are set up (a recipient is named). SQLite is copied by the store itself. An error
/// here stops the start: a migration over data nobody could restore is worse than a start that
/// waits for the operator.
pub async fn before_migration(config: &Config) -> Result<(), String> {
    // A bad backup setting stops the start whatever the database is, so it is found now.
    let settings = settings(config)?;
    if sqlite_file(&config.database_url).is_some() || config.database_url.contains(":memory:") {
        return Ok(());
    }
    if settings.recipient.is_empty() {
        return Ok(());
    }
    let pending = kemlock_store_sql::pending_migrations(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    if pending == 0 {
        return Ok(());
    }
    tracing::info!(
        pending,
        "writing a backup archive before the database is migrated"
    );
    let layout = layout(config)?;
    let report = create_backup(
        Source::Url(&config.database_url),
        &settings,
        &layout,
        Kind::PreMigration,
        30,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(|e| format!("couldn't write the backup before migrating: {e}"))?;
    tracing::info!(archive = %report.name, size = report.size, "the backup before migrating is stored");
    Ok(())
}

/// One backup now, with the retention period from the saved settings, and its outcome saved for
/// the admin console. `kemlock-cli backup` and the schedule call it.
pub async fn run_backup(
    store: &SqlStore,
    settings: &BackupSettings,
    layout: &DataLayout,
) -> Result<BackupReport, kemlock_backup::BackupError> {
    let now = OffsetDateTime::now_utc();
    let retention_days = PrivacySettings::retention(store)
        .await
        .map_or(30, |r| r.backup_days);
    let outcome = create_backup(
        Source::Store(store),
        settings,
        layout,
        Kind::Backup,
        retention_days,
        now,
    )
    .await;
    if let Err(e) = store
        .put_setting(STATUS_KEY, &status_json(now, &outcome))
        .await
    {
        tracing::warn!(error = %e, "couldn't save the backup's outcome");
    }
    outcome
}

/// A name for this process to hold leases under.
fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// How long to wait from `now` until `at`, never less than a second.
fn until(now: OffsetDateTime, at: OffsetDateTime) -> Duration {
    let seconds = (at - now).whole_seconds().max(1);
    Duration::from_secs(u64::try_from(seconds).unwrap_or(1))
}

/// How often the schedule looks at the settings again while it waits.
const RECHECK: Duration = Duration::from_secs(30);

/// Where a backup folder saved in the console is: `folder` inside the data folder, checked now
/// rather than when it was saved. The data folder and the folder are resolved (symlinks included)
/// and the result must lie under the data folder, must not be the data folder itself, and must not
/// be one of the store's own files or folders (the database, attachments, Sends, the server key).
pub fn folder_inside(data_folder: &Path, folder: &str) -> Result<PathBuf, String> {
    use kemlock_app::admin::settings::RESERVED_DATA_NAMES;
    let bad = |why: &str| format!("the backup folder {folder:?} {why}");
    let root = data_folder
        .canonicalize()
        .map_err(|e| format!("the data folder can't be resolved: {e}"))?;
    let mut target = root.clone();
    for part in folder.replace('\', "/").split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." {
            return Err(bad("must not use . or .."));
        }
        target.push(part);
    }
    if target == root {
        return Err(bad("is the data folder itself"));
    }
    // What exists is resolved, so a symlink can't lead out; what doesn't is made under it later.
    let mut existing = target.as_path();
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| bad("has no existing parent"))?;
    }
    let real = existing
        .canonicalize()
        .map_err(|e| bad(&format!("can't be resolved: {e}")))?;
    let rest = target.strip_prefix(existing).unwrap_or(Path::new(""));
    let resolved = real.join(rest);
    let under = resolved
        .strip_prefix(&root)
        .map_err(|_| bad("leaves the data folder"))?;
    let first = under
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .ok_or_else(|| bad("is the data folder itself"))?;
    if RESERVED_DATA_NAMES.iter().any(|name| first.starts_with(name)) {
        return Err(bad("is where the server keeps its own files"));
    }
    Ok(resolved)
}

/// The backup settings the running server follows: what the snapshot says (the environment, then
/// the config file, then what the console saved), and the environment for what is no setting
/// (the bucket's keys, `KEMLOCK_LOW_MEMORY`). A folder the console saved is inside the data
/// folder; one the environment names is taken as it is.
pub fn settings_from_snapshot(
    snapshot: &Snapshot,
    env: &dyn Fn(&str) -> Option<String>,
    data_folder: &Path,
) -> Result<BackupSettings, String> {
    let destination = if snapshot.backup_destination_saved && !snapshot.backup_destination.is_empty()
    {
        folder_inside(data_folder, &snapshot.backup_destination)?
            .display()
            .to_string()
    } else {
        snapshot.backup_destination.clone()
    };
    settings_from_env(
        &|name| match name {
            "KEMLOCK_BACKUP_SCHEDULE" => Some(snapshot.backup_schedule.clone()),
            "KEMLOCK_BACKUP_KEEP" => Some(snapshot.backup_keep.clone()),
            "KEMLOCK_BACKUP_DEST" => Some(destination.clone()),
            "KEMLOCK_BACKUP_RECIPIENT" => Some(snapshot.backup_recipient.clone()),
            other => env(other),
        },
        data_folder,
    )
}

/// Starts the schedule. The task looks at the settings every [`RECHECK`] and again when a backup
/// is due, so turning backups on or off, or changing the schedule, the count, the folder or the
/// recipient, counts without a restart. It runs a backup at each time the schedule names, on one
/// replica at a time, and ends when the handle is aborted or the runtime stops.
pub fn spawn_backups(
    store: SqlStore,
    watch: Arc<SettingsWatch>,
    layout: DataLayout,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let holder = holder_name();
        let mut told = String::new();
        // The settings now, or why there are none: said once each time the reason changes.
        let current = |told: &mut String| -> Option<BackupSettings> {
            let settings = settings_from_snapshot(
                &watch.current(),
                &|name| std::env::var(name).ok(),
                &layout.data_folder,
            );
            let problem = match &settings {
                Err(e) => e.clone(),
                Ok(s) if s.schedule != Schedule::Off && s.recipient.is_empty() => {
                    "backups are scheduled but no age recipient is set; none will be made"
                        .to_owned()
                }
                Ok(_) => String::new(),
            };
            if problem != *told {
                if !problem.is_empty() {
                    tracing::warn!("{problem}");
                }
                *told = problem;
            }
            settings
                .ok()
                .filter(|s| s.schedule != Schedule::Off && !s.recipient.is_empty())
        };
        loop {
            let Some(settings) = current(&mut told) else {
                tokio::time::sleep(RECHECK).await;
                continue;
            };
            let now = OffsetDateTime::now_utc();
            let Some(next) = settings.schedule.next_after(now) else {
                tokio::time::sleep(RECHECK).await;
                continue;
            };
            let wait = until(now, next);
            if wait > RECHECK {
                tokio::time::sleep(RECHECK).await;
                continue;
            }
            tokio::time::sleep(wait).await;
            // What was saved while waiting counts: the backup is made with the settings now.
            let Some(settings) = current(&mut told) else {
                continue;
            };
            match store.try_lease(BACKUP_LEASE, &holder, LEASE_TTL).await {
                Ok(true) => {
                    match run_backup(&store, &settings, &layout).await {
                        Ok(report) => tracing::info!(
                            archive = %report.name,
                            size = report.size,
                            pruned = report.pruned.len(),
                            "backup stored"
                        ),
                        Err(e) => tracing::error!(error = %e, "the backup failed"),
                    }
                    if let Err(e) = store.release_lease(BACKUP_LEASE, &holder).await {
                        tracing::warn!(error = %e, "couldn't release the backup lease");
                    }
                }
                Ok(false) => tracing::debug!("another replica holds the backup lease"),
                Err(e) => tracing::warn!(error = %e, "couldn't take the backup lease"),
            }
            // Never run twice for one slot: wait out the second the slot started in.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(vars: &[(&str, &str)]) -> Result<BackupSettings, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        settings_from_env(&|name| map.get(name).cloned(), Path::new("data"))
    }

    #[test]
    fn backups_are_off_by_default_into_the_data_folder() {
        let s = settings(&[]).expect("defaults");
        assert_eq!(s.schedule, Schedule::Off);
        assert_eq!(s.keep, 30);
        assert_eq!(s.recipient, "");
        assert_eq!(s.zstd_level, 3);
        assert_eq!(
            s.destination,
            DestinationConfig::Local {
                folder: PathBuf::from("data").join("backups")
            }
        );
    }

    #[test]
    fn a_schedule_a_keep_count_and_a_recipient_are_read() {
        let s = settings(&[
            ("KEMLOCK_BACKUP_SCHEDULE", "6h"),
            ("KEMLOCK_BACKUP_KEEP", "14"),
            ("KEMLOCK_BACKUP_RECIPIENT", " age1abc "),
            ("KEMLOCK_BACKUP_DEST", "/mnt/nas/kemlock"),
            ("KEMLOCK_LOW_MEMORY", "true"),
        ])
        .expect("valid");
        assert_eq!(s.schedule, Schedule::EverySixHours);
        assert_eq!(s.keep, 14);
        assert_eq!(s.recipient, "age1abc");
        assert_eq!(s.zstd_level, 1);
        assert_eq!(
            s.destination,
            DestinationConfig::Local {
                folder: PathBuf::from("/mnt/nas/kemlock")
            }
        );
    }

    #[test]
    fn a_bucket_needs_its_keys() {
        let s = settings(&[
            ("KEMLOCK_BACKUP_DEST", "s3://vault-backups/kemlock/prod/"),
            ("KEMLOCK_BACKUP_S3_ACCESS_KEY_ID", "AKID"),
            ("KEMLOCK_BACKUP_S3_SECRET_ACCESS_KEY", "secret"),
            ("KEMLOCK_BACKUP_S3_ENDPOINT", "https://s3.example.org"),
        ])
        .expect("valid");
        match s.destination {
            DestinationConfig::S3(s3) => {
                assert_eq!(s3.bucket, "vault-backups");
                assert_eq!(s3.prefix, "kemlock/prod");
                assert_eq!(s3.region, "us-east-1");
                assert!(s3.path_style);
                assert_eq!(s3.endpoint.as_deref(), Some("https://s3.example.org"));
            }
            other => panic!("expected a bucket, got {other:?}"),
        }
        let error = settings(&[("KEMLOCK_BACKUP_DEST", "s3://bucket/x")]).expect_err("no keys");
        assert!(error.contains("KEMLOCK_BACKUP_S3_ACCESS_KEY_ID"), "{error}");
        assert!(settings(&[("KEMLOCK_BACKUP_DEST", "s3:///x")]).is_err());
    }

    #[test]
    fn bad_values_say_which_setting() {
        for (name, value) in [
            ("KEMLOCK_BACKUP_SCHEDULE", "weekly"),
            ("KEMLOCK_BACKUP_KEEP", "10"),
            ("KEMLOCK_BACKUP_KEEP", "many"),
            ("KEMLOCK_LOW_MEMORY", "maybe"),
        ] {
            let error = settings(&[(name, value)]).expect_err("refused");
            assert!(error.contains(name), "{name}: {error}");
        }
    }

    #[test]
    fn the_sqlite_file_is_read_from_the_url() {
        assert_eq!(
            sqlite_file("sqlite://data/db.sqlite3?mode=rwc"),
            Some(PathBuf::from("data/db.sqlite3"))
        );
        assert_eq!(sqlite_file("sqlite::memory:"), None);
        assert_eq!(
            sqlite_file("sqlite://x?mode=memory&cache=shared"),
            Some(PathBuf::from("x"))
        );
        assert_eq!(sqlite_file("postgres://u@h/db"), None);
        assert_eq!(
            with_suffix(Path::new("data/db.sqlite3"), "-wal"),
            PathBuf::from("data/db.sqlite3-wal")
        );
    }

    #[test]
    fn the_layout_leaves_out_the_database_and_follows_the_attachment_folder() {
        let config = Config::from_sources(
            &|name| match name {
                "DATA_FOLDER" => Some("/data".to_owned()),
                _ => None,
            },
            None,
        )
        .expect("valid");
        let layout = layout(&config).expect("a layout");
        assert_eq!(layout.data_folder, PathBuf::from("/data"));
        assert_eq!(
            layout.attachments_folder,
            Some(PathBuf::from("/data").join("attachments"))
        );
        assert!(layout.skip.contains(&PathBuf::from("/data/db.sqlite3")));
        assert!(layout.skip.contains(&PathBuf::from("/data/db.sqlite3-wal")));
        assert!(layout.skip.contains(&PathBuf::from("/data/db.sqlite3-shm")));
    }

    #[test]
    fn a_saved_folder_stays_under_the_data_folder_and_off_the_stores_own_files() {
        let dir = tempfile::tempdir().expect("a folder");
        let root = dir.path().canonicalize().expect("resolves");
        std::fs::create_dir(root.join("attachments")).expect("made");
        assert_eq!(
            folder_inside(&root, "nas/backups").expect("fine"),
            root.join("nas").join("backups")
        );
        for bad in [".", "", "..", "a/../..", "attachments", "Attachments/x", "db", "server.key"] {
            assert!(folder_inside(&root, bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_lead_out_of_the_data_folder() {
        let dir = tempfile::tempdir().expect("a folder");
        let outside = tempfile::tempdir().expect("another folder");
        let root = dir.path().canonicalize().expect("resolves");
        std::os::unix::fs::symlink(outside.path(), root.join("out")).expect("linked");
        assert!(folder_inside(&root, "out").is_err());
        assert!(folder_inside(&root, "out/deeper").is_err());
        // A link to a folder that is the store's own is refused too.
        std::fs::create_dir(root.join("attachments")).expect("made");
        std::os::unix::fs::symlink(root.join("attachments"), root.join("innocent")).expect("linked");
        assert!(folder_inside(&root, "innocent").is_err());
    }

    #[test]
    fn the_wait_is_never_shorter_than_a_second() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            until(now, now + time::Duration::hours(1)),
            Duration::from_secs(3600)
        );
        assert_eq!(
            until(now, now - time::Duration::hours(1)),
            Duration::from_secs(1)
        );
    }
}
