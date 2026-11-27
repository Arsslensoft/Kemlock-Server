//! The backup job: take a snapshot of the database, pack it with the files into an encrypted
//! archive, store it at the destination and prune old archives.
//!
//! Backups run nightly at 03:00 (UTC) or every 6 hours (03:00, 09:00, 15:00 and 21:00 UTC), set in
//! the admin console or by `KEMLOCK_BACKUP_SCHEDULE`, and `kemlock-cli backup` runs one now. The
//! server holds only the public age recipient.

use crate::archive::{ArchiveSpec, parse_recipient, write_archive};
use crate::destination::{ArchiveInfo, Destination, DestinationConfig};
use crate::error::BackupError;
use crate::manifest::{MacKey, Manifest};
use kemlock_store_sql::{Snapshot, SqlStore};
use std::path::PathBuf;
use time::{Duration, OffsetDateTime, Time, UtcOffset};

/// The prefix of the archives the schedule and `kemlock-cli backup` make.
pub const BACKUP_PREFIX: &str = "kemlock-backup-";
/// The prefix of the archive written before a migration on PostgreSQL or MySQL.
pub const PRE_MIGRATION_PREFIX: &str = "kemlock-premigration-";
/// What every archive's name ends with.
pub const ARCHIVE_SUFFIX: &str = ".tar.zst.age";

/// The `settings` key the last backup's outcome is kept under, for the admin console.
pub const STATUS_KEY: &str = "backup.status";

/// How often backups run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    Off,
    /// Every night at 03:00 UTC.
    Nightly,
    /// At 03:00, 09:00, 15:00 and 21:00 UTC.
    EverySixHours,
}

impl Schedule {
    pub fn parse(text: &str) -> Option<Schedule> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" | "" => Some(Schedule::Off),
            "nightly" | "daily" | "03:00" => Some(Schedule::Nightly),
            "6h" | "6 h" | "every-6-hours" | "6-hourly" => Some(Schedule::EverySixHours),
            _ => None,
        }
    }

    fn hours(self) -> &'static [u8] {
        match self {
            Schedule::Off => &[],
            Schedule::Nightly => &[3],
            Schedule::EverySixHours => &[3, 9, 15, 21],
        }
    }

    /// The first run strictly after `now`; `None` when backups are off.
    pub fn next_after(self, now: OffsetDateTime) -> Option<OffsetDateTime> {
        let hours = self.hours();
        let first = *hours.first()?;
        let day = now.to_offset(UtcOffset::UTC);
        for hour in hours {
            let at = day.replace_time(Time::from_hms(*hour, 0, 0).ok()?);
            if at > now {
                return Some(at);
            }
        }
        Some((day + Duration::days(1)).replace_time(Time::from_hms(first, 0, 0).ok()?))
    }
}

/// The settings of the job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSettings {
    pub schedule: Schedule,
    /// How many backups to keep: 7, 14 or 30.
    pub keep: u32,
    pub destination: DestinationConfig,
    /// The operator's age public key (`age1...`).
    pub recipient: String,
    /// zstd's level: 3 by default, 1 in low-RAM mode.
    pub zstd_level: i32,
}

/// Where the server's files are, for the archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataLayout {
    pub data_folder: PathBuf,
    /// The attachments folder when files are on disk; `None` when they are in a bucket.
    pub attachments_folder: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    /// The SQLite database and its `-wal` and `-shm` files, which never go into an archive.
    pub skip: Vec<PathBuf>,
    /// The key the archive's manifest is authenticated with, derived from `server.key`; `None`
    /// when the server has no key at hand, which makes an archive a restore takes only on request.
    pub mac_key: Option<MacKey>,
}

/// What a backup did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupReport {
    pub name: String,
    pub size: u64,
    pub manifest: Manifest,
    /// Archives deleted by the pruning that followed.
    pub pruned: Vec<String>,
}

/// What is snapshotted.
#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    /// An open store.
    Store(&'a SqlStore),
    /// A database URL, with no store: for the archive written before a migration changes the
    /// schema, when opening a store would migrate it.
    Url(&'a str),
}

/// Whether an archive is a scheduled (or manual) backup or the one before a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Backup,
    PreMigration,
}

fn stamp(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// An archive's name: `kemlock-backup-20261123T030000Z.tar.zst.age`, or for the one before a
/// migration `kemlock-premigration-0.1.0-20261123T030000Z.tar.zst.age`.
pub fn archive_name(kind: Kind, at: OffsetDateTime) -> String {
    match kind {
        Kind::Backup => format!("{BACKUP_PREFIX}{}{ARCHIVE_SUFFIX}", stamp(at)),
        Kind::PreMigration => format!(
            "{PRE_MIGRATION_PREFIX}{}-{}{ARCHIVE_SUFFIX}",
            env!("CARGO_PKG_VERSION"),
            stamp(at)
        ),
    }
}

/// When an archive was made, from its name.
pub fn archive_time(name: &str) -> Option<OffsetDateTime> {
    let stem = name.strip_suffix(ARCHIVE_SUFFIX)?;
    let stamp = stem.rsplit('-').next()?;
    let bytes = stamp.as_bytes();
    let shaped = bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8]
            .iter()
            .chain(&bytes[9..15])
            .all(u8::is_ascii_digit);
    if !shaped {
        return None;
    }
    let part = |from: usize, to: usize| -> Option<u32> { stamp[from..to].parse().ok() };
    let date = time::Date::from_calendar_date(
        i32::try_from(part(0, 4)?).ok()?,
        time::Month::try_from(u8::try_from(part(4, 6)?).ok()?).ok()?,
        u8::try_from(part(6, 8)?).ok()?,
    )
    .ok()?;
    let at = Time::from_hms(
        u8::try_from(part(9, 11)?).ok()?,
        u8::try_from(part(11, 13)?).ok()?,
        u8::try_from(part(13, 15)?).ok()?,
    )
    .ok()?;
    Some(date.with_time(at).assume_utc())
}

/// Which archives to delete. Of the scheduled backups the newest `keep` stay, and the rest go;
/// beyond the newest one, any older than `cutoff` go too (the retention period). Archives made
/// before a migration are not counted: they go only when older than `cutoff`. Names that are not
/// archives of this server are never touched.
pub fn plan_prune(names: &[String], keep: usize, cutoff: OffsetDateTime) -> Vec<String> {
    let mut backups: Vec<(&String, OffsetDateTime)> = names
        .iter()
        .filter(|n| n.starts_with(BACKUP_PREFIX))
        .filter_map(|n| archive_time(n).map(|t| (n, t)))
        .collect();
    backups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(a.0)));
    let mut doomed: Vec<String> = backups
        .iter()
        .enumerate()
        .filter(|(i, (_, t))| *i >= keep.max(1) || (*i >= 1 && *t < cutoff))
        .map(|(_, (n, _))| (*n).clone())
        .collect();
    doomed.extend(
        names
            .iter()
            .filter(|n| n.starts_with(PRE_MIGRATION_PREFIX))
            .filter(|n| archive_time(n).is_some_and(|t| t < cutoff))
            .cloned(),
    );
    doomed
}

/// Deletes what `plan_prune` says. Returns the names deleted; a deletion that fails is logged and
/// left for the next run.
pub async fn prune(
    destination: &Destination,
    keep: usize,
    cutoff: OffsetDateTime,
) -> Result<Vec<String>, BackupError> {
    let names: Vec<String> = destination
        .list()
        .await?
        .into_iter()
        .map(|a: ArchiveInfo| a.name)
        .collect();
    let mut gone = Vec::new();
    for name in plan_prune(&names, keep, cutoff) {
        match destination.delete(&name).await {
            Ok(()) => gone.push(name),
            Err(e) => tracing::warn!(archive = %name, error = %e, "couldn't prune an old backup"),
        }
    }
    Ok(gone)
}

/// Takes a backup now: a snapshot of the database, the archive, its upload and the pruning.
/// `retention_days` is the backup retention (7 to 365 days).
pub async fn create_backup(
    source: Source<'_>,
    settings: &BackupSettings,
    layout: &DataLayout,
    kind: Kind,
    retention_days: u32,
    now: OffsetDateTime,
) -> Result<BackupReport, BackupError> {
    let recipient = parse_recipient(&settings.recipient)?;
    let destination = Destination::open(&settings.destination)?;
    crate::archive::create_private_dir(&layout.data_folder)
        .map_err(|e| BackupError::io(format!("can't make {}", layout.data_folder.display()), e))?;
    // Work in a folder of the data folder: it is the one place the image lets the server write.
    let work = tempfile::Builder::new()
        .prefix(".kemlock-backup-work-")
        .tempdir_in(&layout.data_folder)
        .map_err(|e| BackupError::io("can't make a working folder", e))?;
    let rows = work.path().join("rows");
    let snapshot: Snapshot = match source {
        Source::Store(store) => store.snapshot_to(&rows).await?,
        Source::Url(url) => kemlock_store_sql::snapshot_database(url, &rows).await?,
    };

    let name = archive_name(kind, now);
    let out = work.path().join(&name);
    let manifest = {
        let layout = layout.clone();
        let out = out.clone();
        let level = settings.zstd_level;
        tokio::task::spawn_blocking(move || {
            let spec = ArchiveSpec {
                snapshot: &snapshot,
                rows: &rows,
                data_folder: &layout.data_folder,
                skip: &layout.skip,
                attachments: layout.attachments_folder.as_deref(),
                config_file: layout.config_file.as_deref(),
                recipient: &recipient,
                mac_key: layout.mac_key.as_ref(),
                zstd_level: level,
                created_at: now,
            };
            write_archive(&spec, &out)
        })
        .await
        .map_err(|e| BackupError::Config(format!("the archive task stopped: {e}")))??
    };
    let size = std::fs::metadata(&out)
        .map_err(|e| BackupError::io(format!("can't read {}", out.display()), e))?
        .len();
    destination.put_file(&name, &out).await?;

    let cutoff = now - Duration::days(i64::from(retention_days));
    let pruned = prune(&destination, settings.keep as usize, cutoff).await?;
    Ok(BackupReport {
        name,
        size,
        manifest,
        pruned,
    })
}

/// The `settings` entry the admin console shows: when the last backup ran and how it ended.
pub fn status_json(at: OffsetDateTime, outcome: &Result<BackupReport, BackupError>) -> String {
    let at = at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let value = match outcome {
        Ok(report) => serde_json::json!({
            "at": at,
            "ok": true,
            "archive": report.name,
            "size": report.size,
            "rows": report.manifest.total_rows(),
            "files": report.manifest.files.len(),
        }),
        Err(e) => serde_json::json!({ "at": at, "ok": false, "error": e.to_string() }),
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn schedules_parse() {
        assert_eq!(Schedule::parse("nightly"), Some(Schedule::Nightly));
        assert_eq!(Schedule::parse(" 6h "), Some(Schedule::EverySixHours));
        assert_eq!(Schedule::parse("off"), Some(Schedule::Off));
        assert_eq!(Schedule::parse(""), Some(Schedule::Off));
        assert_eq!(Schedule::parse("weekly"), None);
    }

    #[test]
    fn the_next_run_is_at_a_fixed_hour_after_now() {
        let at = |s| Schedule::next_after(s, datetime!(2026-11-23 12:00 UTC));
        assert_eq!(at(Schedule::Off), None);
        assert_eq!(at(Schedule::Nightly), Some(datetime!(2026-11-24 03:00 UTC)));
        assert_eq!(
            at(Schedule::EverySixHours),
            Some(datetime!(2026-11-23 15:00 UTC))
        );
        // Exactly on a run's time, the next one is the one after.
        assert_eq!(
            Schedule::EverySixHours.next_after(datetime!(2026-11-23 15:00 UTC)),
            Some(datetime!(2026-11-23 21:00 UTC))
        );
        assert_eq!(
            Schedule::EverySixHours.next_after(datetime!(2026-11-23 22:30 UTC)),
            Some(datetime!(2026-11-24 03:00 UTC))
        );
        assert_eq!(
            Schedule::Nightly.next_after(datetime!(2026-11-23 01:00 UTC)),
            Some(datetime!(2026-11-23 03:00 UTC))
        );
        // A time in another offset is read in UTC.
        assert_eq!(
            Schedule::Nightly.next_after(datetime!(2026-11-23 01:00 -05:00)),
            Some(datetime!(2026-11-24 03:00 UTC))
        );
    }

    #[test]
    fn names_carry_their_time_and_read_back() {
        let at = datetime!(2026-11-23 03:04:05 UTC);
        let name = archive_name(Kind::Backup, at);
        assert_eq!(name, "kemlock-backup-20261123T030405Z.tar.zst.age");
        assert_eq!(archive_time(&name), Some(at));
        let pre = archive_name(Kind::PreMigration, at);
        assert!(pre.starts_with("kemlock-premigration-"));
        assert_eq!(archive_time(&pre), Some(at));
        assert_eq!(archive_time("notes.txt"), None);
        assert_eq!(archive_time("kemlock-backup-garbage.tar.zst.age"), None);
        assert_eq!(
            archive_time("kemlock-backup-20261323T030405Z.tar.zst.age"),
            None
        );
    }

    fn names(days: &[i64]) -> Vec<String> {
        days.iter()
            .map(|d| {
                archive_name(
                    Kind::Backup,
                    datetime!(2026-11-01 03:00 UTC) + Duration::days(*d),
                )
            })
            .collect()
    }

    #[test]
    fn only_the_newest_few_are_kept() {
        let all = names(&[0, 1, 2, 3, 4]);
        let cutoff = datetime!(2026-01-01 00:00 UTC);
        let doomed = plan_prune(&all, 3, cutoff);
        assert_eq!(doomed, vec![all[1].clone(), all[0].clone()]);
    }

    #[test]
    fn archives_older_than_the_retention_go_but_the_newest_never_does() {
        let all = names(&[0, 1, 2]);
        // Everything is older than the cutoff: the newest stays.
        let doomed = plan_prune(&all, 30, datetime!(2027-01-01 00:00 UTC));
        assert_eq!(doomed, vec![all[1].clone(), all[0].clone()]);
        // Nothing is older.
        assert!(plan_prune(&all, 30, datetime!(2026-01-01 00:00 UTC)).is_empty());
    }

    #[test]
    fn other_files_and_premigration_archives_are_handled_on_their_own_terms() {
        let mut all = names(&[0, 1]);
        let pre = archive_name(Kind::PreMigration, datetime!(2026-10-01 03:00 UTC));
        all.push(pre.clone());
        all.push("notes.txt".to_owned());
        all.push("kemlock-backup-garbage.tar.zst.age".to_owned());
        // A pre-migration archive isn't counted against `keep`...
        assert!(plan_prune(&all, 2, datetime!(2026-01-01 00:00 UTC)).is_empty());
        // ...and goes with age. Nothing else is touched.
        let doomed = plan_prune(&all, 2, datetime!(2026-10-15 00:00 UTC));
        assert_eq!(doomed, vec![pre]);
    }

    #[tokio::test]
    async fn pruning_deletes_from_the_destination() {
        let destination = Destination::memory();
        let dir = tempfile::tempdir().expect("a temp dir");
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").expect("written");
        let all = names(&[0, 1, 2]);
        for name in &all {
            destination.put_file(name, &file).await.expect("stored");
        }
        let gone = prune(&destination, 2, datetime!(2026-01-01 00:00 UTC))
            .await
            .expect("pruned");
        assert_eq!(gone, vec![all[0].clone()]);
        let left: Vec<String> = destination
            .list()
            .await
            .expect("listed")
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(left, vec![all[1].clone(), all[2].clone()]);
    }

    #[test]
    fn the_status_says_how_the_last_backup_went() {
        let at = datetime!(2026-11-23 03:00 UTC);
        let failed = status_json(at, &Err(BackupError::Destination("full".to_owned())));
        let parsed: serde_json::Value = serde_json::from_str(&failed).expect("json");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["at"], "2026-11-23T03:00:00Z");
        assert!(parsed["error"].as_str().expect("text").contains("full"));
    }
}
