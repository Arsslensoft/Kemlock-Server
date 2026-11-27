//! `kemlock-cli backup` and `kemlock-cli restore`.
//!
//! ```text
//! kemlock-cli backup [--to <folder|s3://bucket/prefix>] [--recipient <age1...>]
//!                    [--allow-unauthenticated]
//! kemlock-cli restore <archive> --identity <file> [--server-key <file>]
//!                      [--allow-unauthenticated] --yes
//! kemlock-cli restore --check <archive> --identity <file> --server-key <file> [--record]
//!                      [--allow-unauthenticated]
//! kemlock-cli restore --pre-migration <version> --yes
//! ```
//!
//! `backup` takes one backup now with the server's backup settings (`KEMLOCK_BACKUP_*`), the
//! destination and the recipient overridable here. `restore` replaces the database and files with
//! an archive's (stop the server first). `restore --check` is the drill: it restores into a scratch
//! folder, starts a read-only server there and compares row counts and file hashes with the
//! archive's manifest, changing nothing. `restore --pre-migration` puts back the SQLite copy the
//! server made before an upgrade.

use kemlock_server::Config;
use kemlock_server::backups::{layout, run_backup, settings_from_env};
use kemlock_server::restore::{
    DRILL_KEY, RestoreOptions, drill_json, inspect_archive, restore, restore_check,
    restore_pre_migration,
};
use kemlock_store_sql::SqlStore;
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupArgs {
    /// A folder or `s3://bucket/prefix`, instead of `KEMLOCK_BACKUP_DEST`.
    pub(crate) to: Option<String>,
    /// An age public key, instead of `KEMLOCK_BACKUP_RECIPIENT`.
    pub(crate) recipient: Option<String>,
    /// Writes the archive without an authentication code when the server key can't be read.
    pub(crate) allow_unauthenticated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreMode {
    /// Replace this server's data with the archive's.
    Restore { archive: String },
    /// The drill.
    Check { archive: String },
    /// Put back the SQLite copy made before the upgrade to this version.
    PreMigration { version: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreArgs {
    pub(crate) mode: RestoreMode,
    /// The age identity file.
    pub(crate) identity: Option<String>,
    /// The `server.key` that was stored apart.
    pub(crate) server_key: Option<String>,
    /// Confirms a restore, which replaces what is there.
    pub(crate) yes: bool,
    /// With `--check`: save the outcome in the server's database for the admin console.
    pub(crate) record: bool,
    /// Takes an archive that carries no authentication code, or a wrong one, or can't be checked
    /// for want of the server key: for archives made before they were authenticated.
    pub(crate) allow_unauthenticated: bool,
}

fn value(
    name: &str,
    inline: Option<&str>,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<String, String> {
    match inline {
        Some(value) => Ok(value.to_owned()),
        None => rest
            .next()
            .cloned()
            .ok_or_else(|| format!("{name} needs a value")),
    }
}

/// Parses the arguments after `backup`.
pub(crate) fn parse_backup(args: &[String]) -> Result<BackupArgs, String> {
    let mut parsed = BackupArgs {
        to: None,
        recipient: None,
        allow_unauthenticated: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, v)) => (name, Some(v)),
            None => (arg.as_str(), None),
        };
        match name {
            "--to" => parsed.to = Some(value(name, inline, &mut rest)?),
            "--recipient" => parsed.recipient = Some(value(name, inline, &mut rest)?),
            "--allow-unauthenticated" => parsed.allow_unauthenticated = true,
            other => return Err(format!("backup doesn't take {other:?}")),
        }
    }
    Ok(parsed)
}

/// Parses the arguments after `restore`.
pub(crate) fn parse_restore(args: &[String]) -> Result<RestoreArgs, String> {
    let mut archive = None;
    let mut check = false;
    let mut pre_migration = None;
    let mut parsed = RestoreArgs {
        mode: RestoreMode::Restore {
            archive: String::new(),
        },
        identity: None,
        server_key: None,
        yes: false,
        record: false,
        allow_unauthenticated: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, v)) if name.starts_with("--") => (name, Some(v)),
            _ => (arg.as_str(), None),
        };
        match name {
            "--identity" => parsed.identity = Some(value(name, inline, &mut rest)?),
            "--server-key" => parsed.server_key = Some(value(name, inline, &mut rest)?),
            "--pre-migration" => pre_migration = Some(value(name, inline, &mut rest)?),
            "--check" => check = true,
            "--yes" => parsed.yes = true,
            "--record" => parsed.record = true,
            "--allow-unauthenticated" => parsed.allow_unauthenticated = true,
            other if other.starts_with("--") => {
                return Err(format!("restore doesn't take {other:?}"));
            }
            _ => {
                if archive.replace(arg.clone()).is_some() {
                    return Err("restore takes one archive".to_owned());
                }
            }
        }
    }
    parsed.mode = match (pre_migration, archive, check) {
        (Some(version), None, false) => RestoreMode::PreMigration { version },
        (Some(_), _, _) => {
            return Err("--pre-migration takes a version and nothing else but --yes".to_owned());
        }
        (None, Some(archive), true) => RestoreMode::Check { archive },
        (None, Some(archive), false) => RestoreMode::Restore { archive },
        (None, None, _) => {
            return Err("restore needs an archive (or --pre-migration <version>)".to_owned());
        }
    };
    if parsed.record && !matches!(parsed.mode, RestoreMode::Check { .. }) {
        return Err("--record goes with --check".to_owned());
    }
    Ok(parsed)
}

/// What a backup does when it has no `server.key` to make the archive's authentication code with
/// (the file is missing or unreadable and `KEMLOCK_SERVER_KEY` is not set): refuses, unless the
/// operator said to write the archive without a code, which a later restore then takes only with
/// `--allow-unauthenticated`. `Ok(Some(warning))` is to be shown on stderr.
fn without_server_key(
    has_key: bool,
    allow_unauthenticated: bool,
) -> Result<Option<String>, String> {
    match (has_key, allow_unauthenticated) {
        (true, _) => Ok(None),
        (false, true) => Ok(Some(
            "no server.key could be read, so this archive has no authentication code: a restore \
             will refuse it unless told to take it unauthenticated"
                .to_owned(),
        )),
        (false, false) => Err(
            "no server.key could be read (the data folder has none, or it can't be read, and \
             KEMLOCK_SERVER_KEY isn't set), so the archive couldn't be authenticated; fix that, or \
             add --allow-unauthenticated to write it without a code"
                .to_owned(),
        ),
    }
}

/// `kemlock-cli backup`.
pub(crate) async fn run_backup_command(config: &Config, args: BackupArgs) -> u8 {
    let settings = settings_from_env(
        &|name| match name {
            "KEMLOCK_BACKUP_DEST" if args.to.is_some() => args.to.clone(),
            "KEMLOCK_BACKUP_RECIPIENT" if args.recipient.is_some() => args.recipient.clone(),
            other => std::env::var(other).ok(),
        },
        &config.data_folder,
    );
    let settings = match settings {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 2;
        }
    };
    let layout = match layout(config) {
        Ok(layout) => layout,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 2;
        }
    };
    match without_server_key(layout.mac_key.is_some(), args.allow_unauthenticated) {
        Ok(Some(warning)) => eprintln!("kemlock-cli: warning: {warning}"),
        Ok(None) => {}
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 2;
        }
    }
    let store = match SqlStore::connect(&config.database_url).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("kemlock-cli: can't open the database: {e}");
            return 1;
        }
    };
    let outcome = run_backup(&store, &settings, &layout).await;
    let _ = store.close().await;
    match outcome {
        Ok(report) => {
            println!(
                "backup {} stored ({} bytes, {} rows in {} tables, {} files)",
                report.name,
                report.size,
                report.manifest.total_rows(),
                report.manifest.tables.len(),
                report.manifest.files.len()
            );
            for name in &report.pruned {
                println!("pruned {name}");
            }
            println!("server.key is not in the archive: keep a copy apart, a restore needs it");
            0
        }
        Err(e) => {
            eprintln!("kemlock-cli: the backup failed: {e}");
            1
        }
    }
}

fn need(value: &Option<String>, what: &str) -> Result<PathBuf, String> {
    value
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| format!("restore needs {what}"))
}

/// `kemlock-cli restore`.
pub(crate) async fn run_restore_command(config: &Config, args: RestoreArgs) -> u8 {
    match run_restore(config, args).await {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("kemlock-cli: {message}");
            code
        }
    }
}

async fn run_restore(config: &Config, args: RestoreArgs) -> Result<(), (u8, String)> {
    let usage = |message: String| (2u8, message);
    match args.mode {
        RestoreMode::PreMigration { version } => {
            if !args.yes {
                return Err(usage(format!(
                    "restore --pre-migration {version} replaces the database with the copy made \
                     before that upgrade; writes since are lost. Stop the server and add --yes"
                )));
            }
            let replaced = restore_pre_migration(config, &version).map_err(|e| (1, e))?;
            println!(
                "the copy from before the upgrade to {version} is the database again; the one it \
                 replaced is at {}",
                replaced.display()
            );
            Ok(())
        }
        RestoreMode::Check { archive } => {
            let identity = need(&args.identity, "--identity <file>").map_err(usage)?;
            let server_key = need(&args.server_key, "--server-key <file>").map_err(usage)?;
            let outcome = restore_check(
                &PathBuf::from(&archive),
                &identity,
                &server_key,
                &config.data_folder,
                args.allow_unauthenticated,
            )
            .await;
            if args.record {
                match SqlStore::connect(&config.database_url).await {
                    Ok(store) => {
                        let saved = store
                            .put_setting(
                                DRILL_KEY,
                                &drill_json(OffsetDateTime::now_utc(), &outcome),
                            )
                            .await;
                        let _ = store.close().await;
                        if let Err(e) = saved {
                            eprintln!("kemlock-cli: couldn't record the drill: {e}");
                        }
                    }
                    Err(e) => eprintln!("kemlock-cli: couldn't record the drill: {e}"),
                }
            }
            let report = outcome.map_err(|e| (1, format!("the drill failed: {e}")))?;
            println!(
                "drill passed: archive of {} restored into a scratch folder",
                report.created_at
            );
            println!(
                "  {} tables, {} rows and {} files match the manifest",
                report.tables, report.rows, report.files
            );
            println!(
                "  a read-only server started over it{}",
                if report.writes_refused {
                    " and refused a write"
                } else {
                    ""
                }
            );
            if report.authenticated {
                println!("  the archive's authentication code matches the server key");
            } else {
                println!("  the archive was NOT authenticated (--allow-unauthenticated)");
            }
            Ok(())
        }
        RestoreMode::Restore { archive } => {
            let identity = need(&args.identity, "--identity <file>").map_err(usage)?;
            let options = RestoreOptions {
                archive: PathBuf::from(&archive),
                identity,
                server_key: args.server_key.as_deref().map(PathBuf::from),
                allow_unauthenticated: args.allow_unauthenticated,
            };
            if !args.yes {
                // Before asking for --yes, say which archive this is: when it says it was made,
                // and whether a newer one sits beside it or the file was renamed, so an old
                // archive under a new name is noticed.
                let info = inspect_archive(config, &options)
                    .await
                    .map_err(|e| (1, format!("can't open the archive: {e}")))?;
                println!(
                    "{archive}: made {}, {} tables, {} rows, {} files",
                    info.created_at, info.tables, info.rows, info.files
                );
                for warning in &info.warnings {
                    println!("warning: {warning}");
                }
                return Err(usage(
                    "restore replaces the database and files with the archive's; stop the \
                     server and add --yes (try --check first)"
                        .to_owned(),
                ));
            }
            let report = restore(config, &options)
                .await
                .map_err(|e| (1, format!("the restore failed: {e}")))?;
            println!(
                "restored the archive of {}: {} tables, {} rows, {} files",
                report.created_at, report.tables, report.rows, report.files
            );
            if report.server_key_installed {
                println!("server.key was put in place");
            }
            for note in &report.notes {
                println!("note: {note}");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn backup_takes_a_destination_and_a_recipient() {
        assert_eq!(
            parse_backup(&args(&[])),
            Ok(BackupArgs {
                to: None,
                recipient: None,
                allow_unauthenticated: false,
            })
        );
        assert_eq!(
            parse_backup(&args(&["--to", "/mnt/nas", "--recipient=age1abc"])),
            Ok(BackupArgs {
                to: Some("/mnt/nas".to_owned()),
                recipient: Some("age1abc".to_owned()),
                allow_unauthenticated: false,
            })
        );
        assert!(parse_backup(&args(&["--to"])).is_err());
        assert!(parse_backup(&args(&["--everything"])).is_err());
    }

    #[test]
    fn a_backup_with_no_server_key_is_refused_unless_told_to_go_ahead() {
        assert_eq!(without_server_key(true, false), Ok(None));
        assert_eq!(without_server_key(true, true), Ok(None));
        let warning = without_server_key(false, true)
            .expect("allowed")
            .expect("a warning");
        assert!(warning.contains("no authentication code"), "{warning}");
        let refused = without_server_key(false, false).expect_err("refused");
        assert!(refused.contains("--allow-unauthenticated"), "{refused}");
        assert!(
            parse_backup(&args(&["--allow-unauthenticated"]))
                .expect("parses")
                .allow_unauthenticated
        );
    }

    #[test]
    fn restore_has_three_modes() {
        let restore =
            parse_restore(&args(&["a.age", "--identity", "id.txt", "--yes"])).expect("a restore");
        assert_eq!(
            restore.mode,
            RestoreMode::Restore {
                archive: "a.age".to_owned()
            }
        );
        assert_eq!(restore.identity.as_deref(), Some("id.txt"));
        assert!(restore.yes);

        let check = parse_restore(&args(&[
            "--check",
            "a.age",
            "--identity=id.txt",
            "--server-key",
            "server.key",
            "--record",
        ]))
        .expect("a drill");
        assert_eq!(
            check.mode,
            RestoreMode::Check {
                archive: "a.age".to_owned()
            }
        );
        assert_eq!(check.server_key.as_deref(), Some("server.key"));
        assert!(check.record);

        let pre = parse_restore(&args(&["--pre-migration", "0.1.0", "--yes"])).expect("a copy");
        assert_eq!(
            pre.mode,
            RestoreMode::PreMigration {
                version: "0.1.0".to_owned()
            }
        );
    }

    #[test]
    fn restore_takes_unauthenticated_archives_only_when_told_to() {
        let plain =
            parse_restore(&args(&["a.age", "--identity", "id.txt", "--yes"])).expect("a restore");
        assert!(!plain.allow_unauthenticated);
        let told = parse_restore(&args(&[
            "a.age",
            "--identity",
            "id.txt",
            "--allow-unauthenticated",
            "--yes",
        ]))
        .expect("a restore");
        assert!(told.allow_unauthenticated);
        let drill = parse_restore(&args(&["--check", "a.age", "--allow-unauthenticated"]))
            .expect("a drill");
        assert!(drill.allow_unauthenticated);
    }

    #[test]
    fn bad_restore_arguments_are_refused() {
        assert!(parse_restore(&args(&[])).is_err(), "no archive");
        assert!(
            parse_restore(&args(&["a.age", "b.age"])).is_err(),
            "two archives"
        );
        assert!(parse_restore(&args(&["--pre-migration", "0.1.0", "a.age"])).is_err());
        assert!(
            parse_restore(&args(&["a.age", "--record"])).is_err(),
            "record is for the drill"
        );
        assert!(parse_restore(&args(&["a.age", "--force"])).is_err());
        assert!(parse_restore(&args(&["a.age", "--identity"])).is_err());
    }

    #[test]
    fn a_missing_flag_is_named() {
        let error = need(&None, "--identity <file>").expect_err("missing");
        assert!(error.contains("--identity"));
        assert_eq!(
            need(&Some("x".to_owned()), "--identity <file>"),
            Ok(PathBuf::from("x"))
        );
    }
}
