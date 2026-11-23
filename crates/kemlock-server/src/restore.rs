//! Restoring from a backup, the restore drill, and putting a pre-migration copy back
//! (`kemlock-cli restore`).
//!
//! - [`restore`] replaces this server's database and files with an archive's. It needs the age
//!   identity (the secret half of the recipient the archive was encrypted to) and, when the data
//!   folder has none, the `server.key` that was stored apart: the archive holds the sealed OPAQUE
//!   and token-signing secrets but never the key that opens them.
//! - [`restore_check`] is the drill (`restore --check`): it restores the archive into a scratch
//!   folder, starts a read-only server there and compares row counts and file hashes with the
//!   archive's manifest. It touches nothing else.
//! - [`restore_pre_migration`] puts back the copy of the SQLite database the server made before it
//!   migrated, and says what it did with the database it replaced.

use crate::app::build;
use crate::backups::{sqlite_file, with_suffix};
use crate::config::{Config, LogFormat};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use kemlock_backup::{
    AgeIdentity, Attachments, Manifest, parse_identity, read_archive, verify_unpacked,
};
use kemlock_store_sql::{SnapshotTable, SqlStore};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What `restore` was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreOptions {
    pub archive: PathBuf,
    /// The age identity file (`AGE-SECRET-KEY-1...`).
    pub identity: PathBuf,
    /// A copy of the `server.key` of the server that made the archive.
    pub server_key: Option<PathBuf>,
}

/// What a restore did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    /// When the archive was made.
    pub created_at: String,
    pub tables: usize,
    pub rows: u64,
    pub files: usize,
    pub server_key_installed: bool,
    /// Things the operator should know: what was skipped and why.
    pub notes: Vec<String>,
}

/// What the drill found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrillReport {
    pub created_at: String,
    pub tables: usize,
    pub rows: u64,
    pub files: usize,
    /// A read-only server started over the restored data and answered `/alive` and `/health`.
    pub server_started: bool,
    /// It refused a write.
    pub writes_refused: bool,
}

fn read_identity(path: &Path) -> Result<AgeIdentity, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("can't read the identity file {}: {e}", path.display()))?;
    parse_identity(&text).map_err(|e| e.to_string())
}

/// Decrypts and unpacks the archive into `dest` and checks it against its manifest.
async fn unpack(archive: &Path, identity: &Path, dest: &Path) -> Result<Manifest, String> {
    let identity = read_identity(identity)?;
    let archive = archive.to_owned();
    let dest = dest.to_owned();
    tokio::task::spawn_blocking(move || {
        read_archive(&archive, &identity, &dest).map_err(|e| e.to_string())?;
        verify_unpacked(&dest).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("the unpacking task stopped: {e}"))?
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("can't make {}: {e}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("can't copy {} to {}: {e}", from.display(), to.display()))
}

fn snapshot_tables(manifest: &Manifest) -> Vec<SnapshotTable> {
    manifest
        .tables
        .iter()
        .map(|t| SnapshotTable {
            name: t.name.clone(),
            columns: t.columns.clone(),
            rows: t.rows,
        })
        .collect()
}

/// A key file's 32 bytes.
fn read_server_key(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("can't read the server key {}: {e}", path.display()))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{} must be exactly 32 bytes: is it the server.key file?",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Compares the restored database's row counts with the manifest's.
async fn compare_counts(store: &SqlStore, manifest: &Manifest) -> Result<(), String> {
    let counts = store.row_counts().await.map_err(|e| e.to_string())?;
    for table in &manifest.tables {
        let found = counts
            .iter()
            .find(|(name, _)| *name == table.name)
            .map(|(_, rows)| *rows);
        if found != Some(table.rows) {
            return Err(format!(
                "table {} holds {} rows after the restore, the manifest says {}",
                table.name,
                found.map_or_else(|| "no".to_owned(), |n| n.to_string()),
                table.rows
            ));
        }
    }
    Ok(())
}

fn data_name(path: &str) -> Option<&str> {
    path.strip_prefix("data/").filter(|n| !n.contains('/'))
}

/// Replaces this server's database and files with the archive's. Stop the server first. The
/// database is migrated to this version, then every table is emptied and refilled in one
/// transaction; the data folder's files and the attachments are copied over what is there.
pub async fn restore(config: &Config, options: &RestoreOptions) -> Result<RestoreReport, String> {
    std::fs::create_dir_all(&config.data_folder)
        .map_err(|e| format!("can't make {}: {e}", config.data_folder.display()))?;
    let mut notes = Vec::new();

    // The key first: a restore that can't unseal its secrets afterwards is better refused now.
    let key_path = config.data_folder.join(kemlock_backup::SERVER_KEY_FILE);
    let mut server_key_installed = false;
    if let Some(source) = &options.server_key {
        let wanted = read_server_key(source)?;
        match std::fs::read(&key_path) {
            Ok(existing) if existing != wanted => {
                return Err(format!(
                    "{} is a different server.key from the one given: it would not open the \
                     archive's sealed secrets. Move it away or give that key",
                    key_path.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&key_path, &wanted)
                    .map_err(|e| format!("can't write {}: {e}", key_path.display()))?;
                server_key_installed = true;
            }
            Err(e) => return Err(format!("can't read {}: {e}", key_path.display())),
        }
    } else if !key_path.exists() && config.server_key.is_none() {
        notes.push(
            "no server.key was given and the data folder has none: put the one stored apart in \
             place before starting the server, or its sealed secrets won't open"
                .to_owned(),
        );
    }

    let scratch = tempfile::Builder::new()
        .prefix(".kemlock-restore-")
        .tempdir_in(&config.data_folder)
        .map_err(|e| format!("can't make a working folder: {e}"))?;
    let unpacked = scratch.path().join("unpacked");
    let manifest = unpack(&options.archive, &options.identity, &unpacked).await?;

    // The database.
    let store = SqlStore::connect(&config.database_url)
        .await
        .map_err(|e| format!("can't open the database: {e}"))?;
    let restored = store
        .restore_from(&unpacked.join("db"), &snapshot_tables(&manifest))
        .await;
    let compared = match restored {
        Ok(()) => compare_counts(&store, &manifest).await,
        Err(e) => Err(format!("restoring the rows: {e}")),
    };
    if let Err(e) = store.close().await {
        tracing::warn!(error = %e, "couldn't close the database cleanly");
    }
    compared?;

    // The files.
    let blobs =
        kemlock_blob::BlobConfig::from_env(&config.data_folder).map_err(|e| e.to_string())?;
    let attachments_folder = match blobs.backend {
        kemlock_blob::Backend::Local { folder } => Some(folder),
        kemlock_blob::Backend::S3(_) => None,
    };
    let mut files = 0usize;
    for entry in &manifest.files {
        let from = unpacked.join(&entry.path);
        if let Some(name) = data_name(&entry.path) {
            copy_file(&from, &config.data_folder.join(name))?;
            files += 1;
        } else if let Some(relative) = entry.path.strip_prefix("attachments/") {
            match &attachments_folder {
                Some(folder) => {
                    copy_file(&from, &folder.join(relative))?;
                    files += 1;
                }
                None => {
                    if !notes.iter().any(|n| n.contains("bucket")) {
                        notes.push(
                            "the archive holds attachments but this server keeps them in a \
                             bucket: they were not copied"
                                .to_owned(),
                        );
                    }
                }
            }
        } else if let Some(name) = entry.path.strip_prefix("config/") {
            let target = config
                .config_file
                .clone()
                .unwrap_or_else(|| config.data_folder.join(name));
            if target.exists() {
                let beside = with_suffix(&target, ".from-backup");
                copy_file(&from, &beside)?;
                notes.push(format!(
                    "{} exists: the archive's copy is at {}",
                    target.display(),
                    beside.display()
                ));
            } else {
                copy_file(&from, &target)?;
            }
            files += 1;
        }
    }
    if manifest.attachments == Attachments::External {
        notes.push("the archive's attachments were in a bucket and are not part of it".to_owned());
    }
    Ok(RestoreReport {
        created_at: manifest.created_at.clone(),
        tables: manifest.tables.len(),
        rows: manifest.total_rows(),
        files,
        server_key_installed,
        notes,
    })
}

/// The first line's status code of an HTTP/1.x response.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\r' || *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// One request to the drill's server, over a plain TCP connection.
async fn http_status(address: SocketAddr, method: &str, path: &str) -> Result<u16, String> {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|e| format!("can't reach the drill server: {e}"))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("can't ask the drill server: {e}"))?;
    let mut head = [0u8; 512];
    let read = stream
        .read(&mut head)
        .await
        .map_err(|e| format!("the drill server didn't answer: {e}"))?;
    parse_status(&head[..read]).ok_or_else(|| "the drill server's answer isn't HTTP".to_owned())
}

/// The drill's server answers reads and refuses everything else.
async fn read_only(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        next.run(request).await
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "this server is a restore drill and is read-only",
        )
            .into_response()
    }
}

/// The restore drill: restores `archive` into a scratch folder under `work_in`, starts a
/// read-only server there, and compares row counts and file hashes with the manifest. The scratch
/// folder is removed afterwards. `server_key` is the separately stored `server.key`: the server
/// can start only if it unseals the archive's secrets.
pub async fn restore_check(
    archive: &Path,
    identity: &Path,
    server_key: &Path,
    work_in: &Path,
) -> Result<DrillReport, String> {
    std::fs::create_dir_all(work_in)
        .map_err(|e| format!("can't make {}: {e}", work_in.display()))?;
    let key = read_server_key(server_key)?;
    let scratch = tempfile::Builder::new()
        .prefix(".kemlock-drill-")
        .tempdir_in(work_in)
        .map_err(|e| format!("can't make a scratch folder: {e}"))?;

    // 1. Open the archive and check every file and every table's rows against the manifest.
    let unpacked = scratch.path().join("unpacked");
    let manifest = unpack(archive, identity, &unpacked).await?;

    // 2. Lay the files out as a data folder, with the key that was stored apart.
    let data = scratch.path().join("data");
    std::fs::create_dir_all(&data).map_err(|e| format!("can't make {}: {e}", data.display()))?;
    let mut files = 0usize;
    for entry in &manifest.files {
        let from = unpacked.join(&entry.path);
        if let Some(name) = data_name(&entry.path) {
            copy_file(&from, &data.join(name))?;
            files += 1;
        } else if let Some(relative) = entry.path.strip_prefix("attachments/") {
            copy_file(&from, &data.join("attachments").join(relative))?;
            files += 1;
        }
    }
    std::fs::write(data.join(kemlock_backup::SERVER_KEY_FILE), &key)
        .map_err(|e| format!("can't write the server key: {e}"))?;

    // 3. Restore the rows into a SQLite database there and count them.
    let url = format!(
        "sqlite://{}?mode=rwc",
        data.join("db.sqlite3").to_string_lossy().replace('\\', "/")
    );
    let store = SqlStore::connect(&url)
        .await
        .map_err(|e| format!("can't make the scratch database: {e}"))?;
    let restored = store
        .restore_from(&unpacked.join("db"), &snapshot_tables(&manifest))
        .await;
    let counted = match restored {
        Ok(()) => compare_counts(&store, &manifest).await,
        Err(e) => Err(format!("restoring the rows: {e}")),
    };
    if let Err(e) = store.close().await {
        tracing::warn!(error = %e, "couldn't close the scratch database cleanly");
    }
    counted?;

    // 4. Start the server over it, read-only: it unseals the archive's secrets with the key.
    let config = Config {
        domain: "http://127.0.0.1".to_owned(),
        database_url: url,
        data_folder: data,
        address: "127.0.0.1".to_owned(),
        port: 0,
        signups_allowed: false,
        log_level: "warn".to_owned(),
        log_format: LogFormat::Text,
        server_key: None,
        trusted_proxies: Vec::new(),
        ip_header: None,
        browser_extension_ids: Vec::new(),
        source_url: None,
        ignored: Vec::new(),
        config_file: None,
        settings_env: crate::config::settings_env(&|name| std::env::var(name).ok()),
        bitwarden_env: crate::config::bitwarden_env(&|name| std::env::var(name).ok()),
    };
    let built = build(&config).await.map_err(|e| {
        format!(
            "the server wouldn't start from the archive: {e} \
             (is the server key the one the archive's server used?)"
        )
    })?;
    let router = built.router.layer(axum::middleware::from_fn(read_only));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("can't listen for the drill: {e}"))?;
    let address = listener
        .local_addr()
        .map_err(|e| format!("can't listen for the drill: {e}"))?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    let probes = async {
        let alive = http_status(address, "GET", "/alive").await?;
        let health = http_status(address, "GET", "/health").await?;
        let write = http_status(
            address,
            "PUT",
            "/kem/v1/items/00000000-0000-0000-0000-000000000000",
        )
        .await?;
        Ok::<_, String>((alive, health, write))
    }
    .await;
    let _ = stop.send(());
    let _ = server.await;
    if let Err(e) = built.store.close().await {
        tracing::warn!(error = %e, "couldn't close the drill's database cleanly");
    }
    let (alive, health, write) = probes?;
    if alive != 200 {
        return Err(format!(
            "the drill server's /alive answered {alive}, not 200"
        ));
    }
    if health != 200 {
        return Err(format!(
            "the drill server's /health answered {health}, not 200"
        ));
    }
    Ok(DrillReport {
        created_at: manifest.created_at.clone(),
        tables: manifest.tables.len(),
        rows: manifest.total_rows(),
        files,
        server_started: true,
        writes_refused: write == 503,
    })
}

/// The `settings` key the last drill's outcome is kept under, for the admin console, which asks
/// for another drill after 90 days.
pub const DRILL_KEY: &str = "backup.last_drill";

/// The drill's outcome as the admin console reads it.
pub fn drill_json(at: OffsetDateTime, outcome: &Result<DrillReport, String>) -> String {
    let at = at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    match outcome {
        Ok(report) => serde_json::json!({
            "at": at,
            "ok": true,
            "archiveCreatedAt": report.created_at,
            "tables": report.tables,
            "rows": report.rows,
            "files": report.files,
            "serverStarted": report.server_started,
            "writesRefused": report.writes_refused,
        }),
        Err(message) => serde_json::json!({ "at": at, "ok": false, "error": message }),
    }
    .to_string()
}

/// Puts the copy the server made before the upgrade to `version` back as the SQLite database
/// (`kemlock-cli restore --pre-migration <version>`). Stop the server first. The database it
/// replaces, with its `-wal` and `-shm` files, is moved to `backups/replaced-<time>.sqlite3`, so
/// nothing is lost but the writes made since the upgrade are not in the copy. Returns the path of
/// the replaced database.
pub fn restore_pre_migration(config: &Config, version: &str) -> Result<PathBuf, String> {
    if version.is_empty()
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
    {
        return Err(format!("{version:?} isn't a version"));
    }
    let database = sqlite_file(&config.database_url).ok_or_else(|| {
        "this server's database isn't a SQLite file: PostgreSQL and MySQL keep no copy, restore the \
         backup archive written before the upgrade instead"
            .to_owned()
    })?;
    let folder = database
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("backups");
    let copy = folder.join(format!("pre-{version}.sqlite3"));
    if !copy.is_file() {
        let mut have: Vec<String> = std::fs::read_dir(&folder)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix("pre-")
                    .and_then(|n| n.strip_suffix(".sqlite3"))
                    .map(str::to_owned)
            })
            .collect();
        have.sort();
        return Err(format!(
            "there is no {} (copies exist for: {})",
            copy.display(),
            if have.is_empty() {
                "none".to_owned()
            } else {
                have.join(", ")
            }
        ));
    }

    let replaced = folder.join(format!(
        "replaced-{}.sqlite3",
        OffsetDateTime::now_utc().unix_timestamp()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let from = with_suffix(&database, suffix);
        if from.exists() {
            std::fs::rename(&from, with_suffix(&replaced, suffix))
                .map_err(|e| format!("can't move {} aside: {e}", from.display()))?;
        }
    }
    std::fs::copy(&copy, &database)
        .map_err(|e| format!("can't put {} back: {e}", copy.display()))?;
    Ok(replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_in(folder: &Path) -> Config {
        let data = folder.to_string_lossy().replace('\\', "/");
        Config::from_sources(
            &|name| match name {
                "DATA_FOLDER" => Some(data.clone()),
                _ => None,
            },
            None,
        )
        .expect("valid")
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\nx: y\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_status(b"nope"), None);
        assert_eq!(parse_status(b""), None);
    }

    #[test]
    fn only_files_directly_in_data_are_the_data_folders() {
        assert_eq!(
            data_name("data/opaque-setup.sealed"),
            Some("opaque-setup.sealed")
        );
        assert_eq!(data_name("data/a/b"), None);
        assert_eq!(data_name("attachments/ab/c"), None);
    }

    #[test]
    fn the_copy_before_an_upgrade_goes_back_and_the_database_it_replaces_is_kept() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let config = config_in(dir.path());
        let database = dir.path().join("db.sqlite3");
        std::fs::write(&database, b"after the upgrade").expect("db");
        std::fs::write(with_suffix(&database, "-wal"), b"wal").expect("wal");
        std::fs::create_dir_all(dir.path().join("backups")).expect("folder");
        std::fs::write(
            dir.path().join("backups").join("pre-0.1.0.sqlite3"),
            b"before the upgrade",
        )
        .expect("copy");

        let replaced = restore_pre_migration(&config, "0.1.0").expect("restored");

        assert_eq!(std::fs::read(&database).expect("db"), b"before the upgrade");
        assert!(!with_suffix(&database, "-wal").exists());
        assert_eq!(
            std::fs::read(&replaced).expect("kept"),
            b"after the upgrade"
        );
        assert_eq!(
            std::fs::read(with_suffix(&replaced, "-wal")).expect("kept"),
            b"wal"
        );
    }

    #[test]
    fn a_missing_copy_says_which_versions_have_one() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let config = config_in(dir.path());
        std::fs::create_dir_all(dir.path().join("backups")).expect("folder");
        std::fs::write(dir.path().join("backups").join("pre-0.0.9.sqlite3"), b"x").expect("copy");

        let error = restore_pre_migration(&config, "0.1.0").expect_err("no such copy");
        assert!(error.contains("0.0.9"), "{error}");
        assert!(restore_pre_migration(&config, "../../etc").is_err());
        assert!(restore_pre_migration(&config, "").is_err());
    }

    #[test]
    fn only_a_sqlite_database_has_a_copy_to_put_back() {
        let mut config = config_in(Path::new("data"));
        config.database_url = "postgres://u:p@db/kemlock".to_owned();
        let error = restore_pre_migration(&config, "0.1.0").expect_err("not SQLite");
        assert!(error.contains("PostgreSQL"), "{error}");
    }

    #[test]
    fn the_drill_outcome_is_saved_as_json() {
        let at = time::macros::datetime!(2026-11-23 10:00 UTC);
        let ok = drill_json(
            at,
            &Ok(DrillReport {
                created_at: "2026-11-23T03:00:00Z".to_owned(),
                tables: 3,
                rows: 10,
                files: 2,
                server_started: true,
                writes_refused: true,
            }),
        );
        let parsed: serde_json::Value = serde_json::from_str(&ok).expect("json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["rows"], 10);
        let failed = drill_json(at, &Err("boom".to_owned()));
        let parsed: serde_json::Value = serde_json::from_str(&failed).expect("json");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"], "boom");
    }
}
