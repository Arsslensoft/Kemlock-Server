//! Opening the database: pools, SQLite's pragmas, and the one-writer rule.
//!
//! SQLite runs in WAL mode with one writer and a pool of readers, as the performance design
//! asks. Every write goes through the writer pool, which holds a single connection, so writers
//! queue inside the pool and never meet `SQLITE_BUSY`; reads go through the reader pool and never
//! wait for a write. PostgreSQL and MySQL use one ordinary pool for both.

use crate::error::map_db;
use kemlock_app::ports::StoreError;
use sea_orm::sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How durable SQLite commits are. `Full` (the default) syncs the WAL on every commit, so a
/// power cut loses no write the server acknowledged; `Normal` may lose the last few commits in a
/// power cut (never corrupts) and is faster. An admin can choose it in Server settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SqliteSync {
    #[default]
    Full,
    Normal,
}

/// Knobs for [`crate::SqlStore::connect_with`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreOptions {
    /// SQLite's `synchronous` pragma.
    pub sqlite_sync: SqliteSync,
    /// Size of SQLite's reader pool: 4 by default, 1 in low-RAM mode.
    pub sqlite_readers: u32,
    /// Size of the PostgreSQL and MySQL pool.
    pub pool_size: u32,
}

impl Default for StoreOptions {
    fn default() -> Self {
        StoreOptions {
            sqlite_sync: SqliteSync::Full,
            sqlite_readers: 4,
            pool_size: 10,
        }
    }
}

/// The two connections the store uses. On PostgreSQL and MySQL, and for an in-memory SQLite
/// database, they are the same pool.
#[derive(Clone, Debug)]
pub(crate) struct Pools {
    pub(crate) writer: DatabaseConnection,
    pub(crate) reader: DatabaseConnection,
}

/// The URL's scheme: `sqlite`, `postgres`, `postgresql` or `mysql`.
fn scheme(url: &str) -> &str {
    url.split(':').next().unwrap_or("")
}

pub(crate) async fn open(url: &str, options: &StoreOptions) -> Result<Pools, StoreError> {
    match scheme(url) {
        "sqlite" => open_sqlite(url, options).await,
        "postgres" | "postgresql" | "mysql" => open_pooled(url, options).await,
        other => Err(StoreError::Backend(format!(
            "unsupported database URL scheme {other:?}; use sqlite:, postgres: or mysql:"
        ))),
    }
}

/// A connect error, with the URL (it may hold a password) taken out of the message.
pub(crate) fn connect_error(url: &str, err: sea_orm::DbErr) -> StoreError {
    match map_db(err) {
        StoreError::Backend(message) => StoreError::Backend(format!(
            "could not connect to the database: {}",
            message.replace(url, "<database url>")
        )),
        other => other,
    }
}

async fn open_pooled(url: &str, options: &StoreOptions) -> Result<Pools, StoreError> {
    let mut connect = ConnectOptions::new(url.to_owned());
    connect
        .max_connections(options.pool_size.max(1))
        .sqlx_logging(false);
    let db = Database::connect(connect)
        .await
        .map_err(|e| connect_error(url, e))?;
    Ok(Pools {
        reader: db.clone(),
        writer: db,
    })
}

fn is_memory(url: &str) -> bool {
    url.contains(":memory:") || url.contains("mode=memory")
}

/// The file of a SQLite URL (`sqlite://path?mode=rwc`, `sqlite:path`); `None` for one in memory.
fn sqlite_file(url: &str) -> Option<PathBuf> {
    if is_memory(url) || url.contains("mode=ro") {
        return None;
    }
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))?;
    let path = rest.split('?').next().unwrap_or(rest);
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Whether the URL lets SQLite make the database file: `mode=rwc` or no `mode` at all. With
/// `mode=rw` the file must exist already, and a missing one is the operator's mistake to hear
/// about, not for the server to paper over with an empty database.
fn may_create(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return true;
    };
    query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("mode="))
        .all(|mode| mode == "rwc")
}

/// `path` with `suffix` added to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Makes `path` readable and writable by its owner only, when it is anything more. A no-op off
/// Unix. Used for what holds the whole vault: the database and the copies made of it.
pub(crate) fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Before SQLite opens its file: a new one is made readable by its owner only (SQLite gives the
/// `-wal` and `-shm` files the main file's mode), and an existing one, and its `-wal` and `-shm`,
/// are tightened to that. The server's data folder is 0700 where the server made it, but a
/// database in a folder someone else made, or one an older version made, would otherwise be 0644.
fn keep_database_private(url: &str) {
    let Some(file) = sqlite_file(url) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if may_create(url) && !file.exists() {
            // An empty file is a new database to SQLite. If the folder isn't there, SQLite says
            // so when it connects.
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file);
        }
    }
    for path in [
        file.clone(),
        with_suffix(&file, "-wal"),
        with_suffix(&file, "-shm"),
    ] {
        match restrict_to_owner(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                file = %path.display(),
                error = %e,
                "couldn't make the database file readable by its owner only"
            ),
        }
    }
}

async fn open_sqlite(url: &str, options: &StoreOptions) -> Result<Pools, StoreError> {
    let memory = is_memory(url);
    let sync = match options.sqlite_sync {
        SqliteSync::Full => SqliteSynchronous::Full,
        SqliteSync::Normal => SqliteSynchronous::Normal,
    };

    keep_database_private(url);
    // The writer first: it creates the file and puts it in WAL mode before any reader opens it.
    let writer = connect_sqlite(url, 1, memory, sync).await?;
    if memory {
        // An in-memory database exists only inside its one connection, so reads share it.
        return Ok(Pools {
            reader: writer.clone(),
            writer,
        });
    }
    let reader = connect_sqlite(url, options.sqlite_readers.max(1), memory, sync).await?;
    // SQLite has made the -wal and -shm files by now; they follow the main file's mode, and this
    // makes sure.
    keep_database_private(url);
    Ok(Pools { writer, reader })
}

async fn connect_sqlite(
    url: &str,
    connections: u32,
    memory: bool,
    sync: SqliteSynchronous,
) -> Result<DatabaseConnection, StoreError> {
    let mut connect = ConnectOptions::new(url.to_owned());
    connect
        .max_connections(connections)
        // An in-memory database dies with its last connection, so keep one open for good.
        .min_connections(u32::from(memory))
        .idle_timeout(None::<Duration>)
        .max_lifetime(None::<Duration>)
        .acquire_timeout(Duration::from_secs(30))
        .sqlx_logging(false);
    connect.map_sqlx_sqlite_opts(move |opts| {
        let opts = opts
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10))
            .synchronous(sync)
            // Freed pages are overwritten with zeros, so a deleted item or account does not
            // linger in the file (and in what a copy of it, a backup or a disk image, holds).
            .pragma("secure_delete", "ON");
        if memory {
            opts
        } else {
            opts.journal_mode(SqliteJournalMode::Wal)
        }
    });
    Database::connect(connect)
        .await
        .map_err(|e| connect_error(url, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes_and_memory_urls_are_told_apart() {
        assert_eq!(scheme("sqlite://data/kemlock.db?mode=rwc"), "sqlite");
        assert_eq!(scheme("postgres://u:p@h/db"), "postgres");
        assert_eq!(scheme("mysql://u@h/db"), "mysql");
        assert!(is_memory("sqlite::memory:"));
        assert!(is_memory("sqlite://x?mode=memory&cache=shared"));
        assert!(!is_memory("sqlite://data/kemlock.db?mode=rwc"));
    }

    #[test]
    fn defaults_are_the_durable_ones() {
        let options = StoreOptions::default();
        assert_eq!(options.sqlite_sync, SqliteSync::Full);
        assert_eq!(options.sqlite_readers, 4);
    }


    fn file_url(path: &Path) -> String {
        format!(
            "sqlite://{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        )
    }

    async fn pragma(db: &DatabaseConnection, name: &str) -> i64 {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        db.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA {name}"),
        ))
        .await
        .expect("the pragma runs")
        .expect("a row")
        .try_get_by_index::<i64>(0)
        .expect("a number")
    }

    #[tokio::test]
    async fn deleted_data_is_overwritten_on_every_connection() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let pools = open(
            &file_url(&dir.path().join("db.sqlite3")),
            &StoreOptions::default(),
        )
        .await
        .expect("opens");
        assert_eq!(pragma(&pools.writer, "secure_delete").await, 1);
        assert_eq!(pragma(&pools.reader, "secure_delete").await, 1);
    }

    #[test]
    fn the_file_is_made_only_when_the_url_lets_sqlite_make_it() {
        assert!(may_create("sqlite://data/db.sqlite3?mode=rwc"));
        assert!(may_create("sqlite://data/db.sqlite3"));
        assert!(may_create("sqlite://data/db.sqlite3?cache=shared&mode=rwc"));
        assert!(!may_create("sqlite://data/db.sqlite3?mode=rw"));
        assert!(!may_create("sqlite://data/db.sqlite3?mode=ro"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_missing_database_is_not_made_when_the_url_says_rw() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let file = dir.path().join("absent.sqlite3");
        let url = format!(
            "sqlite://{}?mode=rw",
            file.to_string_lossy().replace('\\', "/")
        );
        // SQLite refuses, and the server did not make an empty file first.
        assert!(open(&url, &StoreOptions::default()).await.is_err());
        assert!(!file.exists());
    }

    #[test]
    fn the_file_of_a_sqlite_url_is_found() {
        assert_eq!(
            sqlite_file("sqlite://data/db.sqlite3?mode=rwc"),
            Some(PathBuf::from("data/db.sqlite3"))
        );
        assert_eq!(
            sqlite_file("sqlite:///var/lib/kemlock/db"),
            Some(PathBuf::from("/var/lib/kemlock/db"))
        );
        assert_eq!(sqlite_file("sqlite::memory:"), None);
        assert_eq!(sqlite_file("sqlite://x?mode=memory&cache=shared"), None);
        assert_eq!(sqlite_file("sqlite://x?mode=ro"), None);
        assert_eq!(sqlite_file("postgres://u@h/db"), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_database_files_are_readable_by_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).expect("a file").permissions().mode() & 0o777;
        let dir = tempfile::tempdir().expect("a temp dir");

        // A new database is made private from the start.
        let fresh = dir.path().join("fresh.sqlite3");
        let pools = open(&file_url(&fresh), &StoreOptions::default())
            .await
            .expect("opens");
        assert_eq!(mode(&fresh), 0o600);
        for suffix in ["-wal", "-shm"] {
            let side = with_suffix(&fresh, suffix);
            if side.exists() {
                assert_eq!(mode(&side), 0o600, "{suffix}");
            }
        }
        drop(pools);

        // One an older version made, world-readable, is tightened.
        let old = dir.path().join("old.sqlite3");
        std::fs::write(&old, b"").expect("an old file");
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).expect("loosened");
        let pools = open(&file_url(&old), &StoreOptions::default())
            .await
            .expect("opens");
        assert_eq!(mode(&old), 0o600);
        drop(pools);
    }
    #[tokio::test]
    async fn an_unknown_scheme_is_refused_without_echoing_the_url() {
        let err = open("redis://secret@host", &StoreOptions::default())
            .await
            .expect_err("unsupported");
        match err {
            StoreError::Backend(message) => assert!(!message.contains("secret")),
            other => panic!("unexpected {other:?}"),
        }
    }
}
