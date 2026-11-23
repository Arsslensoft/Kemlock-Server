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

async fn open_sqlite(url: &str, options: &StoreOptions) -> Result<Pools, StoreError> {
    let memory = is_memory(url);
    let sync = match options.sqlite_sync {
        SqliteSync::Full => SqliteSynchronous::Full,
        SqliteSync::Normal => SqliteSynchronous::Normal,
    };

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
            .synchronous(sync);
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
