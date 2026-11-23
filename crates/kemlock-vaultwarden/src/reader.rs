//! Opens a Vaultwarden server's data and reads it into a [`VaultwardenSnapshot`].
//!
//! The database is only ever read: SQLite is opened read-only with `query_only` on, and MySQL and
//! PostgreSQL are read inside one read-only repeatable-read transaction, so every table comes from
//! one moment even while Vaultwarden is running. Before any table is read, the migrations the
//! database has run are compared with the releases this crate accepts (see [`crate::schema`]).

use crate::error::ReadError;
use crate::schema::{self, Dialect, SchemaCheck};
use crate::snapshot::{Cell, DataFiles, SnapshotMeta, Table, VaultwardenSnapshot};
use sqlx::mysql::MySqlConnection;
use sqlx::postgres::PgConnection;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{AssertSqlSafe, ConnectOptions, Connection, Row};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where a Vaultwarden server keeps its rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Database {
    /// A `db.sqlite3` file.
    Sqlite(PathBuf),
    /// A `postgres://` URL.
    Postgres(String),
    /// A `mysql://` URL.
    MySql(String),
}

/// A Vaultwarden server to read: its database and, beside it, the data folder with the
/// attachments, sends, `rsa_key.pem` and `config.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub database: Database,
    /// The data folder. For a SQLite source it is the folder holding `db.sqlite3`; for MySQL and
    /// PostgreSQL it is given separately, and without it no files are read.
    pub folder: Option<PathBuf>,
}

impl Source {
    /// Reads a `--from` value: a data folder (with `db.sqlite3` in it), a `db.sqlite3` file, or
    /// a `mysql://`, `mariadb://`, `postgres://` or `postgresql://` URL. `files` names the data
    /// folder of a MySQL or PostgreSQL server.
    pub fn parse(from: &str, files: Option<&str>) -> Result<Source, ReadError> {
        let lower = from.to_ascii_lowercase();
        let folder = files.map(PathBuf::from);
        if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
            let rest = from.split_once("://").map(|(_, r)| r).unwrap_or_default();
            return Ok(Source {
                database: Database::Postgres(format!("postgres://{rest}")),
                folder,
            });
        }
        if lower.starts_with("mysql://") || lower.starts_with("mariadb://") {
            let rest = from.split_once("://").map(|(_, r)| r).unwrap_or_default();
            return Ok(Source {
                database: Database::MySql(format!("mysql://{rest}")),
                folder,
            });
        }
        let path = Path::new(from);
        if path.is_dir() {
            return Ok(Source {
                database: Database::Sqlite(path.join("db.sqlite3")),
                folder: Some(path.to_path_buf()),
            });
        }
        if path.is_file() {
            return Ok(Source {
                database: Database::Sqlite(path.to_path_buf()),
                folder: path
                    .parent()
                    .map(Path::to_path_buf)
                    .filter(|p| !p.as_os_str().is_empty()),
            });
        }
        Err(ReadError::BadSource(from.to_owned()))
    }

    /// The source as it may be printed: a URL's password is hidden.
    pub fn describe(&self) -> String {
        match &self.database {
            Database::Sqlite(path) => path.display().to_string(),
            Database::Postgres(url) | Database::MySql(url) => redact_url(url),
        }
    }

    fn dialect(&self) -> Dialect {
        match self.database {
            Database::Sqlite(_) => Dialect::Sqlite,
            Database::Postgres(_) => Dialect::Postgres,
            Database::MySql(_) => Dialect::MySql,
        }
    }
}

/// A database URL without its password, for printing.
pub fn redact_url(url: &str) -> String {
    match (url.split_once("://"), url.rfind('@')) {
        (Some((scheme, _)), Some(at)) if at > scheme.len() + 3 => {
            let userinfo = &url[scheme.len() + 3..at];
            let user = userinfo.split(':').next().unwrap_or_default();
            format!("{scheme}://{user}:***@{}", &url[at + 1..])
        }
        _ => url.to_owned(),
    }
}

fn db_err(e: sqlx::Error) -> ReadError {
    ReadError::Database(e.to_string())
}

fn check_schema(dialect: Dialect, versions: &[String]) -> Result<&'static str, ReadError> {
    match schema::check_versions(dialect, versions) {
        SchemaCheck::Supported(release) => Ok(release),
        SchemaCheck::Older { release, missing } => Err(ReadError::SchemaOlder { release, missing }),
        SchemaCheck::Unknown { unknown } => Err(ReadError::SchemaUnknown { unknown }),
    }
}

/// Reads the migration history, checks it, then reads every table, all through `$tx`, which is an
/// open transaction. The three databases have different row types, so this is a macro and not a
/// generic function. The SQL it runs is built from this crate's own constants, never from input.
macro_rules! dump {
    ($tx:expr, $dialect:expr) => {{
        let dialect: Dialect = $dialect;
        let migration_rows = sqlx::query(schema::MIGRATIONS_SQL)
            .fetch_all(&mut *$tx)
            .await
            .map_err(|e| ReadError::NotVaultwarden(e.to_string()))?;
        let mut versions: Vec<String> = Vec::with_capacity(migration_rows.len());
        for row in &migration_rows {
            versions.push(row.try_get_unchecked::<String, _>(0usize).map_err(db_err)?);
        }
        let release = check_schema(dialect, &versions)?;

        let mut tables: Vec<Table> = Vec::with_capacity(schema::TABLES.len());
        for spec in schema::TABLES.iter().copied() {
            let sql = schema::select_sql(spec, dialect);
            let rows = sqlx::query(AssertSqlSafe(sql))
                .fetch_all(&mut *$tx)
                .await
                .map_err(|e| ReadError::Database(format!("reading {}: {e}", spec.name)))?;
            let mut cells_by_row: Vec<Vec<Cell>> = Vec::with_capacity(rows.len());
            for row in &rows {
                let mut cells: Vec<Cell> = Vec::with_capacity(spec.cols.len());
                for (index, col) in spec.cols.iter().enumerate() {
                    let cell = match col.kind {
                        schema::Kind::Text | schema::Kind::Time => row
                            .try_get_unchecked::<Option<String>, _>(index)
                            .map_err(db_err)?
                            .map_or(Cell::Null, Cell::Text),
                        schema::Kind::Int | schema::Kind::Bool => row
                            .try_get_unchecked::<Option<i64>, _>(index)
                            .map_err(db_err)?
                            .map_or(Cell::Null, Cell::Int),
                        schema::Kind::Blob => row
                            .try_get_unchecked::<Option<Vec<u8>>, _>(index)
                            .map_err(db_err)?
                            .map_or(Cell::Null, Cell::Bytes),
                    };
                    cells.push(cell);
                }
                cells_by_row.push(cells);
            }
            tables.push(Table::from_rows(spec, cells_by_row));
        }
        (release, tables)
    }};
}

async fn read_sqlite(path: &Path) -> Result<(&'static str, Vec<Table>), ReadError> {
    if !path.is_file() {
        return Err(ReadError::NoDatabase(path.display().to_string()));
    }
    // Read-only at the file level, and `query_only` as a second lock on the same door. No
    // `journal_mode` is set: sqlx leaves it alone unless asked, and changing it would write.
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(false)
        .pragma("query_only", "ON");
    let mut conn = options.connect().await.map_err(db_err)?;
    // A deferred `BEGIN`: SQLite's snapshot starts with the first read and lasts to the end, so
    // all tables come from one moment, in WAL mode and in rollback-journal mode alike.
    let mut tx = conn.begin().await.map_err(db_err)?;
    let (release, tables) = dump!(tx, Dialect::Sqlite);
    tx.rollback().await.map_err(db_err)?;
    conn.close().await.map_err(db_err)?;
    Ok((release, tables))
}

async fn read_postgres(url: &str) -> Result<(&'static str, Vec<Table>), ReadError> {
    let mut conn = PgConnection::connect(url).await.map_err(db_err)?;
    let mut tx = conn
        .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .await
        .map_err(db_err)?;
    let (release, tables) = dump!(tx, Dialect::Postgres);
    tx.rollback().await.map_err(db_err)?;
    conn.close().await.map_err(db_err)?;
    Ok((release, tables))
}

async fn read_mysql(url: &str) -> Result<(&'static str, Vec<Table>), ReadError> {
    let mut conn = MySqlConnection::connect(url).await.map_err(db_err)?;
    sqlx::raw_sql("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut conn)
        .await
        .map_err(db_err)?;
    let mut tx = conn
        .begin_with("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        .await
        .map_err(db_err)?;
    let (release, tables) = dump!(tx, Dialect::MySql);
    tx.rollback().await.map_err(db_err)?;
    conn.close().await.map_err(db_err)?;
    Ok((release, tables))
}

fn read_text(path: &Path) -> Result<Option<String>, ReadError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ReadError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        }),
    }
}

fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, ReadError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ReadError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        }),
    }
}

fn io_err(path: &Path, e: &std::io::Error) -> ReadError {
    ReadError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    }
}

/// Lists `dir/<a>/<b>` files as `a/b` with their sizes. Vaultwarden keeps attachments as
/// `attachments/<cipher>/<attachment>` and send files as `sends/<send>/<file>`.
fn list_two_levels(dir: &Path) -> Result<BTreeMap<String, u64>, ReadError> {
    let mut found = BTreeMap::new();
    let outer = std::fs::read_dir(dir).map_err(|e| io_err(dir, &e))?;
    for entry in outer {
        let entry = entry.map_err(|e| io_err(dir, &e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let first = entry.file_name().to_string_lossy().into_owned();
        let inner = std::fs::read_dir(&path).map_err(|e| io_err(&path, &e))?;
        for file in inner {
            let file = file.map_err(|e| io_err(&path, &e))?;
            let meta = file.metadata().map_err(|e| io_err(&file.path(), &e))?;
            if meta.is_file() {
                let second = file.file_name().to_string_lossy().into_owned();
                found.insert(format!("{first}/{second}"), meta.len());
            }
        }
    }
    Ok(found)
}

/// Reads the files beside the database. Whatever isn't there stays empty; the plan says so.
pub fn read_files_blocking(root: &Path) -> Result<DataFiles, ReadError> {
    if !root.is_dir() {
        return Err(ReadError::NoFolder(root.display().to_string()));
    }
    let attachments = root.join("attachments");
    let sends = root.join("sends");
    let config_json = read_text(&root.join("config.json"))?;
    if let Some(text) = &config_json {
        serde_json::from_str::<serde_json::Value>(text)
            .map_err(|e| ReadError::BadConfig(e.to_string()))?;
    }
    let mut files = DataFiles {
        root: Some(root.to_path_buf()),
        rsa_key_pem: read_bytes(&root.join("rsa_key.pem"))?,
        rsa_pub_pem: read_bytes(&root.join("rsa_key.pub.pem"))?,
        config_json,
        ..DataFiles::default()
    };
    if attachments.is_dir() {
        files.attachment_files = list_two_levels(&attachments)?;
        files.attachments_dir = Some(attachments);
    }
    if sends.is_dir() {
        files.send_files = list_two_levels(&sends)?;
        files.sends_dir = Some(sends);
    }
    Ok(files)
}

/// Reads a Vaultwarden server: checks the schema version, reads every table in one read-only
/// transaction, then reads the files. Nothing in the source is changed.
pub async fn read_snapshot(source: &Source) -> Result<VaultwardenSnapshot, ReadError> {
    let (release, tables) = match &source.database {
        Database::Sqlite(path) => read_sqlite(path).await?,
        Database::Postgres(url) => read_postgres(url).await?,
        Database::MySql(url) => read_mysql(url).await?,
    };
    let files = match &source.folder {
        Some(folder) => {
            let folder = folder.clone();
            tokio::task::spawn_blocking(move || read_files_blocking(&folder))
                .await
                .map_err(|e| ReadError::Io {
                    path: "data folder".to_owned(),
                    message: e.to_string(),
                })??
        }
        None => DataFiles::default(),
    };
    let meta = SnapshotMeta {
        database: source.dialect().name(),
        release,
        source: source.describe(),
    };
    Ok(VaultwardenSnapshot::from_tables(meta, tables, files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_told_apart_and_normalised() {
        let pg = Source::parse("postgresql://vw:pw@db/vault", Some("/data")).expect("postgres");
        assert_eq!(
            pg.database,
            Database::Postgres("postgres://vw:pw@db/vault".to_owned())
        );
        assert_eq!(pg.folder, Some(PathBuf::from("/data")));

        let my = Source::parse("MariaDB://vw:pw@db/vault", None).expect("mysql");
        assert_eq!(
            my.database,
            Database::MySql("mysql://vw:pw@db/vault".to_owned())
        );
        assert_eq!(my.folder, None);
    }

    #[test]
    fn a_missing_path_is_not_a_source() {
        let err = Source::parse("/no/such/folder/anywhere", None).expect_err("not a source");
        assert!(matches!(err, ReadError::BadSource(_)), "{err}");
    }

    #[test]
    fn a_folder_means_its_db_sqlite3() {
        let dir = std::env::temp_dir();
        let source = Source::parse(&dir.display().to_string(), None).expect("a folder");
        assert_eq!(source.database, Database::Sqlite(dir.join("db.sqlite3")));
        assert_eq!(source.folder, Some(dir));
    }

    #[test]
    fn passwords_in_urls_are_hidden() {
        assert_eq!(
            redact_url("postgres://vw:s3cret@db.example/vault"),
            "postgres://vw:***@db.example/vault"
        );
        assert_eq!(redact_url("mysql://db/vault"), "mysql://db/vault");
        let source = Source::parse("mysql://vw:s3cret@db/vault", None).expect("mysql");
        assert!(!source.describe().contains("s3cret"));
    }
}
