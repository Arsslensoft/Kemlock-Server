//! Why reading, mapping or applying failed.

/// Why a Vaultwarden server's data could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// `--from` is neither a folder nor a `mysql://` or `postgres://` URL.
    #[error(
        "{0:?} is neither a Vaultwarden data folder nor a mysql://, mariadb://, postgres:// or postgresql:// URL"
    )]
    BadSource(String),
    #[error("there is no db.sqlite3 in {0}")]
    NoDatabase(String),
    /// The data folder given for a MySQL or PostgreSQL source doesn't exist.
    #[error("the data folder {0} doesn't exist")]
    NoFolder(String),
    #[error("can't read {path}: {message}")]
    Io { path: String, message: String },
    #[error("the database failed: {0}")]
    Database(String),
    /// The database has no `__diesel_schema_migrations` table.
    #[error("this isn't a Vaultwarden database: it has no migration history ({0})")]
    NotVaultwarden(String),
    #[error(
        "this database was last opened by a Vaultwarden older than {release}: {missing} of its \
         migrations have not run. Start a supported Vaultwarden release on a copy of it once, \
         stop it, and import again"
    )]
    SchemaOlder {
        release: &'static str,
        missing: usize,
    },
    #[error(
        "this database has migrations the importer doesn't know ({}): it was written by a \
         newer Vaultwarden or a fork. Importing it could lose data, so nothing was read",
        .unknown.join(", ")
    )]
    SchemaUnknown { unknown: Vec<String> },
    #[error("config.json isn't valid JSON: {0}")]
    BadConfig(String),
}

/// Why a snapshot could not be mapped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapError {
    #[error("{table} row {key}: {column} is {value:?}, not a UUID")]
    BadId {
        table: &'static str,
        key: String,
        column: &'static str,
        value: String,
    },
    #[error("{table} row {key}: {column} is {value:?}, not a date and time")]
    BadTime {
        table: &'static str,
        key: String,
        column: &'static str,
        value: String,
    },
    #[error("{table} row {key}: {column} is missing")]
    Missing {
        table: &'static str,
        key: String,
        column: &'static str,
    },
    #[error("config.json isn't a JSON object")]
    BadConfig,
}
