//! What can go wrong making, storing, reading or checking a backup.

/// A backup failed. The messages are for logs and the operator's terminal; none carries a key.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// The database side failed (reading rows, writing them back).
    #[error("database: {0}")]
    Store(String),
    /// The age recipient or identity isn't one.
    #[error("{0}")]
    Key(String),
    /// Encrypting or decrypting failed: the wrong identity, or an archive that isn't one.
    #[error("age: {0}")]
    Age(String),
    /// The manifest is missing, unreadable or of a format this version doesn't know.
    #[error("manifest: {0}")]
    Manifest(String),
    /// The archive's contents don't match its manifest.
    #[error("check failed: {0}")]
    Verify(String),
    /// The archive can't be shown to come from the server whose key was given: its
    /// authentication code is missing or wrong.
    #[error("not authenticated: {0}")]
    Unauthenticated(String),
    /// The destination (a folder or a bucket) refused or failed.
    #[error("destination: {0}")]
    Destination(String),
    /// A setting is missing or wrong.
    #[error("{0}")]
    Config(String),
}

impl BackupError {
    pub(crate) fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        BackupError::Io {
            what: what.into(),
            source,
        }
    }
}

impl From<kemlock_app::ports::StoreError> for BackupError {
    fn from(e: kemlock_app::ports::StoreError) -> Self {
        BackupError::Store(e.to_string())
    }
}
