//! Kemlock Server's backups (design, "Self-hosting and homelab", Operations).
//!
//! An archive is a tar, compressed with zstd and encrypted to an age recipient, holding the
//! database as plain rows (so it restores into SQLite, PostgreSQL or MySQL), the attachment
//! folder, the data folder's other files and the TOML configuration file, with a manifest of row
//! counts and file hashes. `server.key` is never in one. The server holds only the public
//! recipient, so it can't read its own backups.
//!
//! - [`archive`]: writing, reading and checking an archive;
//! - [`destination`]: a local path or an S3-compatible bucket;
//! - [`job`]: the schedule, taking a backup and pruning old ones;
//! - [`manifest`]: what an archive says it holds.
//!
//! Restoring needs a started server (to compare against), so `kemlock-server` has the restore and
//! the drill; this crate gives them the archive.

pub mod archive;
pub mod destination;
pub mod error;
pub mod job;
pub mod manifest;

pub use age::x25519::Identity as AgeIdentity;
pub use archive::{
    ArchiveSpec, SERVER_KEY_FILE, create_private_file, is_never_restored, is_restorable_config_name,
    is_restorable_data_file, parse_identity, parse_recipient,
    read_archive, verify_unpacked, write_archive,
};
pub use destination::{ArchiveInfo, Destination, DestinationConfig, S3Destination};
pub use error::BackupError;
pub use job::{
    ARCHIVE_SUFFIX, BACKUP_PREFIX, BackupReport, BackupSettings, DataLayout, Kind,
    PRE_MIGRATION_PREFIX, STATUS_KEY, Schedule, Source, archive_name, archive_time, create_backup,
    plan_prune, prune, status_json,
};
pub use manifest::{Attachments, FileEntry, MANIFEST_NAME, Manifest, TableEntry};
