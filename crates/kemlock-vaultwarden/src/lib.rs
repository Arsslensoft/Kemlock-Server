//! Moving in from Vaultwarden (design, "Migrating from Vaultwarden").
//!
//! The move copies a Vaultwarden server's rows and files exactly as stored, so nobody re-keys,
//! re-enrols two-step login or signs in again, and Vaultwarden's own data is never changed. This
//! crate has four parts, each testable alone:
//!
//! 1. [`reader`] opens a data folder (`db.sqlite3` read-only, plus `attachments/`, `sends/`,
//!    `rsa_key.pem` and `config.json`) or a MySQL or PostgreSQL URL, refuses a schema version it
//!    doesn't know ([`schema`]), and returns a [`VaultwardenSnapshot`] with nothing decrypted.
//! 2. [`diff`] says what changed between two snapshots taken minutes apart (the first while
//!    Vaultwarden runs, the second after it stops), by primary key, deletions included.
//! 3. [`mapping`] turns a snapshot into plain structs that say what Kemlock Server stores:
//!    Compatible accounts, `bw` items holding the cipher JSON Vaultwarden would return
//!    ([`cipher_json`]), files to copy, `rsa_key.pem`, and settings ([`settings`]).
//! 4. [`sink`] defines the store side as a trait, [`ImportSink`]. Its SQL implementation is
//!    `SqlImportSink` in `kemlock-store-sql`.
//!
//! [`plan`] prints a dry run of what a move would do.

pub mod cipher_json;
pub mod diff;
pub mod error;
pub mod mapping;
mod migrations_1_37_5;
pub mod plan;
pub mod reader;
pub mod schema;
pub mod settings;
pub mod sink;
pub mod snapshot;
pub mod two_step;
pub mod vwtime;

pub use diff::{Deletion, SnapshotDiff, diff};
pub use error::{MapError, ReadError};
pub use mapping::{MappedImport, map_snapshot};
pub use plan::render_plan;
pub use reader::{Database, Source, read_snapshot};
pub use sink::{ApplyReport, ImportSink, apply};
pub use snapshot::VaultwardenSnapshot;
