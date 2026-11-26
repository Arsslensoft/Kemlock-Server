//! SQL repositories and migrations for SQLite, PostgreSQL and MySQL.
//!
//! [`SqlStore`] implements every repository port in `kemlock_app::ports` (`ServerInfo`,
//! `UserRepo`, `DeviceRepo`, `TokenRepo`, `TwoFactorRepo`, `ItemStore`, `EventLog`) and `AttachmentRepo`
//! from `kemlock_app::files::ports`. It is built
//! on SeaORM, but no SeaORM type appears in this crate's API: callers see domain types and
//! `StoreError`.
//!
//! - **Migrations** run forward only, at connect time, under a lease so two replicas never migrate
//!   at once (see [`SqlStore::connect`]).
//! - **SQLite** runs in WAL mode with `synchronous=FULL` by default, one writer connection that
//!   every write goes through, and a pool of readers. PostgreSQL and MySQL use one ordinary pool.
//! - **Items** are written with an optimistic revision check. Each accepted write takes this
//!   server's next sequence number and an HLC time, replaces the item's row and appends to the
//!   change log, in one transaction, so a delta sync is a range read and federation can replay the
//!   log later.

mod backup;
mod bind_secrets;
mod connect;
mod convert;
mod error;
mod fanout;
mod lease;
mod migrate;
mod migration;
mod owner_lock;
mod repo;
mod request_ip;
mod store;
mod tables;

pub use backup::{Snapshot, SnapshotTable, snapshot_database};
pub use bind_secrets::BindReport;
pub use connect::{SqliteSync, StoreOptions};
pub use fanout::{Dialect, NUDGE_CHANNEL, NudgeListener};
pub use migrate::{pending_migrations, pre_migration_path};
pub use request_ip::{request_ip, with_request_ip};
pub use store::SqlStore;

pub use repo::vaultwarden::{
    DEFAULT_EVENTS_RETENTION_DAYS, ImportError, ImportFiles, ImportFilesFuture, ImportOptions,
    SqlImportSink,
};
