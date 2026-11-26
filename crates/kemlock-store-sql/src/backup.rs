//! Reading a whole database into plain rows, and putting rows back, on any of the three backends.
//!
//! A snapshot is one JSON Lines file per table (`<table>.jsonl`): a header line
//! `{"table": ..., "columns": [...]}`, then one array of cells per row, in the order of the
//! header's columns. A cell is `null`, a number, a boolean, a string, an RFC 3339 time (a string),
//! a UUID (a string) or a blob (unpadded base64url, a string); the table's column types, taken from
//! the entity that maps it, say which. The format is the same whatever database it came from, so a
//! snapshot of SQLite restores into PostgreSQL or MySQL and the other way round (design, "Snapshots").
//!
//! The rows are read in one transaction. On PostgreSQL and MySQL it is `REPEATABLE READ`, read
//! only; SQLite's WAL gives a transaction one snapshot of the file, so writers carry on meanwhile.
//! Either way every table is read as of one moment.
//!
//! The registry of tables lives here: a table with no entry in it makes a snapshot fail, so a
//! forgotten table can never be silently missing from a backup. A test applies the migrations one
//! at a time and names the migration and table of any it finds missing.
//!
//! Rows travel as they are stored; the backup never opens or seals a secret. What the tables hold:
//!
//! - **Sealed under `server.key`** (restoring needs the same key, which a backup never carries):
//!   `two_factor.sealed_secret`, `two_factor_recovery.sealed_code`,
//!   `sso_settings.sealed_client_secret`,
//!   `bw_account_extras.sealed_totp_secret` and `sealed_totp_recover`, and the `vw_rows` rows of the
//!   Vaultwarden tables `twofactor` and `organization_api_key` (`data` starts with `sealed:`).
//! - **Sealed to a key the server never holds** (the owner's, a device's, a contact's or a
//!   passkey's PRF output): `users.sealed_private_keys`, `device_key_copies.wrapped_key`,
//!   `auth_requests.sealed_key`, `emergency_access.sealed_key`, `members.sealed_space_key`,
//!   `collection_keys.sealed`, `space_recovery_boxes.sealed`, `sends.sealed_key` and
//!   `passkeys.prf_wrapped_key`.
//! - **Hashes**: `refresh_tokens`, `admin_invites.token_hash`, `email_changes.token_hash`,
//!   `email_confirmations.token_hash` and
//!   `sends.password_hash`.
//! - **Plain**: `push_tokens.token`, `bw_devices.push_token` and `webauthn_challenges.state` (a
//!   short-lived ceremony state)
//!   are not sealed, so the archive's own encryption is all that protects them.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::migration::Migrator;
use crate::store::SqlStore;
use crate::tables::space_chain;
use crate::tables::space_recovery;
use crate::tables::space_tables;
use crate::tables::sso;
use crate::tables::{
    admin, attachments, auth_requests, bw_account_extras, bw_accounts, bw_attachments, bw_devices,
    bw_docs, bw_user_key_ids, changes, custom_fields, dedup_owners, device_api_use,
    device_key_copies, devices, duplicate_dismissals, email_changes, email_confirmations,
    emergency_access, events,
    federation, federation_insight, federation_keys, federation_logs, federation_wiring, item_tags,
    items, passkeys, pending_erasures, policies, push_tokens, recovery_kits, refresh_tokens,
    revoked_families, sends, server_meta, settings, sign_in_log, signed_manifests, sync_horizon,
    two_factor, two_factor_recovery, two_step_versions, users, vw_rows, webauthn_challenges,
};
use kemlock_app::admin::SettingsRepo;
use kemlock_app::b64url;
use kemlock_app::sealed::SECRETS_BOUND_KEY;
use kemlock_app::ports::StoreError;
use sea_orm::sea_query::{Alias, Expr, Order, Query};
use sea_orm::{
    AccessMode, ColumnTrait, ColumnType, ConnectionTrait, DatabaseConnection, DbBackend,
    EntityTrait, IdenStatic, IsolationLevel, Iterable, PrimaryKeyToColumn, QueryResult, Statement,
    TransactionTrait, Value,
};
use sea_orm_migration::MigratorTrait;
use serde_json::Value as Json;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// Tables that are no part of a snapshot: the lease table is this process's, the migration table is
/// the migrator's, and `live_nudges` is a one-minute buffer of wake-ups for replicas. Its rows are
/// worthless after a restore, and putting back ids a sequence handed out would leave a PostgreSQL
/// sequence behind them.
const EXCLUDED: [&str; 3] = ["job_leases", "seaql_migrations", "live_nudges"];

/// Rows read or inserted at a time.
const BATCH: u64 = 100;

/// A table of a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotTable {
    pub name: String,
    /// The columns in the order of each row's cells.
    pub columns: Vec<String>,
    pub rows: u64,
}

/// What a snapshot holds, for the backup's manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The database it came from: `sqlite`, `postgres` or `mysql`.
    pub database: &'static str,
    /// The migrations the database had applied.
    pub migrations: Vec<String>,
    pub tables: Vec<SnapshotTable>,
}

// ---------------------------------------------------------------------------------------------
// The registry.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Uuid,
    Bool,
    I16,
    I32,
    I64,
    Text,
    Blob,
    Time,
}

impl Kind {
    fn of(column: &ColumnType) -> Option<Kind> {
        match column {
            ColumnType::Uuid => Some(Kind::Uuid),
            ColumnType::Boolean => Some(Kind::Bool),
            ColumnType::SmallInteger => Some(Kind::I16),
            ColumnType::Integer => Some(Kind::I32),
            ColumnType::BigInteger => Some(Kind::I64),
            ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_) => Some(Kind::Text),
            ColumnType::Blob | ColumnType::Binary(_) | ColumnType::VarBinary(_) => Some(Kind::Blob),
            ColumnType::TimestampWithTimeZone => Some(Kind::Time),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct ColumnSpec {
    name: &'static str,
    kind: Kind,
}

#[derive(Clone, Debug)]
struct TableSpec {
    name: &'static str,
    columns: Vec<ColumnSpec>,
    /// The primary key's columns, for a stable order.
    key: Vec<&'static str>,
}

fn spec_of<E: EntityTrait>() -> Result<TableSpec, StoreError> {
    let name = E::default().table_name();
    let mut columns = Vec::new();
    for column in <E::Column as Iterable>::iter() {
        let def = column.def();
        let column_name = IdenStatic::as_str(&column);
        let kind = Kind::of(def.get_column_type()).ok_or_else(|| {
            StoreError::Backend(format!(
                "column {name}.{column_name} has a type the backup can't carry"
            ))
        })?;
        columns.push(ColumnSpec {
            name: column_name,
            kind,
        });
    }
    let key = <E::PrimaryKey as Iterable>::iter()
        .map(|k| IdenStatic::as_str(&PrimaryKeyToColumn::into_column(k)))
        .collect();
    Ok(TableSpec { name, columns, key })
}

macro_rules! registry {
    ($($entity:path),+ $(,)?) => {
        vec![$(spec_of::<$entity>()),+]
    };
}

/// Every table, parents before the tables that name them (foreign keys), so rows go back in this
/// order and are cleared in the reverse of it. A test checks the order against the schema's
/// foreign keys.
fn registry() -> Result<Vec<TableSpec>, StoreError> {
    registry!(
        users::Entity,
        devices::Entity,
        device_api_use::Entity,
        push_tokens::Entity,
        bw_devices::Entity,
        refresh_tokens::Entity,
        revoked_families::Entity,
        two_factor::Entity,
        two_factor_recovery::Entity,
        two_step_versions::Entity,
        passkeys::Entity,
        recovery_kits::Entity,
        email_changes::Entity,
        email_confirmations::Entity,
        webauthn_challenges::Entity,
        bw_accounts::Entity,
        bw_account_extras::Entity,
        bw_user_key_ids::Entity,
        auth_requests::Entity,
        device_key_copies::Entity,
        emergency_access::Entity,
        sso::identities::Entity,
        sso::settings::Entity,
        sso::domains::Entity,
        server_meta::Entity,
        settings::Entity,
        custom_fields::Entity,
        events::Entity,
        sign_in_log::Entity,
        pending_erasures::Entity,
        admin::user_state::Entity,
        admin::invites::Entity,
        admin::requests::Entity,
        items::Entity,
        item_tags::Entity,
        duplicate_dismissals::Entity,
        dedup_owners::Entity,
        changes::Entity,
        sync_horizon::Entity,
        attachments::Entity,
        bw_attachments::Entity,
        bw_docs::Entity,
        vw_rows::Entity,
        sends::Entity,
        signed_manifests::Entity,
        space_tables::spaces::Entity,
        space_tables::members::Entity,
        space_tables::groups::Entity,
        space_tables::group_members::Entity,
        space_tables::collections::Entity,
        space_tables::collection_grants::Entity,
        space_tables::collection_keys::Entity,
        space_tables::item_collections::Entity,
        policies::Entity,
        federation::peers::Entity,
        federation::vault_federation::Entity,
        federation::peer_log_switches::Entity,
        federation::peer_cursors::Entity,
        federation::change_meta::Entity,
        federation::home_records::Entity,
        federation::item_siblings::Entity,
        federation_wiring::peer_acknowledgements::Entity,
        federation_wiring::vault_offers::Entity,
        federation_wiring::replicated_accounts::Entity,
        federation_wiring::federation_erasures::Entity,
        federation_wiring::federation_replicated_sends::Entity,
        federation_wiring::federation_withheld::Entity,
        federation_logs::peer_events::Entity,
        federation_keys::key_records::Entity,
        federation_keys::learned_keys::Entity,
        federation_insight::peer_security::Entity,
        federation_insight::peer_mismatches::Entity,
        space_chain::records::Entity,
        space_chain::seals::Entity,
        space_chain::names::Entity,
        space_chain::pending::Entity,
        space_chain::held::Entity,
        space_recovery::Entity,
    )
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------------------------
// Looking at the live schema.

fn backend_name(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "sqlite",
        DbBackend::Postgres => "postgres",
        DbBackend::MySql => "mysql",
        _ => "other",
    }
}

async fn strings<C: ConnectionTrait>(
    db: &C,
    statement: Statement,
) -> Result<Vec<String>, StoreError> {
    db.query_all_raw(statement)
        .await
        .store()?
        .iter()
        .map(|row| row.try_get_by_index::<String>(0).store())
        .collect()
}

/// The tables the database has.
async fn live_tables<C: ConnectionTrait>(db: &C) -> Result<BTreeSet<String>, StoreError> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DbBackend::Sqlite => {
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        }
        DbBackend::Postgres => {
            "SELECT CAST(table_name AS TEXT) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'"
        }
        DbBackend::MySql => {
            "SELECT CAST(table_name AS CHAR) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
        }
        _ => {
            return Err(StoreError::Backend(
                "backups support SQLite, PostgreSQL and MySQL only".to_owned(),
            ));
        }
    };
    Ok(strings(db, Statement::from_string(backend, sql))
        .await?
        .into_iter()
        .collect())
}

/// The columns a table has.
async fn live_columns<C: ConnectionTrait>(
    db: &C,
    table: &str,
) -> Result<BTreeSet<String>, StoreError> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DbBackend::Sqlite => "SELECT name FROM pragma_table_info(?)",
        DbBackend::Postgres => {
            "SELECT CAST(column_name AS TEXT) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1"
        }
        DbBackend::MySql => {
            "SELECT CAST(column_name AS CHAR) FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ?"
        }
        _ => {
            return Err(StoreError::Backend(
                "backups support SQLite, PostgreSQL and MySQL only".to_owned(),
            ));
        }
    };
    Ok(strings(
        db,
        Statement::from_sql_and_values(backend, sql, [Value::from(table.to_owned())]),
    )
    .await?
    .into_iter()
    .collect())
}

/// The tables to take, in registry order, with the columns they have now. A table the database
/// has and the registry doesn't know is an error; a column too.
async fn plan<C: ConnectionTrait>(db: &C) -> Result<Vec<(TableSpec, Vec<ColumnSpec>)>, StoreError> {
    let registry = registry()?;
    let live = live_tables(db).await?;
    let known: BTreeSet<&str> = registry.iter().map(|t| t.name).collect();
    let unknown: Vec<&String> = live
        .iter()
        .filter(|t| !known.contains(t.as_str()) && !EXCLUDED.contains(&t.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(StoreError::Backend(format!(
            "the database has tables the backup doesn't know: {}",
            unknown
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let mut out = Vec::new();
    for table in registry {
        if !live.contains(table.name) {
            continue;
        }
        let have = live_columns(db, table.name).await?;
        let extra: Vec<&String> = have
            .iter()
            .filter(|c| !table.columns.iter().any(|spec| spec.name == c.as_str()))
            .collect();
        if !extra.is_empty() {
            return Err(StoreError::Backend(format!(
                "table {} has columns the backup doesn't know: {}",
                table.name,
                extra
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let present: Vec<ColumnSpec> = table
            .columns
            .iter()
            .filter(|spec| have.contains(spec.name))
            .cloned()
            .collect();
        out.push((table, present));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Cells.

#[derive(Clone, Debug, PartialEq)]
enum Cell {
    Null,
    Bool(bool),
    I16(i16),
    I32(i32),
    I64(i64),
    Text(String),
    Blob(Vec<u8>),
    Uuid(Uuid),
    Time(OffsetDateTime),
}

fn read_cell(row: &QueryResult, column: &ColumnSpec) -> Result<Cell, StoreError> {
    let name = column.name;
    macro_rules! get {
        ($t:ty, $wrap:expr) => {{
            let value: Option<$t> = row.try_get("", name).store()?;
            value.map_or(Cell::Null, $wrap)
        }};
    }
    Ok(match column.kind {
        Kind::Uuid => get!(Uuid, Cell::Uuid),
        Kind::Bool => get!(bool, Cell::Bool),
        Kind::I16 => get!(i16, Cell::I16),
        Kind::I32 => get!(i32, Cell::I32),
        Kind::I64 => get!(i64, Cell::I64),
        Kind::Text => get!(String, Cell::Text),
        Kind::Blob => get!(Vec<u8>, Cell::Blob),
        Kind::Time => get!(OffsetDateTime, |t| Cell::Time(utc(t))),
    })
}

fn cell_to_json(cell: &Cell) -> Result<Json, StoreError> {
    Ok(match cell {
        Cell::Null => Json::Null,
        Cell::Bool(b) => Json::Bool(*b),
        Cell::I16(n) => Json::from(*n),
        Cell::I32(n) => Json::from(*n),
        Cell::I64(n) => Json::from(*n),
        Cell::Text(s) => Json::String(s.clone()),
        Cell::Blob(b) => Json::String(b64url::encode(b)),
        Cell::Uuid(u) => Json::String(u.to_string()),
        Cell::Time(t) => Json::String(
            t.format(&Rfc3339)
                .map_err(|e| StoreError::Backend(format!("can't write a time: {e}")))?,
        ),
    })
}

fn bad_cell(column: &str, what: &str) -> StoreError {
    StoreError::Backend(format!("the snapshot's {column} isn't {what}"))
}

fn json_to_cell(kind: Kind, column: &str, value: &Json) -> Result<Cell, StoreError> {
    if value.is_null() {
        return Ok(Cell::Null);
    }
    let text = || value.as_str().ok_or_else(|| bad_cell(column, "a string"));
    Ok(match kind {
        Kind::Bool => Cell::Bool(
            value
                .as_bool()
                .ok_or_else(|| bad_cell(column, "a boolean"))?,
        ),
        Kind::I16 => Cell::I16(
            value
                .as_i64()
                .and_then(|n| i16::try_from(n).ok())
                .ok_or_else(|| bad_cell(column, "a 16-bit number"))?,
        ),
        Kind::I32 => Cell::I32(
            value
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| bad_cell(column, "a 32-bit number"))?,
        ),
        Kind::I64 => Cell::I64(
            value
                .as_i64()
                .ok_or_else(|| bad_cell(column, "a 64-bit number"))?,
        ),
        Kind::Text => Cell::Text(text()?.to_owned()),
        Kind::Blob => {
            Cell::Blob(b64url::decode(text()?).ok_or_else(|| bad_cell(column, "base64url"))?)
        }
        Kind::Uuid => Cell::Uuid(Uuid::parse_str(text()?).map_err(|_| bad_cell(column, "a UUID"))?),
        Kind::Time => Cell::Time(
            OffsetDateTime::parse(text()?, &Rfc3339).map_err(|_| bad_cell(column, "a time"))?,
        ),
    })
}

/// The SQL value of a cell, typed even when it is null.
fn cell_value(kind: Kind, cell: Cell) -> Value {
    match (kind, cell) {
        (Kind::Uuid, Cell::Uuid(u)) => Value::Uuid(Some(u)),
        (Kind::Uuid, _) => Value::Uuid(None),
        (Kind::Bool, Cell::Bool(b)) => Value::Bool(Some(b)),
        (Kind::Bool, _) => Value::Bool(None),
        (Kind::I16, Cell::I16(n)) => Value::SmallInt(Some(n)),
        (Kind::I16, _) => Value::SmallInt(None),
        (Kind::I32, Cell::I32(n)) => Value::Int(Some(n)),
        (Kind::I32, _) => Value::Int(None),
        (Kind::I64, Cell::I64(n)) => Value::BigInt(Some(n)),
        (Kind::I64, _) => Value::BigInt(None),
        (Kind::Text, Cell::Text(s)) => Value::String(Some(s)),
        (Kind::Text, _) => Value::String(None),
        (Kind::Blob, Cell::Blob(b)) => Value::Bytes(Some(b)),
        (Kind::Blob, _) => Value::Bytes(None),
        (Kind::Time, Cell::Time(t)) => Value::TimeDateTimeWithTimeZone(Some(utc(t))),
        (Kind::Time, _) => Value::TimeDateTimeWithTimeZone(None),
    }
}

// ---------------------------------------------------------------------------------------------
// Taking a snapshot.

fn io_error(what: &str, e: std::io::Error) -> StoreError {
    StoreError::Backend(format!("{what}: {e}"))
}

async fn snapshot_db(db: &DatabaseConnection, dir: &Path) -> Result<Snapshot, StoreError> {
    std::fs::create_dir_all(dir).map_err(|e| io_error("can't make the snapshot folder", e))?;
    let backend = db.get_database_backend();
    // SQLite has no isolation levels to set: a read transaction in WAL mode is one snapshot.
    let (isolation, access) = if backend == DbBackend::Sqlite {
        (None, None)
    } else {
        (
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
    };
    let txn = db.begin_with_config(isolation, access).await.store()?;
    let result = snapshot_in(&txn, dir).await;
    // Nothing was written: rolling back is the same as committing and cheaper to get right.
    if let Err(rollback) = txn.rollback().await {
        tracing::warn!(%rollback, "rollback after a snapshot failed");
    }
    let (tables, migrations) = result?;
    Ok(Snapshot {
        database: backend_name(backend),
        migrations,
        tables,
    })
}

async fn snapshot_in<C: ConnectionTrait>(
    txn: &C,
    dir: &Path,
) -> Result<(Vec<SnapshotTable>, Vec<String>), StoreError> {
    let migrations = Migrator::get_applied_migrations_read_only(txn)
        .await
        .store()?
        .iter()
        .map(|m| m.name().to_owned())
        .collect();
    let mut out = Vec::new();
    for (table, columns) in plan(txn).await? {
        let path = dir.join(format!("{}.jsonl", table.name));
        let file = File::create(&path).map_err(|e| io_error("can't write a snapshot file", e))?;
        let mut writer = BufWriter::new(file);
        let names: Vec<String> = columns.iter().map(|c| c.name.to_owned()).collect();
        let header = serde_json::json!({ "table": table.name, "columns": names });
        writeln!(writer, "{header}").map_err(|e| io_error("can't write a snapshot file", e))?;

        let mut rows = 0u64;
        loop {
            let mut select = Query::select();
            select
                .columns(columns.iter().map(|c| Alias::new(c.name)))
                .from(Alias::new(table.name));
            for key in &table.key {
                select.order_by(Alias::new(*key), Order::Asc);
            }
            select.limit(BATCH).offset(rows);
            let page = txn.query_all(&select).await.store()?;
            let count = page.len() as u64;
            for row in &page {
                let cells = columns
                    .iter()
                    .map(|c| read_cell(row, c).and_then(|cell| cell_to_json(&cell)))
                    .collect::<Result<Vec<_>, _>>()?;
                writeln!(writer, "{}", Json::Array(cells))
                    .map_err(|e| io_error("can't write a snapshot file", e))?;
            }
            rows += count;
            if count < BATCH {
                break;
            }
        }
        writer
            .flush()
            .map_err(|e| io_error("can't write a snapshot file", e))?;
        out.push(SnapshotTable {
            name: table.name.to_owned(),
            columns: names,
            rows,
        });
    }
    Ok((out, migrations))
}

impl SqlStore {
    /// Reads every table into `<dir>/<table>.jsonl`, as of one moment, without stopping writes.
    pub async fn snapshot_to(&self, dir: &Path) -> Result<Snapshot, StoreError> {
        snapshot_db(self.reader(), dir).await
    }

    /// How many rows each table has now, in registry order.
    pub async fn row_counts(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let db = self.reader();
        let mut counts = Vec::new();
        for (table, _) in plan(db).await? {
            let select = Query::select()
                .expr(Expr::cust("COUNT(*)"))
                .from(Alias::new(table.name))
                .to_owned();
            let row = db
                .query_one(&select)
                .await
                .store()?
                .ok_or_else(|| StoreError::Backend("a count returned no row".to_owned()))?;
            let n: i64 = row.try_get_by_index(0).store()?;
            counts.push((table.name.to_owned(), u64::try_from(n).unwrap_or(0)));
        }
        Ok(counts)
    }

    /// Replaces the contents of every table with the rows in `dir`, in one transaction: either
    /// the database holds the snapshot afterwards or it is as it was. `tables` is the snapshot's
    /// table list (from the backup's manifest). Rows go back with their ids, so the server's own
    /// id and sequence come back too; this handle still has the id it loaded at connect, so
    /// reconnect after restoring.
    pub async fn restore_from(
        &self,
        dir: &Path,
        tables: &[SnapshotTable],
    ) -> Result<(), StoreError> {
        let registry = registry()?;
        for table in tables {
            if !registry.iter().any(|spec| spec.name == table.name) {
                return Err(StoreError::Backend(format!(
                    "the snapshot has a table this server doesn't know: {}",
                    table.name
                )));
            }
        }
        let txn = self.writer().begin().await.store()?;
        match restore_in(&txn, dir, tables, &registry).await {
            Ok(()) => {
                txn.commit().await.store()?;
                // What came back may hold secrets sealed the old way: the start-up pass seals
                // them to their accounts again, and until it has run nothing may say it has.
                SettingsRepo::delete_setting(self, SECRETS_BOUND_KEY).await
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after a failed restore failed");
                }
                Err(err)
            }
        }
    }
}

/// A snapshot of the database at `url`, without a store: the server uses it to write a backup
/// before a migration changes a PostgreSQL or MySQL database, when the schema is the old one.
pub async fn snapshot_database(url: &str, dir: &Path) -> Result<Snapshot, StoreError> {
    let mut options = sea_orm::ConnectOptions::new(url.to_owned());
    options.max_connections(1).sqlx_logging(false);
    let db = sea_orm::Database::connect(options)
        .await
        .map_err(|e| crate::connect::connect_error(url, e))?;
    let snapshot = snapshot_db(&db, dir).await;
    if let Err(e) = db.close().await {
        tracing::warn!(error = %e, "couldn't close the snapshot connection");
    }
    snapshot
}

// ---------------------------------------------------------------------------------------------
// Restoring.

async fn restore_in(
    txn: &sea_orm::DatabaseTransaction,
    dir: &Path,
    tables: &[SnapshotTable],
    registry: &[TableSpec],
) -> Result<(), StoreError> {
    // Clear what is there, children before parents.
    let live = live_tables(txn).await?;
    for spec in registry.iter().rev().filter(|s| live.contains(s.name)) {
        txn.execute(&Query::delete().from_table(Alias::new(spec.name)).to_owned())
            .await
            .store()?;
    }

    // Put the snapshot back, parents before children.
    for spec in registry {
        let Some(table) = tables.iter().find(|t| t.name == spec.name) else {
            continue;
        };
        if !live.contains(spec.name) {
            return Err(StoreError::Backend(format!(
                "this database has no table {} to restore into",
                spec.name
            )));
        }
        let mut columns = Vec::new();
        for name in &table.columns {
            let column = spec
                .columns
                .iter()
                .find(|c| c.name == name.as_str())
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "the snapshot's {}.{name} is a column this server doesn't know",
                        spec.name
                    ))
                })?;
            columns.push(column.clone());
        }
        let path = dir.join(format!("{}.jsonl", spec.name));
        let file = File::open(&path).map_err(|e| io_error("can't read a snapshot file", e))?;
        let mut lines = BufReader::new(file).lines();
        let header = lines
            .next()
            .ok_or_else(|| StoreError::Backend(format!("{} is empty", path.display())))?
            .map_err(|e| io_error("can't read a snapshot file", e))?;
        let header: Json = serde_json::from_str(&header)
            .map_err(|e| StoreError::Backend(format!("{}: {e}", path.display())))?;
        let header_columns: Vec<&str> = header["columns"]
            .as_array()
            .map(|a| a.iter().filter_map(Json::as_str).collect())
            .unwrap_or_default();
        let wanted: Vec<&str> = table.columns.iter().map(String::as_str).collect();
        if header_columns != wanted {
            return Err(StoreError::Backend(format!(
                "{}: its columns aren't the ones the manifest names",
                path.display()
            )));
        }

        let mut inserted = 0u64;
        let mut batch: Vec<Vec<Value>> = Vec::new();
        for line in lines {
            let line = line.map_err(|e| io_error("can't read a snapshot file", e))?;
            if line.is_empty() {
                continue;
            }
            let cells: Json = serde_json::from_str(&line)
                .map_err(|e| StoreError::Backend(format!("{}: {e}", path.display())))?;
            let cells = cells
                .as_array()
                .filter(|a| a.len() == columns.len())
                .ok_or_else(|| {
                    StoreError::Backend(format!("{}: a row has the wrong width", path.display()))
                })?;
            let mut row = Vec::with_capacity(columns.len());
            for (column, value) in columns.iter().zip(cells) {
                let cell = json_to_cell(column.kind, column.name, value)?;
                row.push(cell_value(column.kind, cell));
            }
            batch.push(row);
            if batch.len() as u64 >= BATCH {
                inserted +=
                    insert_rows(txn, spec.name, &columns, std::mem::take(&mut batch)).await?;
            }
        }
        inserted += insert_rows(txn, spec.name, &columns, batch).await?;
        if inserted != table.rows {
            return Err(StoreError::Backend(format!(
                "{}: the manifest says {} rows, the file has {inserted}",
                spec.name, table.rows
            )));
        }
    }
    Ok(())
}

async fn insert_rows(
    txn: &sea_orm::DatabaseTransaction,
    table: &str,
    columns: &[ColumnSpec],
    rows: Vec<Vec<Value>>,
) -> Result<u64, StoreError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let count = rows.len() as u64;
    let mut insert = Query::insert();
    insert
        .into_table(Alias::new(table))
        .columns(columns.iter().map(|c| Alias::new(c.name)));
    for row in rows {
        insert
            .values(row.into_iter().map(Expr::val))
            .map_err(|e| StoreError::Backend(format!("can't build an insert: {e}")))?;
    }
    txn.execute(&insert).await.store()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_builds_and_names_users_first() {
        let registry = registry().expect("every column has a type the backup carries");
        assert_eq!(registry[0].name, "users");
        let names: BTreeSet<&str> = registry.iter().map(|t| t.name).collect();
        assert_eq!(names.len(), registry.len(), "no table twice");
        for table in &registry {
            assert!(!table.key.is_empty(), "{} has a primary key", table.name);
        }
        // A child comes after the table it names.
        let at = |name: &str| registry.iter().position(|t| t.name == name).expect("known");
        assert!(at("users") < at("devices"));
        assert!(at("devices") < at("refresh_tokens"));
        assert!(at("devices") < at("device_key_copies"));
        assert!(at("users") < at("emergency_access"));
        assert!(at("users") < at("sso_identities"));
    }

    /// Applies the migrations one at a time to an empty SQLite database and holds the registry to
    /// what they make: a migration that adds a table the registry lacks fails this test with the
    /// migration's and the table's names, and a table put back before the table it names fails
    /// with both.
    #[tokio::test]
    async fn the_registry_has_every_table_the_migrations_make() {
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        options
            .max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        let db = sea_orm::Database::connect(options)
            .await
            .expect("an in-memory database");
        let registry = registry().expect("every column has a type the backup carries");
        let known: BTreeSet<&str> = registry.iter().map(|t| t.name).collect();

        let mut before = BTreeSet::new();
        let mut made_by = std::collections::BTreeMap::new();
        loop {
            let next = {
                let pending = Migrator::get_pending_migrations(&db)
                    .await
                    .expect("the pending migrations");
                match pending.first() {
                    Some(migration) => migration.name().to_owned(),
                    None => break,
                }
            };
            Migrator::up(&db, Some(1))
                .await
                .unwrap_or_else(|e| panic!("migration {next} fails: {e}"));
            let now = live_tables(&db).await.expect("the tables");
            for table in now.difference(&before) {
                made_by.insert(table.clone(), next.clone());
            }
            before = now;
        }
        // A table a later migration drops never reaches a backup, so only what is left counts.
        let lacking: Vec<String> = before
            .iter()
            .filter(|t| !known.contains(t.as_str()) && !EXCLUDED.contains(&t.as_str()))
            .map(|t| format!("{t} (made by migration {})", made_by[t]))
            .collect();
        assert!(
            lacking.is_empty(),
            "the backup's registry (`registry()` in backup.rs) lacks tables the migrations make: \
             {}. Add each one's entity to it, after the tables it has foreign keys to, or to \
             EXCLUDED with the reason it is no part of a backup",
            lacking.join(", ")
        );

        let gone: Vec<&str> = known
            .iter()
            .copied()
            .filter(|name| !before.contains(*name))
            .collect();
        assert!(
            gone.is_empty(),
            "the registry names tables the migrations no longer leave in the schema: {}",
            gone.join(", ")
        );

        let keys = strings_of_pairs(
            &db,
            "SELECT m.name, f.\"table\" FROM sqlite_master AS m, \
             pragma_foreign_key_list(m.name) AS f WHERE m.type = 'table'",
        )
        .await;
        let at = |name: &str| registry.iter().position(|t| t.name == name);
        let misplaced: Vec<String> = keys
            .iter()
            .filter(|(child, parent)| child != parent)
            .filter_map(|(child, parent)| Some((child, parent, at(child)?, at(parent)?)))
            .filter(|(_, _, child_at, parent_at)| parent_at > child_at)
            .map(|(child, parent, _, _)| format!("{child} comes before {parent}, which it names"))
            .collect();
        assert!(
            misplaced.is_empty(),
            "rows would go back before the rows their foreign keys name: {}",
            misplaced.join("; ")
        );

        plan(&db)
            .await
            .expect("every table and column of the schema is known to the backup");
    }

    /// Two text columns of every row a query returns.
    async fn strings_of_pairs(db: &DatabaseConnection, sql: &str) -> Vec<(String, String)> {
        db.query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .expect("the query runs")
            .iter()
            .map(|row| {
                (
                    row.try_get_by_index::<String>(0).expect("a name"),
                    row.try_get_by_index::<String>(1).expect("a name"),
                )
            })
            .collect()
    }

    #[test]
    fn cells_survive_the_trip_through_json() {
        let cases = [
            (Kind::Uuid, Cell::Uuid(Uuid::from_u128(7))),
            (Kind::Bool, Cell::Bool(true)),
            (Kind::I16, Cell::I16(-3)),
            (Kind::I32, Cell::I32(70_000)),
            (Kind::I64, Cell::I64(i64::MAX)),
            (Kind::Text, Cell::Text("zoë \"quoted\"".to_owned())),
            (Kind::Blob, Cell::Blob(vec![0, 255, 7, 128])),
            (
                Kind::Time,
                Cell::Time(time::macros::datetime!(2026-05-06 07:08:09.123456 UTC)),
            ),
            (Kind::Text, Cell::Null),
            (Kind::Blob, Cell::Null),
        ];
        for (kind, cell) in cases {
            let json = cell_to_json(&cell).expect("writes");
            assert_eq!(json_to_cell(kind, "c", &json).expect("reads"), cell);
        }
    }

    #[test]
    fn a_cell_of_the_wrong_shape_is_refused() {
        assert!(json_to_cell(Kind::Uuid, "c", &Json::String("nope".to_owned())).is_err());
        assert!(json_to_cell(Kind::I16, "c", &Json::from(70_000)).is_err());
        assert!(json_to_cell(Kind::Bool, "c", &Json::from(1)).is_err());
        assert!(json_to_cell(Kind::Blob, "c", &Json::String("***".to_owned())).is_err());
    }

    #[test]
    fn a_null_cell_keeps_its_type_in_sql() {
        assert_eq!(cell_value(Kind::Uuid, Cell::Null), Value::Uuid(None));
        assert_eq!(cell_value(Kind::Blob, Cell::Null), Value::Bytes(None));
        assert_eq!(cell_value(Kind::I64, Cell::I64(5)), Value::BigInt(Some(5)));
    }
}
