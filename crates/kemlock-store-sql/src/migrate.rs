//! Running the migrations under a lock, and loading or making this server's identity.

use crate::convert::{unix_millis, utc};
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::lease;
use crate::migration::{Migrator, job_leases_table};
use crate::tables::server_meta;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Hlc, ServerId};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, QueryFilter,
    Statement,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use std::path::Path;
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The lease name two replicas starting together compete for.
const LOCK_NAME: &str = "migrations";
/// A crashed migrator's lock frees itself after this long.
const LOCK_TTL: Duration = Duration::minutes(5);
/// How long a starting replica waits for another's migration before giving up.
const LOCK_WAIT: StdDuration = StdDuration::from_secs(300);
const LOCK_POLL: StdDuration = StdDuration::from_millis(250);

/// Applies pending migrations, forward only, holding the `migrations` lease so only one replica
/// migrates at a time; a replica that loses the race waits, then finds nothing left to do.
///
/// The lock is a row in `job_leases`, so that table is created first, outside the migrations
/// (an idempotent `CREATE TABLE IF NOT EXISTS`, which is also safe if two replicas race on it).
pub(crate) async fn run(db: &DatabaseConnection) -> Result<(), StoreError> {
    let backend = db.get_database_backend();
    SchemaManager::new(db)
        .create_table(job_leases_table(backend))
        .await
        .store()?;

    let holder = Uuid::new_v4().to_string();
    let started = Instant::now();
    while !lease::try_acquire(db, LOCK_NAME, &holder, LOCK_TTL).await? {
        if started.elapsed() > LOCK_WAIT {
            return Err(StoreError::Backend(
                "timed out waiting for another process to finish migrating the database".to_owned(),
            ));
        }
        tokio::time::sleep(LOCK_POLL).await;
    }

    let migrated = match pre_migration_copy(db).await {
        Ok(()) => Migrator::up(db, None).await.store(),
        Err(e) => Err(e),
    };
    if migrated.is_ok() {
        prune_after_migration(db).await;
    }
    if let Err(err) = lease::release(db, LOCK_NAME, &holder).await {
        tracing::warn!(%err, "could not release the migration lock; it expires on its own");
    }
    migrated
}

/// How many migrations are waiting on the existing database at `url`, without applying any: 0 for
/// a database that is new (or empty) or up to date. The server asks before it connects, so it can
/// write a backup archive first on PostgreSQL and MySQL, where there is no file to copy.
pub async fn pending_migrations(url: &str) -> Result<usize, StoreError> {
    let mut options = sea_orm::ConnectOptions::new(url.to_owned());
    options.max_connections(1).sqlx_logging(false);
    let db = sea_orm::Database::connect(options)
        .await
        .map_err(|e| crate::connect::connect_error(url, e))?;
    let pending = Migrator::get_pending_migrations_read_only(&db)
        .await
        .store();
    if let Err(e) = db.close().await {
        tracing::warn!(error = %e, "couldn't close the migration check's connection");
    }
    let pending = pending?.len();
    Ok(if pending == Migrator::migrations().len() {
        0
    } else {
        pending
    })
}

/// This server's id: read from `server_meta`, or made (UUID v4) on the first start and stored.
/// Two replicas starting on a fresh database agree on the id of whichever inserted first.
pub(crate) async fn load_or_create_server_id(
    db: &DatabaseConnection,
) -> Result<ServerId, StoreError> {
    if let Some(row) = server_meta::Entity::find_by_id(server_meta::ROW_ID)
        .one(db)
        .await
        .store()?
    {
        return Ok(ServerId(row.server_id));
    }

    let fresh = server_meta::ActiveModel {
        id: Set(server_meta::ROW_ID),
        server_id: Set(Uuid::new_v4()),
        created_at: Set(utc(OffsetDateTime::now_utc())),
        next_seq: Set(1),
        last_hlc: Set(0),
    };
    match server_meta::Entity::insert(fresh).exec(db).await {
        Ok(_) => {}
        // Another replica made the row first; read theirs.
        Err(err) if is_unique_violation(&err) => {}
        Err(err) => return Err(map_db(err)),
    }
    server_meta::Entity::find_by_id(server_meta::ROW_ID)
        .one(db)
        .await
        .store()?
        .map(|row| ServerId(row.server_id))
        .ok_or_else(|| StoreError::Backend("server_meta has no row after creating it".to_owned()))
}

/// How far ahead of the wall clock a stored HLC time may be before start-up treats it as damage:
/// a day, far more than clock skew between servers or a client's wrong clock explains.
const CLOCK_REPAIR_AHEAD_MS: u64 = 24 * 60 * 60 * 1000;

/// Puts `server_meta.last_hlc` back to the wall clock when it is far in the future (or out of
/// range), which is what a peer's change record with a huge HLC time used to leave behind: every
/// later write took a time above what the column holds and failed. Returns whether it changed.
/// Items that already carry the large time keep it; only what this server writes next is affected.
pub(crate) async fn repair_future_clock(
    db: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let Some(meta) = server_meta::Entity::find_by_id(server_meta::ROW_ID)
        .one(db)
        .await
        .store()?
    else {
        return Ok(false);
    };
    let now_ms = unix_millis(now);
    let limit = Hlc::from_parts(now_ms.saturating_add(CLOCK_REPAIR_AHEAD_MS), 0);
    let damaged = !u64::try_from(meta.last_hlc).is_ok_and(|stored| stored <= limit.0);
    if !damaged {
        return Ok(false);
    }
    let repaired = Hlc::from_parts(now_ms, 0);
    server_meta::Entity::update_many()
        .col_expr(
            server_meta::Column::LastHlc,
            Expr::value(i64::try_from(repaired.0).unwrap_or(i64::MAX)),
        )
        .filter(server_meta::Column::Id.eq(server_meta::ROW_ID))
        .exec(db)
        .await
        .store()?;
    tracing::warn!(
        was = meta.last_hlc,
        now = repaired.0,
        "the stored change clock was far in the future (a peer's record, most likely): set back to the wall clock"
    );
    Ok(true)
}

/// The file a SQLite database is copied to before migrations change it, inside the database's own
/// folder: `<data>/backups/pre-<version>.sqlite3`, where `kemlock-cli restore --pre-migration`
/// looks for it.
pub fn pre_migration_path(database_file: &Path) -> std::path::PathBuf {
    database_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups")
        .join(format!("pre-{}.sqlite3", env!("CARGO_PKG_VERSION")))
}

/// How many pre-migration copies are always kept, newest first, whatever their age: the one just
/// made and the one before it, so a rollback of the last two upgrades is possible.
const KEEP_PRE_MIGRATION_COPIES: usize = 2;
/// How long a copy beyond those, or a database a rollback moved aside, is kept.
const OLD_COPY_MAX_AGE: StdDuration = StdDuration::from_secs(30 * 24 * 60 * 60);

/// Removes the pre-migration copies nothing needs any more from `folder` (`<data>/backups`): each
/// is the whole database in plain, so they are not kept for ever. The newest
/// [`KEEP_PRE_MIGRATION_COPIES`] stay; of the others, and of the `replaced-*` databases a
/// `restore --pre-migration` moved aside, those last written more than [`OLD_COPY_MAX_AGE`] before
/// `now` go, with their `-wal` and `-shm` files. Returns how many files went. A file that can't
/// be read or removed is left and logged.
pub(crate) fn prune_old_copies(folder: &Path, now: std::time::SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return 0;
    };
    let mut pre: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    let mut replaced: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
            continue;
        };
        if name.starts_with("pre-") && name.ends_with(".sqlite3") {
            pre.push((modified, entry.path()));
        } else if name.starts_with("replaced-") && name.ends_with(".sqlite3") {
            replaced.push((modified, entry.path()));
        }
    }
    pre.sort_by(|a, b| b.0.cmp(&a.0));
    let doomed = pre
        .into_iter()
        .skip(KEEP_PRE_MIGRATION_COPIES)
        .chain(replaced)
        .filter(|(modified, _)| {
            now.duration_since(*modified)
                .is_ok_and(|age| age > OLD_COPY_MAX_AGE)
        });
    let mut removed = 0;
    for (_, path) in doomed {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.clone().into_os_string();
            name.push(suffix);
            let file = std::path::PathBuf::from(name);
            if !file.exists() {
                continue;
            }
            match std::fs::remove_file(&file) {
                Ok(()) => removed += 1,
                Err(e) => {
                    tracing::warn!(copy = %file.display(), error = %e, "couldn't remove an old database copy");
                }
            }
        }
    }
    removed
}

/// After a migration that worked, prunes the old copies beside a SQLite database.
async fn prune_after_migration(db: &DatabaseConnection) {
    if db.get_database_backend() != DbBackend::Sqlite {
        return;
    }
    let Ok(Some(row)) = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
        ))
        .await
    else {
        return;
    };
    let Ok(file) = row.try_get_by_index::<String>(0) else {
        return;
    };
    if file.is_empty() {
        return;
    }
    let target = pre_migration_path(Path::new(&file));
    if let Some(folder) = target.parent() {
        let removed = prune_old_copies(folder, std::time::SystemTime::now());
        if removed > 0 {
            tracing::info!(removed, "removed old copies of the database");
        }
    }
}

/// On SQLite, before pending migrations change an existing database, copies it to
/// `pre-<version>.sqlite3` (design, "Upgrades"). The copy is `VACUUM INTO`: one consistent
/// snapshot taken in a read transaction, which writers (in WAL mode) do not wait for. A new
/// database, an in-memory one, and a database with nothing pending are left alone, and an earlier
/// copy of the same version is kept: it is from before the first migration of that upgrade.
/// PostgreSQL and MySQL have no file to copy; the server writes a backup archive first when
/// backups are set up.
async fn pre_migration_copy(db: &DatabaseConnection) -> Result<(), StoreError> {
    if db.get_database_backend() != DbBackend::Sqlite {
        return Ok(());
    }
    let pending = Migrator::get_pending_migrations_read_only(db)
        .await
        .store()?;
    if pending.is_empty() || pending.len() == Migrator::migrations().len() {
        return Ok(());
    }
    let row = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
        ))
        .await
        .store()?;
    let Some(row) = row else {
        return Ok(());
    };
    let file: String = row.try_get_by_index(0).store()?;
    if file.is_empty() {
        return Ok(());
    }
    let target = pre_migration_path(Path::new(&file));
    if target.exists() {
        tracing::info!(copy = %target.display(), "keeping the earlier pre-migration copy");
        return Ok(());
    }
    if let Some(folder) = target.parent() {
        std::fs::create_dir_all(folder)
            .map_err(|e| StoreError::Backend(format!("can't make {}: {e}", folder.display())))?;
    }
    let literal = target.to_string_lossy().replace('\'', "''");
    db.execute_unprepared(&format!("VACUUM INTO '{literal}'"))
        .await
        .store()?;
    // A copy of the whole database: private like the database itself.
    if let Err(e) = crate::connect::restrict_to_owner(&target) {
        tracing::warn!(copy = %target.display(), error = %e, "couldn't make the copy readable by its owner only");
    }
    tracing::info!(copy = %target.display(), pending = pending.len(), "copied the database before migrating");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_copy_sits_in_a_backups_folder_beside_the_database() {
        let path = pre_migration_path(Path::new("data/db.sqlite3"));
        let expected = Path::new("data")
            .join("backups")
            .join(format!("pre-{}.sqlite3", env!("CARGO_PKG_VERSION")));
        assert_eq!(path, expected);
    }

    fn touch_old(path: &Path, days: u64) {
        std::fs::write(path, b"x").expect("a file");
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open")
            .set_modified(when)
            .expect("set the time");
    }

    #[test]
    fn old_copies_go_and_the_newest_two_and_the_recent_stay() {
        let folder = tempfile::tempdir().expect("a folder");
        let at = |name: &str| folder.path().join(name);
        touch_old(&at("pre-1.0.sqlite3"), 200);
        touch_old(&at("pre-1.1.sqlite3"), 120);
        touch_old(&at("pre-1.2.sqlite3"), 90);
        touch_old(&at("pre-1.3.sqlite3"), 60);
        // A rollback moved a database aside long ago, with its journal; another only last week.
        touch_old(&at("replaced-1.sqlite3"), 45);
        touch_old(&at("replaced-1.sqlite3-wal"), 45);
        touch_old(&at("replaced-2.sqlite3"), 7);
        touch_old(&at("keep-me.txt"), 400);

        let removed = prune_old_copies(folder.path(), std::time::SystemTime::now());

        // The two newest copies stay even though they are old; the two before them are over 30
        // days old and go. The old replaced database goes with its journal; the recent one stays.
        assert_eq!(removed, 4);
        for gone in [
            "pre-1.0.sqlite3",
            "pre-1.1.sqlite3",
            "replaced-1.sqlite3",
            "replaced-1.sqlite3-wal",
        ] {
            assert!(!at(gone).exists(), "{gone}");
        }
        for kept in [
            "pre-1.2.sqlite3",
            "pre-1.3.sqlite3",
            "replaced-2.sqlite3",
            "keep-me.txt",
        ] {
            assert!(at(kept).exists(), "{kept}");
        }
    }

    #[test]
    fn a_missing_folder_prunes_nothing() {
        assert_eq!(
            prune_old_copies(Path::new("no-such-folder-for-prune"), std::time::SystemTime::now()),
            0
        );
    }
}
