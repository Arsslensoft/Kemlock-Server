//! Running the migrations under a lock, and loading or making this server's identity.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::lease;
use crate::migration::{Migrator, job_leases_table};
use crate::tables::server_meta;
use kemlock_app::ports::StoreError;
use kemlock_domain::ServerId;
use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, Statement};
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
}
