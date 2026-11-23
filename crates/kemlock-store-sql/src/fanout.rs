//! What replicas need from the database to nudge each other's sockets: which backend this is, and
//! on PostgreSQL its `NOTIFY` channel. SQLite is one process, and MySQL has no channel, so it
//! polls the `live_nudges` log (`kemlock_app::push::NudgeLog`).

use crate::error::StoreResult;
use crate::store::SqlStore;
use kemlock_app::ports::StoreError;
use sea_orm::sqlx::postgres::PgListener;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

/// The `NOTIFY` channel a commit nudges. The payload is the owner (`user:<uuid>` or
/// `space:<uuid>`) and nothing else.
pub const NUDGE_CHANNEL: &str = "kemlock_nudge";

/// Which database the store is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

/// A `LISTEN` on [`NUDGE_CHANNEL`].
pub struct NudgeListener {
    inner: PgListener,
}

impl std::fmt::Debug for NudgeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NudgeListener").finish_non_exhaustive()
    }
}

impl NudgeListener {
    /// The next payload. `None` means the connection dropped and was re-made: notifications
    /// sent meanwhile are lost, so the caller should nudge everyone once.
    pub async fn recv(&mut self) -> Result<Option<String>, StoreError> {
        match self.inner.try_recv().await {
            Ok(Some(notification)) => Ok(Some(notification.payload().to_owned())),
            Ok(None) => Ok(None),
            Err(err) => Err(StoreError::Backend(err.to_string())),
        }
    }
}

impl SqlStore {
    /// Which database this store is on.
    pub fn dialect(&self) -> Dialect {
        match self.writer().get_database_backend() {
            DbBackend::Sqlite => Dialect::Sqlite,
            DbBackend::Postgres => Dialect::Postgres,
            DbBackend::MySql => Dialect::MySql,
            // SeaORM only connects to the three; anything else fans out in process, like SQLite.
            _ => Dialect::Sqlite,
        }
    }

    /// `NOTIFY`s every replica listening on [`NUDGE_CHANNEL`]. PostgreSQL only.
    pub async fn pg_notify(&self, payload: &str) -> Result<(), StoreError> {
        if self.dialect() != Dialect::Postgres {
            return Err(StoreError::Backend("NOTIFY needs PostgreSQL".to_owned()));
        }
        let statement = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_notify($1, $2)",
            [NUDGE_CHANNEL.into(), payload.into()],
        );
        self.writer().execute_raw(statement).await.store()?;
        Ok(())
    }

    /// Starts a `LISTEN` on [`NUDGE_CHANNEL`] on a connection of its own. PostgreSQL only.
    pub async fn pg_listen(&self) -> Result<NudgeListener, StoreError> {
        if self.dialect() != Dialect::Postgres {
            return Err(StoreError::Backend("LISTEN needs PostgreSQL".to_owned()));
        }
        let pool = self.writer().get_postgres_connection_pool();
        let mut inner = PgListener::connect_with(pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        inner
            .listen(NUDGE_CHANNEL)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(NudgeListener { inner })
    }
}
