//! `SqlStore`: the handle every repository port is implemented on.

use crate::connect::{self, Pools, StoreOptions};
use crate::error::StoreResult;
use crate::lease;
use crate::migrate;
use kemlock_app::ports::{ServerInfo, StoreError};
use kemlock_domain::ServerId;
use kemlock_domain::privacy::Retention;
use sea_orm::DatabaseConnection;
use kemlock_crypto::seal::ServerSeal;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

/// SQL storage for accounts, devices, tokens and the vault's items, on SQLite, PostgreSQL or
/// MySQL. Cloning is cheap: clones share the pools.
///
/// It implements `ServerInfo`, `UserRepo`, `DeviceRepo`, `TokenRepo`, `TwoFactorRepo`,
/// `ItemStore` and `EventLog` from `kemlock_app::ports`. Several ports share method names
/// (`get`, `put`, `list`, `insert`, `remove`), so call them as `ItemStore::get(&store, id)`.
#[derive(Clone, Debug)]
pub struct SqlStore {
    inner: Arc<Inner>,
}

/// What the server applies over the saved retention settings each time they are read.
type RetentionOverlay = Arc<dyn Fn(&mut Retention) + Send + Sync>;

#[derive(Default)]
struct Overlay(RwLock<Option<RetentionOverlay>>);

impl std::fmt::Debug for Overlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Overlay").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Inner {
    /// Every write goes through here; on SQLite this pool holds a single connection.
    writer: DatabaseConnection,
    /// Plain reads; on SQLite a pool of readers that never wait for a write.
    reader: DatabaseConnection,
    server_id: ServerId,
    /// Applied over the saved retention settings each time they are read.
    retention_overlay: Overlay,
    /// The verified state of the space chains in use, each under the link of its head.
    chain_states: crate::repo::ChainStates,
    /// Seals the secrets the store keeps that the server must show again (a personal API key),
    /// under `server.key`. Set once, at start; a store without one (a tool that reads the
    /// database, a test) keeps them as they come.
    secret_seal: OnceLock<ServerSeal>,
    /// Held while a storage quota is summed and the row it covers is inserted. One server owns a
    /// database, so this serializes the check and the insert on PostgreSQL and MySQL, where a
    /// transaction alone lets two announces each read the sum before either has inserted; on SQLite
    /// the single writer connection does it already.
    quota_gate: tokio::sync::Mutex<()>,
    /// Held across a space change that must leave the space an owner: the check reads the owners
    /// before and after, and on PostgreSQL and MySQL two transactions could each see two owners,
    /// each delete the other, and both commit. One server owns a database, as for `quota_gate`.
    owner_gate: tokio::sync::Mutex<()>,
}

impl SqlStore {
    /// Connects to `url` (`sqlite://path?mode=rwc`, `sqlite::memory:`, `postgres://...`,
    /// `mysql://...`) with the default options, runs pending migrations under a lock, and loads
    /// this server's id, making it on the first start.
    pub async fn connect(url: &str) -> Result<SqlStore, StoreError> {
        SqlStore::connect_with(url, StoreOptions::default()).await
    }

    /// [`connect`](Self::connect) with pool sizes and SQLite durability chosen by the caller.
    pub async fn connect_with(url: &str, options: StoreOptions) -> Result<SqlStore, StoreError> {
        let Pools { writer, reader } = connect::open(url, &options).await?;
        migrate::run(&writer).await?;
        let server_id = migrate::load_or_create_server_id(&writer).await?;
        tracing::info!(%server_id, "database ready");
        Ok(SqlStore {
            inner: Arc::new(Inner {
                writer,
                reader,
                server_id,
                retention_overlay: Overlay::default(),
                chain_states: crate::repo::ChainStates::default(),
                secret_seal: OnceLock::new(),
                quota_gate: tokio::sync::Mutex::new(()),
                owner_gate: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Takes the named lease for `ttl`, so a background job runs on one replica at a time:
    /// `Ok(true)` when it is now `holder`'s (a lease that was free, or had expired), `Ok(false)`
    /// when another holder has it. The lease lapses by itself after `ttl`, for a holder that
    /// crashed; a holder that lives gives it back with [`SqlStore::release_lease`].
    pub async fn try_lease(
        &self,
        name: &str,
        holder: &str,
        ttl: time::Duration,
    ) -> Result<bool, StoreError> {
        lease::try_acquire(self.writer(), name, holder, ttl).await
    }

    /// Gives back a lease `holder` holds; a lease held by someone else is left alone.
    pub async fn release_lease(&self, name: &str, holder: &str) -> Result<(), StoreError> {
        lease::release(self.writer(), name, holder).await
    }

    /// Sets what is applied over the retention settings each time they are read, by every part
    /// of the server that reads them (the retention job, backups, account erasure). The server
    /// uses it to put the environment, the config file and the settings the console saved over
    /// the stored value, and to follow them when they change. Replaces an earlier overlay.
    pub fn set_retention_overlay(&self, overlay: impl Fn(&mut Retention) + Send + Sync + 'static) {
        let mut slot = self
            .inner
            .retention_overlay
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *slot = Some(Arc::new(overlay));
    }

    /// Gives the store the seal it keeps the personal API keys of Bitwarden accounts under (the
    /// server's `server.key`, purpose `bw-api-key`). A key stored plain, by an earlier version or
    /// by the move from Vaultwarden, is sealed at start-up by `seal_stored_secrets`, or when it is
    /// read before then. Set once; a second call is
    /// ignored.
    pub fn set_secret_seal(&self, seal: ServerSeal) {
        let _ = self.inner.secret_seal.set(seal);
    }

    pub(crate) fn secret_seal(&self) -> Option<&ServerSeal> {
        self.inner.secret_seal.get()
    }

    /// Applies the overlay, if one is set, to `retention`.
    pub(crate) fn overlay_retention(&self, retention: &mut Retention) {
        let overlay = self
            .inner
            .retention_overlay
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(overlay) = overlay {
            overlay(retention);
        }
    }

    /// Applies pending migrations, if any. Idempotent; `connect` already calls it.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        migrate::run(&self.inner.writer).await
    }

    /// Checks the database answers, for `/health`.
    pub async fn ping(&self) -> Result<(), StoreError> {
        self.inner.writer.ping().await.store()?;
        self.inner.reader.ping().await.store()
    }

    /// Closes the pools, letting SQLite checkpoint its WAL. Call it on shutdown.
    pub async fn close(&self) -> Result<(), StoreError> {
        self.inner.writer.close_by_ref().await.store()?;
        self.inner.reader.close_by_ref().await.store()
    }

    pub(crate) fn writer(&self) -> &DatabaseConnection {
        &self.inner.writer
    }

    pub(crate) fn chain_states(&self) -> &crate::repo::ChainStates {
        &self.inner.chain_states
    }

    /// Lock this around a quota's sum and the insert it guards.
    pub(crate) async fn quota_gate(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.quota_gate.lock().await
    }

    /// Lock this around a space change that must leave the space a confirmed owner.
    pub(crate) async fn owner_gate(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.owner_gate.lock().await
    }

    pub(crate) fn reader(&self) -> &DatabaseConnection {
        &self.inner.reader
    }

    pub(crate) fn origin(&self) -> ServerId {
        self.inner.server_id
    }
}

impl ServerInfo for SqlStore {
    fn server_id(&self) -> ServerId {
        self.inner.server_id
    }
}
