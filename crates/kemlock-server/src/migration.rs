//! The move from Vaultwarden, started from the admin console and run in the background.
//!
//! `POST /admin/v1/migration/start` must answer inside the request timeout, and a move reads a
//! whole Vaultwarden server and copies its files, so [`VaultwardenMove`] (the admin API's
//! `MigrationRunner`) only takes the lease [`MIGRATION_LEASE`], records the move as running and
//! hands the work to a task. The task does what `kemlock-cli import-vaultwarden --apply` does:
//! `kemlock-vaultwarden` reads and maps the source (read-only), and `kemlock-store-sql`'s
//! `SqlImportSink` writes the accounts, vaults, files and carried rows in one transaction, so a
//! failed move leaves nothing half written and a rerun finds what an earlier one put. Its stage
//! and its result or error go to the status the Migration screen shows (`MigrationRecord`), which
//! every replica reads from the same table.
//!
//! One move runs at a time on the whole cluster: the lease is taken before anything starts and
//! given back when the task ends. A holder that crashed leaves a running status behind and a
//! lease that lapses after [`LEASE_TTL`]; [`VaultwardenMove::recover`], at start, turns such a
//! status into a failure the admin can retry from.

use crate::adapters::ServerCrypto;
use kemlock_app::admin::{
    AdminError, MigrationRecord, MigrationRequest, MigrationRunner, MigrationState, MigrationStatus,
};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::Zeroizing;
use kemlock_crypto::rand;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::UserId;
use kemlock_store_sql::{ImportFiles, ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::reader::redact_url;
use kemlock_vaultwarden::{ApplyReport, Source, apply, map_snapshot, read_snapshot, render_plan};
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;

/// The lease that lets one move run at a time.
pub const MIGRATION_LEASE: &str = "vaultwarden-migration";
/// How long a replica holds the lease: a move can take hours, and a crashed holder is an obstacle
/// only until this lapses.
pub const LEASE_TTL: time::Duration = time::Duration::hours(12);

/// What the task says when the server stopped under a running move.
const INTERRUPTED: &str =
    "the server stopped before the move finished; nothing was half written, start it again";

fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Starts and runs moves from Vaultwarden into this server's own database and data folder.
#[derive(Clone)]
pub struct VaultwardenMove {
    store: SqlStore,
    crypto: ServerCrypto,
    /// What `ServerSeal` is made from for each move; wiped when the last clone is dropped.
    server_key: Arc<Zeroizing<[u8; 32]>>,
    /// Where the import copies `rsa_key.pem`.
    data_folder: PathBuf,
    holder: Arc<str>,
    files: Arc<dyn ImportFiles>,
}

impl std::fmt::Debug for VaultwardenMove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultwardenMove").finish_non_exhaustive()
    }
}

/// What a finished pass wrote, in words.
fn describe(report: &ApplyReport) -> String {
    let mut text = format!(
        "wrote {} accounts, {} folders, {} items, {} attachments ({} files, {} bytes), \
         {} carried rows, {} settings",
        report.accounts,
        report.folders,
        report.items,
        report.attachments,
        report.files,
        report.file_bytes,
        report.carried_rows,
        report.settings,
    );
    if report.rsa_key {
        text.push_str(
            ". Vaultwarden's rsa_key.pem was carried over: restart Kemlock Server so it loads it",
        );
    }
    text
}

impl VaultwardenMove {
    /// A runner over `store`, sealing under `server_key`, writing `rsa_key.pem` into `data_folder`
    /// and attachments and Send files into `files`, the file storage the Bitwarden API reads.
    pub fn new(
        store: SqlStore,
        crypto: ServerCrypto,
        server_key: &[u8; 32],
        data_folder: PathBuf,
        files: Arc<dyn ImportFiles>,
    ) -> VaultwardenMove {
        VaultwardenMove {
            store,
            crypto,
            server_key: Arc::new(Zeroizing::new(*server_key)),
            data_folder,
            holder: holder_name().into(),
            files,
        }
    }

    fn record(&self) -> MigrationRecord<SqlStore, ServerCrypto> {
        MigrationRecord {
            repo: self.store.clone(),
            clock: self.crypto.clone(),
        }
    }

    /// Turns a status left `running` by a server that stopped into a failure, when no replica
    /// holds the lease any more. Called once at start. `Ok(true)` when it did.
    pub async fn recover(&self) -> Result<bool, AdminError> {
        let record = self.record();
        let status = record.status().await?;
        if status.state != MigrationState::Running {
            return Ok(false);
        }
        // A running move on another replica holds the lease; only an orphan can be taken.
        if !self
            .store
            .try_lease(MIGRATION_LEASE, &self.holder, LEASE_TTL)
            .await?
        {
            return Ok(false);
        }
        let outcome = record
            .failed(
                status.started_by.unwrap_or(UserId(uuid::Uuid::nil())),
                status.source.unwrap_or_default(),
                INTERRUPTED.to_owned(),
            )
            .await;
        if let Err(e) = self
            .store
            .release_lease(MIGRATION_LEASE, &self.holder)
            .await
        {
            tracing::warn!(error = %e, "couldn't release the migration lease");
        }
        outcome.map(|_| true)
    }

    async fn begin(&self, request: MigrationRequest) -> Result<MigrationStatus, AdminError> {
        let source = Source::parse(&request.from, request.files.as_deref())
            .map_err(|e| AdminError::Invalid(e.to_string()))?;
        if !self
            .store
            .try_lease(MIGRATION_LEASE, &self.holder, LEASE_TTL)
            .await?
        {
            return Err(AdminError::State(
                "a move from Vaultwarden is already running",
            ));
        }
        let shown = redact_url(&request.from);
        let status = match self.record().running(request.by, shown.clone()).await {
            Ok(status) => status,
            Err(e) => {
                self.release().await;
                return Err(e);
            }
        };
        let job = self.clone();
        tokio::spawn(async move { job.run(request.by, source, shown).await });
        Ok(status)
    }

    async fn release(&self) {
        if let Err(e) = self
            .store
            .release_lease(MIGRATION_LEASE, &self.holder)
            .await
        {
            tracing::warn!(error = %e, "couldn't release the migration lease");
        }
    }

    /// The background task: the move, then its outcome into the status, then the lease back.
    async fn run(self, by: UserId, source: Source, shown: String) {
        let record = self.record();
        let saved = match self.import(&source).await {
            Ok(report) => {
                tracing::info!(%report, "the move from Vaultwarden is done");
                record.finished(report).await
            }
            Err(error) => {
                tracing::warn!(%error, "the move from Vaultwarden failed");
                record.failed(by, shown, error).await
            }
        };
        if let Err(e) = saved {
            tracing::error!(error = %e, "couldn't record the outcome of the Vaultwarden move");
        }
        self.release().await;
    }

    /// Reads, maps and writes. The error is in words for the admin.
    async fn import(&self, source: &Source) -> Result<String, String> {
        let record = self.record();
        self.stage(&record, "reading the Vaultwarden data", None)
            .await;
        let snapshot = read_snapshot(source).await.map_err(|e| e.to_string())?;
        self.stage(&record, "mapping the data", None).await;
        let mapped = map_snapshot(&snapshot).map_err(|e| format!("can't map the data: {e}"))?;
        let plan = render_plan(&snapshot.meta, &mapped, None);
        self.stage(&record, "writing to Kemlock Server", Some(plan))
            .await;
        let options = ImportOptions::new(
            self.data_folder.clone(),
            self.files.clone(),
            OffsetDateTime::now_utc(),
        );
        let mut sink =
            SqlImportSink::begin(&self.store, ServerSeal::new(&self.server_key), options)
                .await
                .map_err(|e| e.to_string())?;
        let report = apply(&mapped, &[], &mut sink)
            .await
            .map_err(|e| e.to_string())?;
        Ok(describe(&report))
    }

    async fn stage(
        &self,
        record: &MigrationRecord<SqlStore, ServerCrypto>,
        stage: &str,
        plan: Option<String>,
    ) {
        if let Err(e) = record.progress(stage, plan).await {
            tracing::warn!(error = %e, "couldn't record the stage of the move");
        }
    }
}

impl MigrationRunner for VaultwardenMove {
    fn start<'a>(
        &'a self,
        request: MigrationRequest,
    ) -> BoxFuture<'a, Result<MigrationStatus, AdminError>> {
        Box::pin(self.begin(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_says_what_was_written_and_when_to_restart() {
        let report = ApplyReport {
            accounts: 2,
            folders: 1,
            items: 30,
            attachments: 4,
            carried_rows: 5,
            settings: 3,
            files: 6,
            file_bytes: 1024,
            ..ApplyReport::default()
        };
        let text = describe(&report);
        assert_eq!(
            text,
            "wrote 2 accounts, 1 folders, 30 items, 4 attachments (6 files, 1024 bytes), \
             5 carried rows, 3 settings"
        );
        let with_key = describe(&ApplyReport {
            rsa_key: true,
            ..report
        });
        assert!(
            with_key.ends_with("restart Kemlock Server so it loads it"),
            "{with_key}"
        );
    }

    #[test]
    fn holder_names_differ() {
        assert_ne!(holder_name(), holder_name());
        assert_eq!(holder_name().len(), 32);
    }
}
