//! Privacy, wired into the server: the files an erasure or the trash purge deletes, the processing
//! summary's inputs, and the daily retention job.
//!
//! The processing summary reads what this server is set up to do from the environment:
//! `KEMLOCK_OPERATOR_NAME` and `KEMLOCK_DPO_CONTACT` fill the controller's lines; `SMTP_HOST` names
//! the mail provider, `SSO_AUTHORITY` the identity provider, `KEMLOCK_S3_BUCKET` (with
//! `KEMLOCK_S3_ENDPOINT`) the object storage, `PUSH_ENABLED` the push relay,
//! `KEMLOCK_UPDATE_CHECK` and `KEMLOCK_WEBSITE_ICONS` the two optional requests the server can
//! make, and the backup settings the backup destination.

use crate::adapters::ServerCrypto;
use crate::backups;
use crate::config::Config;
use kemlock_app::files::{BlobError, BlobStore as _};
use kemlock_app::ports::StoreError;
use kemlock_app::privacy::{
    AccountEraser, EraseAccount, ErasureFiles, ProcessingInputs, ProcessingSource, RunRetention,
};
use kemlock_app::sends::EraseSends;
use kemlock_blob::{BlobConfig, ObjectBlobStore};
use kemlock_crypto::rand;
use kemlock_domain::BlobId;
use kemlock_store_sql::SqlStore;
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::{Instant, MissedTickBehavior};

/// The lease that makes the retention job run on one replica at a time.
pub const RETENTION_LEASE: &str = "retention";
const LEASE_TTL: time::Duration = time::Duration::hours(1);
/// How often the retention job runs.
const RETENTION_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after the server starts the first run is, so start-up isn't slowed and a
/// crash-looping server doesn't run it on every start.
const FIRST_RETENTION_AFTER: Duration = Duration::from_secs(20 * 60);

/// The files an erasure or the trash purge deletes: attachments of the Kemlock API (by blob id,
/// in a folder or a bucket) and files of the Bitwarden API (by `<cipher id>/<attachment id>`, in
/// the data folder's `attachments`).
#[derive(Clone)]
pub struct ServerFiles {
    /// Kemlock files and, under their `<cipher>/<attachment>` keys, the Bitwarden API's.
    blobs: ObjectBlobStore,
}

impl std::fmt::Debug for ServerFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerFiles").finish_non_exhaustive()
    }
}

impl ServerFiles {
    pub fn new(blobs: ObjectBlobStore, _data_folder: &Path) -> Self {
        ServerFiles { blobs }
    }

    /// The Sends eraser of an account erasure: every Send of the account in `store`, with the
    /// bytes of its file Sends in this file storage.
    pub fn send_eraser(&self, store: &SqlStore) -> EraseSends<SqlStore, ObjectBlobStore> {
        EraseSends {
            sends: store.clone(),
            blobs: self.blobs.clone(),
        }
    }
}

impl ErasureFiles for ServerFiles {
    async fn delete_blob(&self, blob: BlobId) -> Result<(), StoreError> {
        match self.blobs.delete(blob).await {
            Ok(()) | Err(BlobError::NotFound) => Ok(()),
            Err(e) => Err(StoreError::Backend(e.to_string())),
        }
    }

    async fn delete_cipher_file(&self, key: &str) -> Result<(), StoreError> {
        self.blobs
            .delete_raw(key)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

/// The file deleters over the configured file storage and the data folder.
pub fn server_files(data_folder: &Path) -> Result<ServerFiles, String> {
    let settings = BlobConfig::from_env(data_folder).map_err(|e| e.to_string())?;
    let blobs =
        ObjectBlobStore::from_config(&settings).map_err(|e| format!("file storage: {e}"))?;
    Ok(ServerFiles::new(blobs, data_folder))
}

fn lookup(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn on(env: &dyn Fn(&str) -> Option<String>, name: &str) -> bool {
    lookup(env, name).is_some_and(|v| {
        ["1", "true", "yes", "on"]
            .iter()
            .any(|t| v.eq_ignore_ascii_case(t))
    })
}

/// What the processing summary says about this server, from the environment.
pub fn processing_inputs(
    env: &dyn Fn(&str) -> Option<String>,
    backup_destination: Option<&str>,
) -> ProcessingInputs {
    ProcessingInputs {
        operator_name: lookup(env, "KEMLOCK_OPERATOR_NAME"),
        dpo_contact: lookup(env, "KEMLOCK_DPO_CONTACT"),
        smtp_provider: lookup(env, "SMTP_HOST"),
        identity_provider: on(env, "SSO_ENABLED")
            .then(|| lookup(env, "SSO_AUTHORITY"))
            .flatten(),
        push_relay: on(env, "PUSH_ENABLED"),
        s3_storage: lookup(env, "KEMLOCK_S3_BUCKET").map(|bucket| {
            lookup(env, "KEMLOCK_S3_ENDPOINT").unwrap_or_else(|| format!("AWS S3 ({bucket})"))
        }),
        update_check: on(env, "KEMLOCK_UPDATE_CHECK"),
        website_icons: on(env, "KEMLOCK_WEBSITE_ICONS"),
        backup_destination: backup_destination.map(str::to_owned),
        federation_peers: 0,
    }
}

/// The processing summary's source on this server: the environment, read when asked.
#[derive(Clone, Debug)]
pub struct EnvProcessing {
    pub config: Config,
}

impl ProcessingSource for EnvProcessing {
    async fn inputs(&self) -> Result<ProcessingInputs, StoreError> {
        let destination = backups::settings(&self.config)
            .ok()
            .filter(|s| !s.recipient.is_empty())
            .map(|s| s.destination.kind().to_owned());
        Ok(processing_inputs(
            &|name| std::env::var(name).ok(),
            destination.as_deref(),
        ))
    }
}

fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One pass of the retention job, under the lease: deletes what has outlived its retention, then
/// erases the accounts whose grace period is over. `Ok(None)` means another replica holds the
/// lease and this one did nothing.
pub async fn retention_once(
    store: &SqlStore,
    crypto: &ServerCrypto,
    files: &ServerFiles,
    holder: &str,
) -> Result<Option<kemlock_app::privacy::RetentionReport>, String> {
    if !store
        .try_lease(RETENTION_LEASE, holder, LEASE_TTL)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(None);
    }
    let outcome = run_retention(store, crypto, files).await;
    // Given back at once, so the next day's run never waits for it to lapse.
    if let Err(e) = store.release_lease(RETENTION_LEASE, holder).await {
        tracing::warn!(error = %e, "couldn't release the retention lease");
    }
    outcome.map(Some)
}

async fn run_retention(
    store: &SqlStore,
    crypto: &ServerCrypto,
    files: &ServerFiles,
) -> Result<kemlock_app::privacy::RetentionReport, String> {
    let report = RunRetention {
        settings: store.clone(),
        store: store.clone(),
        items: store.clone(),
        approvals: store.clone(),
        files: files.clone(),
        clock: crypto.clone(),
    }
    .execute()
    .await
    .map_err(|e| e.to_string())?;

    // Accounts whose deletion grace period is over.
    let due = AccountEraser::due_erasures(store, OffsetDateTime::now_utc())
        .await
        .map_err(|e| e.to_string())?;
    if !due.is_empty() {
        let eraser = EraseAccount {
            users: store.clone(),
            eraser: store.clone(),
            sends: files.send_eraser(store),
            files: files.clone(),
            settings: store.clone(),
            log: store.clone(),
            env: crypto.clone(),
        };
        for user in due {
            match eraser.erase_due(user).await {
                Ok(_) => tracing::info!("erased an account whose grace period ended"),
                Err(e) => tracing::warn!(error = %e, "couldn't erase an account that was due"),
            }
        }
    }
    Ok(report)
}

/// Starts the daily retention job. The task ends when the handle is aborted or the runtime stops.
pub fn spawn_retention(
    store: SqlStore,
    crypto: ServerCrypto,
    files: ServerFiles,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let holder = holder_name();
        let mut every =
            tokio::time::interval_at(Instant::now() + FIRST_RETENTION_AFTER, RETENTION_EVERY);
        every.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            match retention_once(&store, &crypto, &files, &holder).await {
                Ok(Some(report)) => tracing::info!(?report, "retention applied"),
                Ok(None) => tracing::debug!("another replica holds the retention lease"),
                Err(e) => tracing::warn!(error = %e, "the retention job failed"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn inputs(vars: &[(&str, &str)], destination: Option<&str>) -> ProcessingInputs {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        processing_inputs(&|name| map.get(name).cloned(), destination)
    }

    #[test]
    fn a_bare_server_has_nothing_to_declare() {
        assert_eq!(inputs(&[], None), ProcessingInputs::default());
    }

    #[test]
    fn the_integrations_that_are_on_are_named() {
        let i = inputs(
            &[
                ("KEMLOCK_OPERATOR_NAME", "Example GmbH"),
                ("SMTP_HOST", "smtp.example.org"),
                ("SSO_ENABLED", "true"),
                ("SSO_AUTHORITY", "https://id.example.org"),
                ("PUSH_ENABLED", "TRUE"),
                ("KEMLOCK_S3_BUCKET", "vault"),
                ("KEMLOCK_UPDATE_CHECK", "1"),
            ],
            Some("S3"),
        );
        assert_eq!(i.operator_name.as_deref(), Some("Example GmbH"));
        assert_eq!(i.smtp_provider.as_deref(), Some("smtp.example.org"));
        assert_eq!(
            i.identity_provider.as_deref(),
            Some("https://id.example.org")
        );
        assert!(i.push_relay);
        assert_eq!(i.s3_storage.as_deref(), Some("AWS S3 (vault)"));
        assert!(i.update_check);
        assert!(!i.website_icons);
        assert_eq!(i.backup_destination.as_deref(), Some("S3"));
    }

    #[test]
    fn an_identity_provider_that_is_switched_off_is_not_named() {
        let i = inputs(&[("SSO_AUTHORITY", "https://id.example.org")], None);
        assert_eq!(i.identity_provider, None);
    }

    #[test]
    fn a_bucket_with_an_endpoint_is_named_by_it() {
        let i = inputs(
            &[
                ("KEMLOCK_S3_BUCKET", "vault"),
                ("KEMLOCK_S3_ENDPOINT", "https://s3.example.org"),
            ],
            None,
        );
        assert_eq!(i.s3_storage.as_deref(), Some("https://s3.example.org"));
    }

    #[test]
    fn holder_names_differ() {
        assert_ne!(holder_name(), holder_name());
    }
}
