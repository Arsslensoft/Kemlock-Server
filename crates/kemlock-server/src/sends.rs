//! Sends and space policies, wired: the Send routes over the store and the blob store, the policy
//! routes, the join check on the spaces routes, and the job that deletes Sends whose date has come.
//!
//! The Send routes are returned apart from the API router, like the file routes, because an upload
//! takes as long as the connection does and so runs under a longer timeout. File Sends go to the
//! same folder or bucket as attachments (`kemlock_blob::config`), under random blob ids.

use crate::adapters::ServerCrypto;
use crate::app::RunError;
use axum::Router;
use axum::http::StatusCode;
use kemlock_api_kem::{
    Api, JwsTokenSigner, policies_router, sends_router, spaces_router, with_join_guard,
};
use kemlock_app::policies::MemberSendRules;
use kemlock_app::ports::{Clock, StoreError};
use kemlock_app::sends::{PurgeSends, SendsConfig, SendsError};
use kemlock_blob::{BlobConfig, ObjectBlobStore};
use kemlock_crypto::rand;
use kemlock_domain::sends::SendLimits;
use kemlock_store_sql::SqlStore;
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use tower_http::timeout::TimeoutLayer;

/// How long one Send request may take. A 100 MiB file on a slow link takes minutes.
const SEND_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How often the job that deletes due Sends runs.
const PURGE_EVERY: Duration = Duration::from_secs(15 * 60);
/// The lease that makes the job run on one replica at a time.
pub const PURGE_LEASE: &str = "purge-sends";
/// How long a replica holds the lease: far more than a run takes.
const LEASE_TTL: time::Duration = time::Duration::minutes(30);

/// The wall clock, for the job.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

type Purge = PurgeSends<SqlStore, ObjectBlobStore, SystemClock>;

/// What the server keeps to run the Send job.
pub struct SendJobs {
    purge: Purge,
    store: SqlStore,
}

impl std::fmt::Debug for SendJobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendJobs").finish_non_exhaustive()
    }
}

/// The routes of Sends and space policies, and the job. The first router goes under the longer
/// timeout; the second (policies, and the spaces routes with the join check) under the usual one.
pub fn wire(
    data_folder: &Path,
    api: &Api<SqlStore, ServerCrypto, JwsTokenSigner>,
    store: &SqlStore,
) -> Result<(Router, Router, SendJobs), RunError> {
    let settings =
        BlobConfig::from_env(data_folder).map_err(|e| RunError::Config(e.to_string()))?;
    let blobs = ObjectBlobStore::from_config(&settings)
        .map_err(|e| RunError::Config(format!("file storage: {e}")))?;
    let config = SendsConfig {
        limits: SendLimits {
            max_file_size: settings.max_size,
        },
        ..SendsConfig::default()
    };
    let rules = MemberSendRules {
        spaces: store.clone(),
        policies: store.clone(),
    };
    let sends = sends_router(api.clone(), store.clone(), blobs.clone(), rules, config).layer(
        TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, SEND_TIMEOUT),
    );
    let spaces = with_join_guard(
        spaces_router(api.clone(), store.clone()),
        api.clone(),
        store.clone(),
        store.clone(),
    )
    .merge(policies_router(api.clone(), store.clone(), store.clone()));
    let purge = PurgeSends {
        sends: store.clone(),
        blobs,
        clock: SystemClock,
        config,
    };
    Ok((
        sends,
        spaces,
        SendJobs {
            purge,
            store: store.clone(),
        },
    ))
}

/// A name for this process to hold the lease under: unique per process.
fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why one run of the job failed.
#[derive(Debug, PartialEq, Eq)]
pub enum JobError {
    Store(StoreError),
    Sends(SendsError),
}

/// One run, under the lease: deletes the Sends past their date and the file Sends nobody finished
/// uploading. `Ok(Some(n))` is how many went; `Ok(None)` means another replica holds the lease
/// and this one did nothing.
pub async fn purge_once(
    purge: &Purge,
    store: &SqlStore,
    holder: &str,
) -> Result<Option<u64>, JobError> {
    if !store
        .try_lease(PURGE_LEASE, holder, LEASE_TTL)
        .await
        .map_err(JobError::Store)?
    {
        return Ok(None);
    }
    let purged = purge.execute().await.map_err(JobError::Sends);
    // Given back at once, so the next run never waits on this lease to lapse.
    if let Err(e) = store.release_lease(PURGE_LEASE, holder).await {
        tracing::warn!(error = %e, "couldn't release the Send purge lease");
    }
    purged.map(Some)
}

impl SendJobs {
    /// Starts the job: once at start and then every 15 minutes. It stops with the runtime.
    pub fn spawn_purge(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let holder = holder_name();
            let mut tick = tokio::time::interval(PURGE_EVERY);
            loop {
                tick.tick().await;
                match purge_once(&self.purge, &self.store, &holder).await {
                    Ok(Some(0)) => {}
                    Ok(Some(purged)) => tracing::info!(purged, "deleted Sends past their date"),
                    Ok(None) => tracing::debug!("another replica holds the Send purge lease"),
                    Err(e) => tracing::warn!(error = ?e, "the Send purge failed"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::ports::UserRepo;
    use kemlock_app::sends::SendRepo;
    use kemlock_domain::sends::{SendId, SendKind, SendRecord};
    use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
    use uuid::Uuid;

    async fn store() -> SqlStore {
        SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects")
    }

    async fn owner(store: &SqlStore) -> UserId {
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: UserId::random(),
            email: Email::parse("sam@example.org").expect("an email"),
            name: None,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account([3; 16]),
            opaque_record: None,
            wrapped_root_key: vec![2; 100],
            public_bundle: vec![3; 100],
            bundle_signature: vec![4; 100],
            sealed_private_keys: vec![5; 100],
            key_version: 1,
            security_stamp: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        };
        UserRepo::insert(store, &user).await.expect("stored");
        user.id
    }

    fn send(owner: UserId, deletion_at: OffsetDateTime) -> SendRecord {
        let now = OffsetDateTime::now_utc();
        SendRecord {
            id: SendId::random(),
            owner,
            kind: SendKind::Text,
            meta: vec![1; 10],
            sealed_key: vec![2; 10],
            payload: vec![3; 10],
            file: None,
            password: None,
            max_access: None,
            access_count: 0,
            hide_email: false,
            disabled: false,
            expires_at: None,
            deletion_at,
            created_at: now,
            revised_at: now,
        }
    }

    fn purge(store: &SqlStore) -> Purge {
        PurgeSends {
            sends: store.clone(),
            blobs: ObjectBlobStore::memory(),
            clock: SystemClock,
            config: SendsConfig::default(),
        }
    }

    #[tokio::test]
    async fn the_job_deletes_only_the_sends_past_their_date() {
        let store = store().await;
        let owner = owner(&store).await;
        let now = OffsetDateTime::now_utc();
        let due = send(owner, now - time::Duration::minutes(5));
        let later = send(owner, now + time::Duration::days(3));
        SendRepo::add_send(&store, &due).await.expect("stored");
        SendRepo::add_send(&store, &later).await.expect("stored");

        let ran = purge_once(&purge(&store), &store, "me").await;
        assert_eq!(ran, Ok(Some(1)));
        assert_eq!(SendRepo::send_by_id(&store, due.id).await, Ok(None));
        assert!(
            SendRepo::send_by_id(&store, later.id)
                .await
                .expect("read")
                .is_some()
        );
    }

    #[tokio::test]
    async fn only_the_replica_holding_the_lease_runs_and_it_gives_the_lease_back() {
        let store = store().await;
        let owner = owner(&store).await;
        let due = send(
            owner,
            OffsetDateTime::now_utc() - time::Duration::minutes(5),
        );
        SendRepo::add_send(&store, &due).await.expect("stored");

        assert_eq!(
            store.try_lease(PURGE_LEASE, "other", LEASE_TTL).await,
            Ok(true)
        );
        assert_eq!(purge_once(&purge(&store), &store, "me").await, Ok(None));
        assert!(
            SendRepo::send_by_id(&store, due.id)
                .await
                .expect("read")
                .is_some(),
            "nothing was deleted"
        );

        store
            .release_lease(PURGE_LEASE, "other")
            .await
            .expect("release");
        assert_eq!(purge_once(&purge(&store), &store, "me").await, Ok(Some(1)));
        assert_eq!(
            store.try_lease(PURGE_LEASE, "other", LEASE_TTL).await,
            Ok(true)
        );
    }

    #[test]
    fn holder_names_differ() {
        assert_eq!(holder_name().len(), 32);
        assert_ne!(holder_name(), holder_name());
    }
}
