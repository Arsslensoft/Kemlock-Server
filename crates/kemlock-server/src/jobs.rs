//! Background jobs. Each runs on one replica at a time, under a lease in the `job_leases` table.
//!
//! - the daily purge of old tombstones: deleted items leave a tombstone so that devices that were
//!   offline learn of the deletion; after [`TOMBSTONE_RETENTION_DAYS`] a device that has not synced
//!   since is asked for a full sync instead (the per-owner tombstone horizon), and the tombstone
//!   can go;
//! - the hourly emergency-access timer, which approves requests whose wait has ended
//!   ([`ApproveDue`]);
//! - the five-minute purge of device-approval requests that expired a day ago
//!   ([`PurgeApprovals`]);
//! - the hourly purge of attachments no item names any more;
//! - the daily re-check of verified SSO domains: a proof whose DNS record is gone is taken back.
//!
//! The leases are released as soon as a run ends, so the next run never waits on one; a replica
//! that crashes mid-run holds its lease until the lease's own time is up.

use crate::adapters::ServerCrypto;
use crate::files::Files;
use kemlock_app::devices::{LogNotices, PurgeApprovals};
use kemlock_app::emergency::ApproveDue;
use kemlock_app::sso::DomainProofs;
use kemlock_app::ports::{ItemStore, StoreError};
use kemlock_crypto::rand;
use kemlock_store_sql::SqlStore;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

/// How long a tombstone is kept before the purge may remove it.
pub const TOMBSTONE_RETENTION_DAYS: i64 = 180;
/// The lease that makes the purge run on one replica at a time.
pub const PURGE_LEASE: &str = "purge-tombstones";
/// The lease of the emergency-access timer.
pub const APPROVE_DUE_LEASE: &str = "emergency-approve-due";
/// The lease of the device-approval purge.
pub const PURGE_APPROVALS_LEASE: &str = "purge-device-approvals";
/// The lease of the orphaned-file purge.
pub const PURGE_FILES_LEASE: &str = "purge-orphan-files";
/// The lease of the verified-domain re-check.
pub const RECHECK_DOMAINS_LEASE: &str = "recheck-verified-domains";
/// How long a replica holds the purge lease: far more than a purge takes, so a crashed holder
/// is only an obstacle until it lapses.
const LEASE_TTL: time::Duration = time::Duration::hours(1);
/// The lease of the quick jobs: they take seconds, and a crashed holder blocks the next run or
/// two at most.
const SHORT_LEASE_TTL: time::Duration = time::Duration::minutes(10);
/// How often the purge runs.
const PURGE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after the server starts the first purge runs, so start-up isn't slowed by it and a
/// crash-looping server doesn't purge on every start.
const FIRST_PURGE_AFTER: Duration = Duration::from_secs(10 * 60);
/// How often the emergency-access timer looks for requests whose wait has ended. A wait is
/// counted in days, so an hour's delay is nothing.
pub const APPROVE_DUE_EVERY: Duration = Duration::from_secs(60 * 60);
/// How often expired device-approval requests are purged.
pub const PURGE_APPROVALS_EVERY: Duration = Duration::from_secs(5 * 60);
/// How often orphaned files are purged.
pub const PURGE_FILES_EVERY: Duration = Duration::from_secs(60 * 60);
/// How often verified SSO domains are looked at again.
pub const RECHECK_DOMAINS_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How old a domain's proof must be before it is looked at again.
pub const RECHECK_DOMAINS_AFTER: time::Duration = time::Duration::days(7);
/// How long after the server starts the quick jobs first run.
const FIRST_RUN_AFTER: Duration = Duration::from_secs(30);

/// A name for this process to hold leases under: unique per process, so two replicas never
/// confuse each other's leases.
pub(crate) fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What stops a leased job from finishing.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// The lease couldn't be taken: the store failed.
    #[error("couldn't take the lease: {0}")]
    Lease(#[from] StoreError),
    /// The job itself failed.
    #[error("{0}")]
    Run(String),
}

/// Runs `job` when this replica gets the lease `name`, and gives the lease back after. `Ok(None)`
/// means another replica holds it and nothing ran.
pub async fn under_lease<T, E, F, Fut>(
    store: &SqlStore,
    name: &str,
    holder: &str,
    ttl: time::Duration,
    job: F,
) -> Result<Option<T>, JobError>
where
    E: std::fmt::Display,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    if !store.try_lease(name, holder, ttl).await? {
        return Ok(None);
    }
    let outcome = job().await;
    if let Err(e) = store.release_lease(name, holder).await {
        tracing::warn!(lease = name, error = %e, "couldn't release a job lease");
    }
    outcome.map(Some).map_err(|e| JobError::Run(e.to_string()))
}

/// One purge: under the lease, removes tombstones deleted more than
/// [`TOMBSTONE_RETENTION_DAYS`] days before `now`. `Ok(Some(n))` is how many went; `Ok(None)` means
/// another replica holds the lease and this one did nothing.
pub async fn purge_tombstones_once(
    store: &SqlStore,
    holder: &str,
    now: OffsetDateTime,
) -> Result<Option<u64>, StoreError> {
    if !store.try_lease(PURGE_LEASE, holder, LEASE_TTL).await? {
        return Ok(None);
    }
    let before = now - time::Duration::days(TOMBSTONE_RETENTION_DAYS);
    let purged = ItemStore::purge_tombstones(store, before).await;
    // Given back at once, so a purge a day later never waits on this lease to lapse.
    if let Err(e) = store.release_lease(PURGE_LEASE, holder).await {
        tracing::warn!(error = %e, "couldn't release the purge lease");
    }
    purged.map(Some)
}

/// One run of the emergency-access timer, under its lease: approves every request whose wait has
/// ended and tells both parties. `Ok(Some(n))` is how many it approved.
pub async fn approve_due_once(
    store: &SqlStore,
    env: &ServerCrypto,
    holder: &str,
) -> Result<Option<u64>, JobError> {
    under_lease(
        store,
        APPROVE_DUE_LEASE,
        holder,
        SHORT_LEASE_TTL,
        || async {
            ApproveDue {
                users: store.clone(),
                grants: store.clone(),
                notices: LogNotices,
                env: env.clone(),
                events: store.clone(),
            }
            .execute()
            .await
        },
    )
    .await
}

/// One run of the device-approval purge, under its lease: removes requests that expired a day
/// ago. `Ok(Some(n))` is how many went.
pub async fn purge_approvals_once(
    store: &SqlStore,
    env: &ServerCrypto,
    holder: &str,
) -> Result<Option<u64>, JobError> {
    under_lease(
        store,
        PURGE_APPROVALS_LEASE,
        holder,
        SHORT_LEASE_TTL,
        || async {
            PurgeApprovals {
                approvals: store.clone(),
                env: env.clone(),
            }
            .execute()
            .await
        },
    )
    .await
}

/// One run of the verified-domain re-check, under its lease: looks again for the DNS record of every
/// domain proven `RECHECK_DOMAINS_AFTER` ago or longer, and takes the proof back where it is gone.
/// `Ok(Some(n))` is how many proofs were taken back.
pub async fn recheck_domains_once(
    store: &SqlStore,
    env: &ServerCrypto,
    dns: &Arc<kemlock_identity::DnsTxtResolver>,
    holder: &str,
) -> Result<Option<u64>, JobError> {
    under_lease(
        store,
        RECHECK_DOMAINS_LEASE,
        holder,
        SHORT_LEASE_TTL,
        || async {
            DomainProofs {
                repos: store.clone(),
                dns: Arc::clone(dns),
                env: env.clone(),
            }
            .recheck_stale(RECHECK_DOMAINS_AFTER)
            .await
            .map(|done| done.dropped)
        },
    )
    .await
}

/// One run of the orphaned-file purge, under its lease: removes the files no item names any more
/// and the uploads that never finished. `Ok(Some(n))` is how many went.
pub async fn purge_files_once(
    store: &SqlStore,
    files: &Files,
    holder: &str,
) -> Result<Option<u64>, JobError> {
    under_lease(store, PURGE_FILES_LEASE, holder, SHORT_LEASE_TTL, || {
        files.purge_once()
    })
    .await
}

/// Runs `job` every `every`, the first time `first_after` from now. A run that overshoots its
/// slot makes the next one late, never two at once.
fn spawn_every<F, Fut>(first_after: Duration, every: Duration, mut job: F) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(Instant::now() + first_after, every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            job().await;
        }
    })
}

/// Starts the daily purge. The task ends when the returned handle is aborted or dropped with the
/// runtime.
pub fn spawn_purge(store: SqlStore) -> JoinHandle<()> {
    let holder = holder_name();
    spawn_every(FIRST_PURGE_AFTER, PURGE_EVERY, move || {
        let store = store.clone();
        let holder = holder.clone();
        async move {
            match purge_tombstones_once(&store, &holder, OffsetDateTime::now_utc()).await {
                Ok(Some(purged)) => tracing::info!(purged, "purged old tombstones"),
                Ok(None) => tracing::debug!("another replica holds the tombstone purge lease"),
                Err(e) => tracing::warn!(error = %e, "the tombstone purge failed"),
            }
        }
    })
}

/// The running jobs.
#[derive(Debug)]
pub struct Jobs(Vec<JoinHandle<()>>);

impl Jobs {
    /// Stops every job.
    pub fn abort(&self) {
        for job in &self.0 {
            job.abort();
        }
    }
}

/// Logs the outcome of one run of a leased job that counts what it did.
fn report(job: &str, outcome: Result<Option<u64>, JobError>, did: &str) {
    match outcome {
        Ok(Some(0)) => {}
        Ok(Some(count)) => tracing::info!(count, "{did}"),
        Ok(None) => tracing::debug!("another replica holds the {job} lease"),
        Err(e) => tracing::warn!(error = %e, "the {job} job failed"),
    }
}

/// Starts every job: the tombstone purge, the emergency-access timer, the device-approval purge
/// and the orphaned-file purge. They stop with [`Jobs::abort`] or with the runtime.
pub fn spawn_all(store: &SqlStore, env: &ServerCrypto, files: Files) -> Jobs {
    let holder = holder_name();
    let files = Arc::new(files);
    let mut handles = vec![spawn_purge(store.clone())];

    let (s, e, h) = (store.clone(), env.clone(), holder.clone());
    handles.push(spawn_every(FIRST_RUN_AFTER, APPROVE_DUE_EVERY, move || {
        let (s, e, h) = (s.clone(), e.clone(), h.clone());
        async move {
            let outcome = approve_due_once(&s, &e, &h).await;
            report(
                "emergency timer",
                outcome,
                "approved due emergency requests",
            );
        }
    }));

    let (s, e, h) = (store.clone(), env.clone(), holder.clone());
    handles.push(spawn_every(
        FIRST_RUN_AFTER,
        PURGE_APPROVALS_EVERY,
        move || {
            let (s, e, h) = (s.clone(), e.clone(), h.clone());
            async move {
                let outcome = purge_approvals_once(&s, &e, &h).await;
                report("approval purge", outcome, "purged expired device approvals");
            }
        },
    ));

    let (s, e, h) = (store.clone(), env.clone(), holder.clone());
    let dns = Arc::new(kemlock_identity::DnsTxtResolver::new());
    handles.push(spawn_every(
        FIRST_RUN_AFTER,
        RECHECK_DOMAINS_EVERY,
        move || {
            let (s, e, h, d) = (s.clone(), e.clone(), h.clone(), Arc::clone(&dns));
            async move {
                let outcome = recheck_domains_once(&s, &e, &d, &h).await;
                report(
                    "domain re-check",
                    outcome,
                    "verified domains whose DNS record is gone are pending again",
                );
            }
        },
    ));

    let (s, f, h) = (store.clone(), files, holder);
    handles.push(spawn_every(FIRST_RUN_AFTER, PURGE_FILES_EVERY, move || {
        let (s, f, h) = (s.clone(), Arc::clone(&f), h.clone());
        async move {
            let outcome = purge_files_once(&s, &f, &h).await;
            report(
                "file purge",
                outcome,
                "removed files no item names any more",
            );
        }
    }));
    Jobs(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision, UserId};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-12-01 00:00:00 UTC);

    async fn store() -> SqlStore {
        SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects")
    }

    /// A revision of an item: live, or (with `deleted`) a tombstone.
    fn draft(
        id: ItemId,
        owner: Owner,
        revision: u64,
        deleted: Option<OffsetDateTime>,
        at: OffsetDateTime,
    ) -> ItemDraft {
        ItemDraft {
            id,
            owner,
            kind: ItemKind::try_from("login".to_owned()).expect("a valid kind"),
            format: ItemFormat::Kem1,
            expected: revision.checked_sub(1).filter(|r| *r > 0).map(Revision),
            revision: Revision(revision),
            key_version: 1,
            ciphertext: deleted.is_none().then(|| vec![1; 40]),
            item_key: deleted.is_none().then(|| vec![2; 60]),
            deleted_at: deleted,
            updated_at: at,
            signature: None,
        }
    }

    /// Stores an item, then deletes it at `deleted_at`.
    async fn deleted_at(store: &SqlStore, owner: Owner, deleted_at: OffsetDateTime) -> ItemId {
        let id = ItemId::random();
        let put = draft(id, owner, 1, None, deleted_at);
        ItemStore::put(store, put).await.expect("put");
        let delete = draft(id, owner, 2, Some(deleted_at), deleted_at);
        ItemStore::put(store, delete).await.expect("delete");
        id
    }

    async fn stored(store: &SqlStore, id: ItemId) -> bool {
        ItemStore::get(store, id).await.expect("get").is_some()
    }

    #[tokio::test]
    async fn the_purge_removes_tombstones_older_than_the_retention_only() {
        let store = store().await;
        let owner = Owner::User(UserId::random());
        let old = deleted_at(&store, owner, NOW - time::Duration::days(200)).await;
        let recent = deleted_at(&store, owner, NOW - time::Duration::days(10)).await;
        let edge = deleted_at(&store, owner, NOW - time::Duration::days(179)).await;

        let purged = purge_tombstones_once(&store, "me", NOW)
            .await
            .expect("the purge runs");
        assert_eq!(purged, Some(1));
        assert!(!stored(&store, old).await);
        assert!(stored(&store, recent).await);
        assert!(stored(&store, edge).await);
        // Its change is behind the owner's horizon: a device that hasn't synced since must
        // start over.
        let horizon = ItemStore::purged_through(&store, &[owner])
            .await
            .expect("horizon");
        assert!(!horizon.is_empty());
    }

    #[tokio::test]
    async fn only_the_replica_holding_the_lease_purges() {
        let store = store().await;
        let owner = Owner::User(UserId::random());
        let old = deleted_at(&store, owner, NOW - time::Duration::days(300)).await;

        // Another replica is purging right now.
        assert_eq!(
            store.try_lease(PURGE_LEASE, "other", LEASE_TTL).await,
            Ok(true)
        );
        assert_eq!(purge_tombstones_once(&store, "me", NOW).await, Ok(None));
        assert!(stored(&store, old).await, "nothing was purged");

        // When it is done, the next run goes ahead, and gives the lease back.
        store
            .release_lease(PURGE_LEASE, "other")
            .await
            .expect("release");
        assert_eq!(purge_tombstones_once(&store, "me", NOW).await, Ok(Some(1)));
        assert!(!stored(&store, old).await);
        assert_eq!(
            store.try_lease(PURGE_LEASE, "other", LEASE_TTL).await,
            Ok(true),
            "the lease was released after the run"
        );
    }

    #[test]
    fn holder_names_differ_and_fit_the_lease_column() {
        let a = holder_name();
        assert_eq!(a.len(), 32);
        assert_ne!(a, holder_name());
    }

    fn crypto() -> ServerCrypto {
        ServerCrypto::new(
            kemlock_crypto::seal::ServerSeal::new(&[7u8; 32]),
            kemlock_crypto::opaque::OpaqueServer::generate(),
        )
    }

    #[tokio::test]
    async fn the_emergency_timer_runs_under_its_lease() {
        let store = store().await;
        let env = crypto();

        // Nothing is due, and the run says so.
        assert_eq!(
            approve_due_once(&store, &env, "me").await.expect("runs"),
            Some(0)
        );
        // The lease was given back, so another run goes ahead.
        assert_eq!(
            approve_due_once(&store, &env, "me").await.expect("runs"),
            Some(0)
        );

        // Another replica holds it: this one does nothing.
        assert_eq!(
            store
                .try_lease(APPROVE_DUE_LEASE, "other", SHORT_LEASE_TTL)
                .await,
            Ok(true)
        );
        assert_eq!(
            approve_due_once(&store, &env, "me").await.expect("runs"),
            None
        );
    }

    #[tokio::test]
    async fn the_approval_purge_runs_under_its_own_lease() {
        let store = store().await;
        let env = crypto();
        assert_eq!(
            purge_approvals_once(&store, &env, "me")
                .await
                .expect("runs"),
            Some(0)
        );
        // The emergency timer's lease is another one: it doesn't hold this job up.
        assert_eq!(
            store
                .try_lease(APPROVE_DUE_LEASE, "other", SHORT_LEASE_TTL)
                .await,
            Ok(true)
        );
        assert_eq!(
            purge_approvals_once(&store, &env, "me")
                .await
                .expect("runs"),
            Some(0)
        );
        assert_eq!(
            store
                .try_lease(PURGE_APPROVALS_LEASE, "other", SHORT_LEASE_TTL)
                .await,
            Ok(true)
        );
        assert_eq!(
            purge_approvals_once(&store, &env, "me")
                .await
                .expect("runs"),
            None
        );
    }

    #[tokio::test]
    async fn a_leased_job_gives_the_lease_back_even_when_it_fails() {
        let store = store().await;
        let failed: Result<Option<u64>, JobError> =
            under_lease(&store, "some-job", "me", SHORT_LEASE_TTL, || async {
                Err::<u64, _>("it broke")
            })
            .await;
        assert!(matches!(failed, Err(JobError::Run(message)) if message == "it broke"));
        assert_eq!(
            store.try_lease("some-job", "other", SHORT_LEASE_TTL).await,
            Ok(true),
            "the lease was released after the failure"
        );
    }

    #[test]
    fn every_job_has_a_lease_of_its_own() {
        let leases = [
            PURGE_LEASE,
            APPROVE_DUE_LEASE,
            PURGE_APPROVALS_LEASE,
            PURGE_FILES_LEASE,
            RECHECK_DOMAINS_LEASE,
        ];
        let distinct: std::collections::BTreeSet<_> = leases.iter().collect();
        assert_eq!(distinct.len(), leases.len());
        assert_eq!(APPROVE_DUE_EVERY, Duration::from_secs(3600));
        assert_eq!(PURGE_APPROVALS_EVERY, Duration::from_secs(300));
    }
}
