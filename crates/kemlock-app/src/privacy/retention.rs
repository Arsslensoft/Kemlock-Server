//! The retention job: deletes what has outlived its retention period (design, "Privacy and
//! compliance", retention table). It runs daily on one replica at a time.
//!
//! - the event log after `event_log_days`, the sign-in log after `sign_in_log_days`;
//! - full addresses after `full_ip_days` (at once when full addresses are off);
//! - tombstones after 180 days, device approvals once they have expired for a day;
//! - the trash of Bitwarden-API items after `trash_days`, with their files (see below);
//! - the email log after `email_log_days`.
//!
//! **Trash is purged for Bitwarden-API items only.** A Bitwarden cipher is stored as the JSON the
//! Bitwarden API serves, with its `deletedDate` in the clear, so the server can age it out. A
//! Kemlock item keeps its trash flag and date inside the ciphertext (`ItemFormat::Kem1`), which
//! only the account's devices can open: the server sees a live item and cannot tell that it is in
//! the trash. So `trash_days` never touches a Kemlock item; the Kemlock apps empty their own
//! trash on their own schedule, by an ordinary delete that leaves a tombstone like any other. The
//! rule is stated to clients in the processing summary and in `docs/self-hosting.md`.
//!
//! **Tombstones of erased accounts** are not left to the 180-day purge: erasing an account deletes
//! every row of its vault, tombstones included, with its sync horizon, in the same transaction
//! (`AccountEraser::erase_user`), so nothing of it waits for this job.
//!
//! Backups age out in the backup job, which owns the archives, and accounts waiting out their
//! grace period are erased by [`EraseAccount::erase_due`](super::EraseAccount::erase_due).

use super::ports::{ErasureFiles, PrivacySettings, RetentionStore};
use crate::devices::ApprovalRepo;
use crate::error::AppError;
use crate::ports::{Clock, ItemStore};
use kemlock_domain::privacy::Retention;
use time::Duration;

/// What one run removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub events: u64,
    pub sign_ins: u64,
    pub full_ips_dropped: u64,
    pub tombstones: u64,
    pub approvals: u64,
    pub trashed_items: u64,
    pub files_deleted: u64,
    pub files_failed: u64,
    pub email_log: u64,
}

#[derive(Debug)]
pub struct RunRetention<S, R, I, A, F, C> {
    pub settings: S,
    pub store: R,
    pub items: I,
    pub approvals: A,
    pub files: F,
    pub clock: C,
}

impl<S, R, I, A, F, C> RunRetention<S, R, I, A, F, C>
where
    S: PrivacySettings,
    R: RetentionStore,
    I: ItemStore,
    A: ApprovalRepo,
    F: ErasureFiles,
    C: Clock,
{
    /// One pass with the saved retention settings. A step that fails stops the pass with its
    /// error; what ran before it stays done, and the next run starts over.
    pub async fn execute(&self) -> Result<RetentionReport, AppError> {
        let retention = self.settings.retention().await?;
        self.execute_with(&retention).await
    }

    /// One pass with `retention`.
    pub async fn execute_with(&self, retention: &Retention) -> Result<RetentionReport, AppError> {
        let now = self.clock.now();
        let mut report = RetentionReport {
            events: self.store.purge_events(retention.event_cutoff(now)).await?,
            sign_ins: self
                .store
                .purge_sign_ins(retention.sign_in_cutoff(now))
                .await?,
            ..RetentionReport::default()
        };

        // With full addresses off, none may remain from when they were on.
        let full_before = if retention.keeps_full_ips() {
            retention.full_ip_cutoff(now)
        } else {
            now
        };
        report.full_ips_dropped = self.store.drop_full_ips(full_before).await?;

        report.tombstones = self
            .items
            .purge_tombstones(Retention::tombstone_cutoff(now))
            .await?;
        report.approvals = self
            .approvals
            .purge_requests(now - Duration::days(1))
            .await?;

        let trashed = self
            .store
            .purge_trash(retention.trash_cutoff(now), now)
            .await?;
        report.trashed_items = trashed.len() as u64;
        for purged in &trashed {
            for blob in &purged.blobs {
                match self.files.delete_blob(*blob).await {
                    Ok(()) => report.files_deleted += 1,
                    Err(e) => {
                        report.files_failed += 1;
                        tracing::warn!(error = %e, "couldn't delete a file of a purged item");
                    }
                }
            }
            for key in &purged.cipher_files {
                match self.files.delete_cipher_file(key).await {
                    Ok(()) => report.files_deleted += 1,
                    Err(e) => {
                        report.files_failed += 1;
                        tracing::warn!(error = %e, "couldn't delete a file of a purged item");
                    }
                }
            }
        }

        report.email_log = self
            .store
            .purge_email_log(retention.email_log_cutoff(now))
            .await?;
        Ok(report)
    }
}
