//! Purge orphans: removes the attachments no item names any more. When the tombstone purge
//! deletes an item's row, its attachments are left without an item; an upload that never finished
//! is left pending. Both go after the grace period, bytes first.

use super::ports::{AttachmentRepo, BlobError, BlobStore};
use super::{FileError, FilesConfig};
use crate::ports::Clock;

/// How many attachments one round of the purge reads.
const BATCH: u32 = 100;

#[derive(Debug)]
pub struct PurgeOrphans<A, B, C> {
    pub attachments: A,
    pub blobs: B,
    pub clock: C,
    pub config: FilesConfig,
}

impl<A: AttachmentRepo, B: BlobStore, C: Clock> PurgeOrphans<A, B, C> {
    /// Removes every orphan older than the grace period. Returns how many went. A blob that
    /// can't be deleted stops the run with the error, leaving its row for the next one.
    pub async fn execute(&self) -> Result<u64, FileError> {
        let before = self.clock.now() - self.config.orphan_grace;
        let mut purged = 0u64;
        loop {
            let orphans = self.attachments.orphans(before, BATCH).await?;
            let batch = orphans.len();
            for orphan in orphans {
                match self.blobs.delete(orphan.blob).await {
                    Ok(()) | Err(BlobError::NotFound) => {}
                    Err(e) => return Err(e.into()),
                }
                self.attachments.remove(orphan.id).await?;
                purged += 1;
            }
            if batch < BATCH as usize {
                return Ok(purged);
            }
        }
    }
}
