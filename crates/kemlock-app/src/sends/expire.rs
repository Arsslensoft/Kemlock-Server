//! The job that deletes Sends whose date has come, bytes included. It also removes file Sends
//! whose bytes never arrived after a day, so an abandoned upload leaves nothing behind.

use super::ports::{SendBlobs, SendRepo};
use super::{SendsConfig, SendsError};
use crate::files::BlobError;
use crate::ports::Clock;

/// How many Sends one round of the job reads.
const BATCH: u32 = 100;

#[derive(Debug)]
pub struct PurgeSends<S, B, C> {
    pub sends: S,
    pub blobs: B,
    pub clock: C,
    pub config: SendsConfig,
}

impl<S: SendRepo, B: SendBlobs, C: Clock> PurgeSends<S, B, C> {
    /// Removes every Send past its deletion date, and every file Send that was abandoned. Returns
    /// how many went. A blob that can't be deleted stops the run with the error, leaving its row
    /// for the next one.
    pub async fn execute(&self) -> Result<u64, SendsError> {
        let now = self.clock.now();
        let abandoned_before = now - self.config.abandoned_after;
        let mut purged = 0u64;
        loop {
            let due = self
                .sends
                .sends_to_delete(now, abandoned_before, BATCH)
                .await?;
            let batch = due.len();
            for send in due {
                if let Some(file) = send.file {
                    match self.blobs.delete(file.blob).await {
                        Ok(()) | Err(BlobError::NotFound) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                self.sends.remove_send(send.id).await?;
                purged += 1;
            }
            if batch < BATCH as usize {
                return Ok(purged);
            }
        }
    }
}
