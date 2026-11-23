//! Erasing an account's Sends: the [`SendEraser`] of the privacy use case, over the real Sends
//! store. Every Send the account made goes with its file, so an erased account leaves no Send
//! behind for a link to open.

use super::ports::SendRepo;
use crate::files::{BlobError, BlobStore};
use crate::ports::StoreError;
use crate::privacy::SendEraser;
use kemlock_domain::UserId;

/// Deletes the Sends of an account and the bytes of its file Sends.
#[derive(Clone, Debug)]
pub struct EraseSends<S, B> {
    pub sends: S,
    pub blobs: B,
}

impl<S: SendRepo, B: BlobStore> SendEraser for EraseSends<S, B> {
    /// Bytes go before the row, so a file that can't be deleted leaves its row (and the
    /// account) for the retention job's next run: the erasure stops with the error, and what
    /// was removed stays removed. A file already gone is not an error. Returns how many Sends
    /// were deleted.
    async fn erase_sends(&self, user: UserId) -> Result<u64, StoreError> {
        let mut erased = 0u64;
        for send in self.sends.sends_of(user).await? {
            if let Some(file) = send.file {
                match self.blobs.delete(file.blob).await {
                    Ok(()) | Err(BlobError::NotFound) => {}
                    Err(e) => return Err(StoreError::Backend(e.to_string())),
                }
            }
            self.sends.remove_send(send.id).await?;
            erased += 1;
        }
        Ok(erased)
    }
}
