//! The owner's view of their Sends: list, read one, delete one.
//!
//! Deleting is allowed even where a policy forbids making Sends ("you may only delete an existing
//! Send").

use super::ports::{SendBlobs, SendRepo};
use super::{SendsError, own_send, record};
use crate::authenticate::Actor;
use crate::files::BlobError;
use crate::ports::{Clock, EventLog};
use kemlock_domain::sends::{SendId, SendRecord};

#[derive(Debug)]
pub struct ListSends<S> {
    pub sends: S,
}

impl<S: SendRepo> ListSends<S> {
    /// The account's Sends, newest first, deleted-by-date ones included until the job removes them
    /// (they are closed, and the owner may still see that they were).
    pub async fn execute(&self, actor: &Actor) -> Result<Vec<SendRecord>, SendsError> {
        Ok(self.sends.sends_of(actor.user).await?)
    }
}

#[derive(Debug)]
pub struct GetSend<S> {
    pub sends: S,
}

impl<S: SendRepo> GetSend<S> {
    pub async fn execute(&self, actor: &Actor, id: SendId) -> Result<SendRecord, SendsError> {
        own_send(&self.sends, actor, id).await
    }
}

#[derive(Debug)]
pub struct DeleteSend<S, B, V, C> {
    pub sends: S,
    pub blobs: B,
    pub events: V,
    pub clock: C,
}

impl<S: SendRepo, B: SendBlobs, V: EventLog, C: Clock> DeleteSend<S, B, V, C> {
    /// Deletes the Send and, for a file Send, its bytes (bytes first, so a blob that can't be
    /// deleted leaves the row for a retry).
    pub async fn execute(&self, actor: &Actor, id: SendId) -> Result<(), SendsError> {
        let send = own_send(&self.sends, actor, id).await?;
        if let Some(file) = send.file {
            match self.blobs.delete(file.blob).await {
                Ok(()) | Err(BlobError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.sends.remove_send(id).await?;
        record(&self.events, actor, "send.delete", id, self.clock.now()).await;
        Ok(())
    }
}
