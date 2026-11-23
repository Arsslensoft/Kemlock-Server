//! Delete file: removes one attachment and its bytes. The client also writes the item without
//! the attachment's id, which is what devices learn the removal from.

use super::ports::{AttachmentRepo, BlobError, BlobStore};
use super::{FileError, own_attachment};
use crate::authenticate::Actor;
use crate::ports::{Clock, Event, EventLog};
use kemlock_domain::{AttachmentId, ItemId};

#[derive(Debug)]
pub struct DeleteFile<A, B, V, C> {
    pub attachments: A,
    pub blobs: B,
    pub events: V,
    pub clock: C,
}

impl<A: AttachmentRepo, B: BlobStore, V: EventLog, C: Clock> DeleteFile<A, B, V, C> {
    /// Deletes the bytes, then the row, so a failure in between leaves a row that a second
    /// delete finishes, never bytes nothing points to.
    pub async fn execute(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
    ) -> Result<(), FileError> {
        let attachment = own_attachment(&self.attachments, actor, item, file).await?;
        match self.blobs.delete(attachment.blob).await {
            Ok(()) | Err(BlobError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        self.attachments.remove(file).await?;
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action: "attachment.delete",
            target: Some(file.to_string()),
            at: self.clock.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record an attachment event");
        }
        Ok(())
    }
}
