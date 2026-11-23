//! Finish upload: settles a file the client sent straight to the bucket through a pre-signed URL.
//! The server never saw those bytes, so it looks at what arrived: the blob must be the announced
//! size and start like a `KMA1` file. A blob that isn't is deleted. A file uploaded through the
//! server is ready already, and finishing it again changes nothing.

use super::ports::{AttachmentRepo, BlobError, BlobStore};
use super::{FileError, own_attachment};
use crate::authenticate::Actor;
use crate::ports::{Clock, Event, EventLog};
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, ItemId};

#[derive(Debug)]
pub struct FinishUpload<A, B, V, C> {
    pub attachments: A,
    pub blobs: B,
    pub events: V,
    pub clock: C,
}

impl<A: AttachmentRepo, B: BlobStore, V: EventLog, C: Clock> FinishUpload<A, B, V, C> {
    pub async fn execute(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
    ) -> Result<Attachment, FileError> {
        let mut attachment = own_attachment(&self.attachments, actor, item, file).await?;
        if attachment.is_ready() {
            return Ok(attachment);
        }
        match self.blobs.verify(attachment.blob, attachment.size).await {
            Ok(()) => {}
            Err(BlobError::NotFound) => {
                return Err(FileError::Invalid("the file hasn't been uploaded"));
            }
            Err(e @ (BlobError::WrongSize | BlobError::NotKma1(_) | BlobError::TooLarge)) => {
                // Bytes that can't be the file: don't keep them. The client may upload again.
                if let Err(delete) = self.blobs.delete(attachment.blob).await {
                    tracing::warn!(error = %delete, "couldn't delete a refused blob");
                }
                return Err(e.into());
            }
            Err(e) => return Err(e.into()),
        }
        if self.attachments.mark_ready(file).await? {
            let event = Event {
                actor: Some(actor.user),
                device: Some(actor.device),
                action: "attachment.upload",
                target: Some(file.to_string()),
                at: self.clock.now(),
            };
            if let Err(e) = self.events.record(event).await {
                tracing::warn!(error = %e, "couldn't record an attachment event");
            }
        }
        attachment.status = AttachmentStatus::Ready;
        Ok(attachment)
    }
}
