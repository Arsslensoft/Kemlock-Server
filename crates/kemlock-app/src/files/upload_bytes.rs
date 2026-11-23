//! Upload bytes: the second step. Streams the request body into blob storage, never holding more
//! than a chunk or two, and makes the attachment ready when exactly the announced number of bytes
//! arrived and storage accepted them as a `KMA1` file.

use super::ports::{AttachmentRepo, BlobStore, BlobUpload, BodySource};
use super::{FileError, FilesConfig, own_attachment};
use crate::authenticate::Actor;
use crate::ports::{Clock, Event, EventLog};
use crate::quota::check;
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, ItemId, Owner};

#[derive(Debug)]
pub struct UploadBytes<A, B, V, C> {
    pub attachments: A,
    pub blobs: B,
    pub events: V,
    pub clock: C,
    pub config: FilesConfig,
}

impl<A: AttachmentRepo, B: BlobStore, V: EventLog, C: Clock> UploadBytes<A, B, V, C> {
    /// Stores `body` as the bytes of attachment `file` of `item`. `length` is the request's
    /// `Content-Length`, which must be the size announced at the start; a body that turns out
    /// longer or shorter is refused, and so is bytes that don't start like a `KMA1` file. A
    /// refused or broken upload leaves the attachment pending, so the client may send it again.
    pub async fn execute<S: BodySource>(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
        length: u64,
        body: &mut S,
    ) -> Result<Attachment, FileError> {
        let mut attachment = own_attachment(&self.attachments, actor, item, file).await?;
        if attachment.is_ready() {
            return Err(FileError::AlreadyUploaded);
        }
        // The limit may have been lowered since the upload started.
        self.config.limits.check(attachment.size)?;
        // So may the owner's quota. What the owner stores counts this file already, announced, so
        // it is left out of the sum it is checked against.
        let limit = match attachment.owner {
            Owner::User(_) => self.config.user_quota,
            Owner::Space(_) => self.config.space_quota,
        };
        if limit.is_some() {
            let used = self.attachments.attachment_bytes(attachment.owner).await?;
            check(limit, used.saturating_sub(attachment.size), attachment.size)
                .map_err(FileError::Quota)?;
        }
        if length != attachment.size {
            return Err(FileError::LengthMismatch);
        }

        let mut upload = self.blobs.begin(attachment.blob, attachment.size).await?;
        let mut received: u64 = 0;
        loop {
            match body.next_chunk().await {
                Ok(Some(chunk)) => {
                    received = received.saturating_add(chunk.len() as u64);
                    if received > attachment.size {
                        upload.abort().await;
                        return Err(FileError::LengthMismatch);
                    }
                    if let Err(e) = upload.write(chunk).await {
                        upload.abort().await;
                        return Err(e.into());
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    upload.abort().await;
                    return Err(FileError::Interrupted);
                }
            }
        }
        if received != attachment.size {
            upload.abort().await;
            return Err(FileError::LengthMismatch);
        }
        upload.finish().await?;

        if !self.attachments.mark_ready(file).await? {
            // Another upload of this file finished first; its bytes stand.
            return Err(FileError::AlreadyUploaded);
        }
        attachment.status = AttachmentStatus::Ready;

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
        Ok(attachment)
    }
}
