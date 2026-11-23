//! Download: the bytes of a ready attachment, streamed from blob storage, or a short-lived
//! bucket URL when pre-signed URLs are on and the client asked for one.

use super::ports::{AttachmentRepo, BlobRead, BlobStore, PresignedUrl};
use super::{FileError, own_attachment};
use crate::authenticate::Actor;
use crate::ports::ItemStore;
use kemlock_domain::{Attachment, AttachmentId, ItemId};

#[derive(Debug)]
pub struct Download<I, A, B> {
    pub items: I,
    pub attachments: A,
    pub blobs: B,
}

/// An attachment and its bytes.
#[derive(Debug)]
pub struct Downloaded {
    pub attachment: Attachment,
    pub read: BlobRead,
}

impl<I: ItemStore, A: AttachmentRepo, B: BlobStore> Download<I, A, B> {
    /// A ready attachment of the actor's, whose item (when it exists) is not deleted.
    async fn ready(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
    ) -> Result<Attachment, FileError> {
        let attachment = own_attachment(&self.attachments, actor, item, file).await?;
        if !attachment.is_ready() {
            return Err(FileError::NotFound);
        }
        if self
            .items
            .get(item)
            .await?
            .is_some_and(|stored| stored.is_tombstone())
        {
            return Err(FileError::NotFound);
        }
        Ok(attachment)
    }

    /// Opens the file's bytes. A blob missing from storage is `NotFound` too.
    pub async fn open(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
    ) -> Result<Downloaded, FileError> {
        let attachment = self.ready(actor, item, file).await?;
        let read = self.blobs.open(attachment.blob).await.map_err(|e| {
            tracing::warn!(error = %e, attachment = %file, "a ready attachment's blob can't be read");
            FileError::from(e)
        })?;
        Ok(Downloaded { attachment, read })
    }

    /// A URL to fetch the file from the bucket, or `None` when pre-signed URLs are off, so the
    /// caller streams it with [`open`](Self::open) instead.
    pub async fn link(
        &self,
        actor: &Actor,
        item: ItemId,
        file: AttachmentId,
    ) -> Result<Option<PresignedUrl>, FileError> {
        let attachment = self.ready(actor, item, file).await?;
        Ok(self.blobs.presigned_download(attachment.blob).await?)
    }
}
