//! Start upload: the first step of attaching a file. Checks the actor may write the item and the
//! size is within the limit, and records a pending attachment with a random blob id. With
//! pre-signed URLs on, the answer also carries a bucket URL to `PUT` the bytes to.

use super::ports::{AttachmentRepo, BlobStore, PresignedUrl};
use super::{FileError, FilesConfig, item_owner};
use crate::authenticate::Actor;
use crate::ports::{Clock, ItemStore};
use crate::quota::check;
use kemlock_domain::{Attachment, ItemId, Owner};

#[derive(Debug)]
pub struct StartUpload<I, A, B, C> {
    pub items: I,
    pub attachments: A,
    pub blobs: B,
    pub clock: C,
    pub config: FilesConfig,
}

/// A started upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    /// The pending attachment: its id goes into the item's JSON.
    pub attachment: Attachment,
    /// Where to `PUT` the bytes straight to the bucket, when pre-signed URLs are on. Otherwise
    /// the bytes go to the server's own `PUT` route.
    pub upload: Option<PresignedUrl>,
}

impl<I: ItemStore, A: AttachmentRepo, B: BlobStore, C: Clock> StartUpload<I, A, B, C> {
    /// `size` is the length of the `KMA1` file the client will send, which the upload must then
    /// match exactly.
    pub async fn execute(
        &self,
        actor: &Actor,
        item: ItemId,
        size: u64,
    ) -> Result<Started, FileError> {
        let owner = item_owner(&self.items, actor, item).await?;
        // The owner's quota first: a full or switched-off quota is told as such, whatever the file.
        let limit = match owner {
            Owner::User(_) => self.config.user_quota,
            Owner::Space(_) => self.config.space_quota,
        };
        if limit.is_some() {
            let used = self.attachments.attachment_bytes(owner).await?;
            check(limit, used, size).map_err(FileError::Quota)?;
        }
        let attachment = Attachment::start(
            item,
            owner,
            actor.user,
            size,
            self.config.limits,
            self.clock.now(),
        )?;
        // The check above refuses early, for the message. This one is the one that holds: the sum
        // and the insert are one step, so announces that arrive together can't all pass it.
        self.attachments
            .add_within_quota(&attachment, limit)
            .await?
            .map_err(FileError::Quota)?;
        // The URL names the file's exact length, so a `PUT` to it can be no larger than announced.
        let upload = self
            .blobs
            .presigned_upload_sized(attachment.blob, size)
            .await?;
        Ok(Started { attachment, upload })
    }
}
