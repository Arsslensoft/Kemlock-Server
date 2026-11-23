//! Upload the bytes of a file Send. The body streams into blob storage chunk by chunk, never held
//! whole, and the Send opens only when exactly the announced number of bytes has arrived.

use super::ports::{SendBlobs, SendRepo, file_send_bytes};
use super::{SendsConfig, SendsError, own_send, record};
use crate::authenticate::Actor;
use crate::files::{BlobUpload, BodySource};
use crate::ports::{Clock, EventLog};
use crate::quota::check;
use kemlock_domain::sends::{SendFile, SendFileFormat, SendId, SendRecord};

#[derive(Debug)]
pub struct UploadSendFile<S, B, V, C> {
    pub sends: S,
    pub blobs: B,
    pub events: V,
    pub clock: C,
    pub config: SendsConfig,
}

impl<S: SendRepo, B: SendBlobs, V: EventLog, C: Clock> UploadSendFile<S, B, V, C> {
    /// Stores `body` as the file of Send `id`. `length` is the request's `Content-Length`, which
    /// must be the size announced when the Send was made; a body that turns out longer or shorter
    /// is refused, and so are bytes that don't start like a `KMA1` file when the Send says its
    /// file is one. A refused or broken upload leaves the Send waiting, so the client may send it
    /// again.
    pub async fn execute<R: BodySource>(
        &self,
        actor: &Actor,
        id: SendId,
        length: u64,
        body: &mut R,
    ) -> Result<SendRecord, SendsError> {
        let mut send = own_send(&self.sends, actor, id).await?;
        let Some(file) = send.file else {
            return Err(SendsError::Invalid("a note has no file"));
        };
        if file.ready {
            return Err(SendsError::AlreadyUploaded);
        }
        // The limit may have been lowered since the Send was made.
        if file.size > self.config.limits.max_file_size {
            return Err(SendsError::TooLarge);
        }
        // And the quota, which may have been lowered too. The account's file Sends count this one
        // already, as announced, so it is left out of the sum it is checked against.
        if self.config.quota.is_some() {
            let used = file_send_bytes(&self.sends.sends_of(actor.user).await?);
            check(self.config.quota, used.saturating_sub(file.size), file.size)
                .map_err(SendsError::Quota)?;
        }
        if length != file.size {
            return Err(SendsError::LengthMismatch);
        }

        let mut upload = match file.format {
            SendFileFormat::Kma1 => self.blobs.begin(file.blob, file.size).await?,
            SendFileFormat::Opaque => self.blobs.begin_raw(file.blob, file.size).await?,
        };
        let mut received: u64 = 0;
        loop {
            match body.next_chunk().await {
                Ok(Some(chunk)) => {
                    received = received.saturating_add(chunk.len() as u64);
                    if received > file.size {
                        upload.abort().await;
                        return Err(SendsError::LengthMismatch);
                    }
                    if let Err(e) = upload.write(chunk).await {
                        upload.abort().await;
                        return Err(e.into());
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    upload.abort().await;
                    return Err(SendsError::Interrupted);
                }
            }
        }
        if received != file.size {
            upload.abort().await;
            return Err(SendsError::LengthMismatch);
        }
        upload.finish().await?;

        if !self.sends.mark_send_file_ready(id).await? {
            // Another upload of this file finished first; its bytes stand.
            return Err(SendsError::AlreadyUploaded);
        }
        send.file = Some(SendFile {
            ready: true,
            ..file
        });
        record(&self.events, actor, "send.upload", id, self.clock.now()).await;
        Ok(send)
    }
}
