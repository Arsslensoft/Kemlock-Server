//! Open a Send by its access id: the public side, with no account.
//!
//! What comes back is ciphertext the recipient opens with the key in their link, plus the dates
//! and, unless the sender hid it, the sender's email. A Send that is switched off, expired, deleted,
//! out of views or still waiting for its file is `NotFound`, whatever the password, so a recipient
//! learns only that it is not there. A wrong password and a missing one are told apart, because a
//! recipient needs to know to ask for one. The API counts wrong tries (10 a minute per Send).

use super::ports::{SendBlobs, SendRepo};
use super::{SendsError, parse_access_id, proof_matches};
use crate::files::BlobRead;
use crate::platform::Platform;
use crate::ports::UserRepo;
use kemlock_domain::UserId;
use kemlock_domain::sends::{SendId, SendKind, SendRecord};
use time::OffsetDateTime;

#[derive(Debug)]
pub struct AccessSend<S, U, B, E> {
    pub sends: S,
    pub users: U,
    pub blobs: B,
    pub env: E,
}

/// What a recipient gets for opening a Send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accessed {
    pub id: SendId,
    pub kind: SendKind,
    /// The note, or a file's name and size, as the owner's client sealed it under the Send's key.
    pub payload: Vec<u8>,
    /// The size of a file Send's bytes, which [`AccessSend::download`] streams.
    pub file_size: Option<u64>,
    pub expires_at: Option<OffsetDateTime>,
    pub deletion_at: OffsetDateTime,
    /// The sender's email, unless they hid it.
    pub sender_email: Option<String>,
}

/// A file Send's bytes, streaming.
#[derive(Debug)]
pub struct SendDownload {
    pub id: SendId,
    pub read: BlobRead,
}

impl<S: SendRepo, U: UserRepo, B: SendBlobs, E: Platform> AccessSend<S, U, B, E> {
    /// Whether the Send's owner may have Sends open: an account an admin disabled, or one that
    /// waits out its erasure, has none (they open again if the account does).
    async fn owner_is_active(&self, owner: UserId) -> Result<bool, SendsError> {
        Ok(!self.users.account_disabled(owner).await?
            && self.users.erasure_pending(owner).await?.is_none())
    }

    /// The Send behind `access_id` if it is open, with its password checked.
    async fn open(&self, access_id: &str, proof: Option<&[u8]>) -> Result<SendRecord, SendsError> {
        let id = parse_access_id(access_id).ok_or(SendsError::NotFound)?;
        let send = self
            .sends
            .send_by_id(id)
            .await?
            .filter(|send| send.is_open(self.env.now()))
            .ok_or(SendsError::NotFound)?;
        if !self.owner_is_active(send.owner).await? {
            return Err(SendsError::NotFound);
        }
        if let Some(password) = &send.password {
            match proof {
                None => return Err(SendsError::PasswordRequired),
                Some(proof) if proof_matches(&self.env, password, proof) => {}
                Some(_) => return Err(SendsError::WrongPassword),
            }
        }
        Ok(send)
    }

    /// Whether the Send behind `access_id` wants a password, without opening it. A closed or
    /// unknown Send is `NotFound`.
    pub async fn needs_password(&self, access_id: &str) -> Result<bool, SendsError> {
        let id = parse_access_id(access_id).ok_or(SendsError::NotFound)?;
        let send = self
            .sends
            .send_by_id(id)
            .await?
            .filter(|send| send.is_open(self.env.now()))
            .ok_or(SendsError::NotFound)?;
        if !self.owner_is_active(send.owner).await? {
            return Err(SendsError::NotFound);
        }
        Ok(send.has_password())
    }

    /// Opens a Send. A note counts a view; a file Send's description doesn't (the download does).
    pub async fn execute(
        &self,
        access_id: &str,
        proof: Option<&[u8]>,
    ) -> Result<Accessed, SendsError> {
        let send = self.open(access_id, proof).await?;
        if send.kind == SendKind::Text
            && !self.sends.count_send_view(send.id, self.env.now()).await?
        {
            // Someone else took the last view between the check and the count.
            return Err(SendsError::NotFound);
        }
        let sender_email = if send.hide_email {
            None
        } else {
            self.users
                .by_id(send.owner)
                .await?
                .map(|owner| owner.email.as_str().to_owned())
        };
        Ok(Accessed {
            id: send.id,
            kind: send.kind,
            payload: send.payload,
            file_size: send.file.map(|f| f.size),
            expires_at: send.expires_at,
            deletion_at: send.deletion_at,
            sender_email,
        })
    }

    /// Streams a file Send's bytes and counts a view. A note has no file.
    pub async fn download(
        &self,
        access_id: &str,
        proof: Option<&[u8]>,
    ) -> Result<SendDownload, SendsError> {
        let send = self.open(access_id, proof).await?;
        let Some(file) = send.file else {
            return Err(SendsError::NotFound);
        };
        if !self.sends.count_send_view(send.id, self.env.now()).await? {
            return Err(SendsError::NotFound);
        }
        let read = self.blobs.open(file.blob).await.map_err(|e| {
            tracing::warn!(error = %e, send = %send.id, "a ready Send's blob can't be read");
            SendsError::from(e)
        })?;
        Ok(SendDownload { id: send.id, read })
    }
}
