//! Erasure reaches federated peers. When a home erases a vault (a person deleted their account, or
//! a space went with its last owner) the replicas hold a copy that must go too, or the person's
//! data outlives their request.
//!
//! - **The home** queues the erasure for each replica of the vault when it deletes the vault (its
//!   store does that in the same transaction, because the vault's federation settings are deleted
//!   with it: [`ErasureOutbox`](crate::extra::ErasureOutbox)). The replication job tells a peer in
//!   its next session ([`Replica::forward_erasures`]) and completes the erasure when the peer
//!   acknowledges; a peer that is down or refuses keeps its erasure queued for the next session.
//! - **The replica** deletes its copy on [`Request::Erase`] ([`Replica::receive_erasure`]): the
//!   items and every version of them, the change log, attachment rows and their files, home
//!   records, the offer, and the copied account of a personal vault. Only the vault's home may ask,
//!   and a replica that holds nothing of the vault acknowledges all the same, so a repeated
//!   erasure (a lost acknowledgement) is harmless.
//!
//! Both sides log it (`tracing`, at info), and the store records an event on each server.

use crate::error::{FedError, Result};
use crate::extra::PendingErasure;
use crate::message::{Request, Response};
use crate::ports::PeerState;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_domain::{Owner, ServerId};

impl<S: FedStore> Replica<S> {
    /// Handles an erasure `peer` asks for. The peer must be paired and the vault's home (by the
    /// vault's settings here, or by the offer it made if the vault was never accepted).
    pub(crate) async fn receive_erasure(&self, peer: ServerId, vault: Owner) -> Result<()> {
        let paired = self
            .store
            .get_peer(peer)
            .await?
            .is_some_and(|p| p.state == PeerState::Paired);
        if !paired {
            return Err(FedError::UnknownPeer);
        }
        let settings = self.store.get_vault(vault).await?;
        let offer = self.store.offer(vault).await?;
        let home = match (&settings, &offer) {
            (Some(settings), _) => settings.home,
            (None, Some(offer)) => offer.home,
            // Nothing held, nothing to delete: acknowledged, so the home can stop asking.
            (None, None) => {
                tracing::info!(%peer, ?vault, "an erasure of a vault this server doesn't hold");
                return Ok(());
            }
        };
        if home != peer {
            return Err(FedError::Refused("only a vault's home may erase it"));
        }

        let erased = self.store.erase_vault(vault).await?;
        let mut files_failed = 0usize;
        if let Some(files) = &self.files {
            for blob in &erased.blobs {
                if let Err(e) = files.delete(*blob).await {
                    files_failed += 1;
                    tracing::warn!(error = %e, "couldn't delete a file of an erased vault");
                }
            }
        }
        tracing::info!(
            %peer,
            ?vault,
            items = erased.items,
            files = erased.blobs.len(),
            files_failed,
            accounts = erased.accounts,
            "erased a vault at its home's request"
        );
        Ok(())
    }

    /// Tells `peer`, over `channel`, about each vault this server erased that the peer holds a
    /// copy of. An erasure the peer acknowledges is completed; one it refuses or can't take stays
    /// queued for the next session. Returns how many were acknowledged.
    pub async fn forward_erasures<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
    ) -> Result<usize> {
        let mut acknowledged = 0;
        for PendingErasure {
            vault, queued_at, ..
        } in self.store.pending_erasures(peer).await?
        {
            match channel.call(&Request::Erase { vault }).await? {
                Response::Ack => {
                    self.store.complete_erasure(peer, vault).await?;
                    acknowledged += 1;
                    tracing::info!(%peer, ?vault, queued_at, "a peer erased its copy of a vault");
                }
                Response::Error { detail, .. } => {
                    tracing::warn!(%peer, ?vault, %detail, "a peer refused to erase its copy of a vault");
                }
                _ => return Err(FedError::Malformed("an unexpected response to an erasure")),
            }
        }
        Ok(acknowledged)
    }
}
