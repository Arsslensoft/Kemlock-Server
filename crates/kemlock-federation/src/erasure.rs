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
use crate::message::{OfferState, Request, Response};
use crate::ports::PeerState;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_domain::{Owner, ServerId};

use kemlock_app::ports::StoreError;

/// What a replica answers when the vault's account lives on it (it is not a copy), so that no
/// peer, whoever it has become, can have a local account's vault erased. It is final: the home
/// stops asking, as it would after an acknowledgement, and logs it.
pub const ERASE_LOCAL_ACCOUNT: &str = "this server holds that vault's account itself";

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
        // Only a vault this server's admin accepted can be erased: an offer is not consent, and one
        // that was declined, or came from a peer that isn't the home of an account copied from
        // another, must not make its sender the home of anything here.
        let Some(settings) = self.store.get_vault(vault).await? else {
            // Nothing held, nothing to delete: acknowledged, so the home can stop asking. An offer
            // it made for the vault is closed, so the admin isn't asked about a vault that's gone.
            if let Some(mut offer) = self.store.offer(vault).await?
                && offer.home == peer
                && offer.state != OfferState::Accepted
            {
                offer.state = OfferState::Declined;
                self.store.put_offer(&offer).await?;
            }
            tracing::info!(%peer, ?vault, "an erasure of a vault this server doesn't hold");
            return Ok(());
        };
        if settings.home != peer {
            return Err(FedError::Refused("only a vault's home may erase it"));
        }

        let erased = match self.store.erase_vault(vault).await {
            Ok(erased) => erased,
            // The account lives here: refused, and nothing was deleted.
            Err(StoreError::Duplicate) => return Err(FedError::Refused(ERASE_LOCAL_ACCOUNT)),
            Err(e) => return Err(e.into()),
        };
        let mut files_failed = 0usize;
        if let Some(files) = &self.files {
            for blob in &erased.blobs {
                // A file another row holds (a Send's) is not this vault's to delete.
                if self.blob_in_use(*blob).await? {
                    continue;
                }
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
                Response::Error { detail, .. } if detail == ERASE_LOCAL_ACCOUNT => {
                    // Final: the peer will never erase it, so asking again every visit is no use.
                    self.store.complete_erasure(peer, vault).await?;
                    tracing::warn!(%peer, ?vault, "a peer holds that vault's account itself and won't erase it: the erasure was dropped");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extra::ErasureOutbox;
    use crate::memory::MemoryStore;
    use crate::ports::VaultRepo;
    use crate::suite::Suite;
    use crate::testing::identity;
    use kemlock_domain::UserId;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self.remote.serve(self.caller, request, NOW).await.response)
        }
    }

    #[tokio::test]
    async fn a_replica_whose_account_is_local_refuses_for_good_and_the_home_stops_asking() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let (a_id, b_id) = (ia.server, ib.server);
        let a = Replica::new(MemoryStore::new(a_id), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(b_id), Arc::new(ib.clone()));
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        b.accept_vault(vault, a_id, vec![b_id])
            .await
            .expect("accept");
        // The vault's account lives on B, not as a copy.
        b.store.set_local_account(vault);
        a.store.queue_erasure(b_id, vault, NOW);

        let mut channel = Direct {
            remote: &b,
            caller: a_id,
        };
        // B says so in a way A takes as final: nothing is acknowledged, nothing stays queued.
        assert_eq!(
            a.forward_erasures(&mut channel, b_id)
                .await
                .expect("a visit"),
            0
        );
        assert!(
            a.store
                .pending_erasures(b_id)
                .await
                .expect("pending")
                .is_empty()
        );
        // And B still holds the vault.
        assert!(b.store.get_vault(vault).await.expect("get").is_some());

        // A vault B holds nothing of is acknowledged, as before.
        let elsewhere = Owner::User(UserId::random());
        a.store.queue_erasure(b_id, elsewhere, NOW);
        assert_eq!(
            a.forward_erasures(&mut channel, b_id)
                .await
                .expect("a visit"),
            1
        );
    }

    #[tokio::test]
    async fn an_offer_is_no_ground_for_an_erasure_but_an_accepted_vault_is() {
        use crate::extra::{FedAdminRepo as _, StoredOffer};
        use crate::ports::ReplicaStore as _;
        use crate::testing::draft;
        use kemlock_domain::ItemId;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let (a_id, b_id) = (ia.server, ib.server);
        let b = Replica::new(MemoryStore::new(b_id), Arc::new(ib.clone()));
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        // B holds items of a vault it never accepted, with a declined offer of A on file.
        let vault = Owner::User(UserId::random());
        b.store
            .put(draft(ItemId::random(), vault, None, 1, 1_000))
            .expect("an item");
        b.store
            .put_offer(&StoredOffer {
                vault,
                home: a_id,
                epoch: 1,
                replicas: vec![b_id],
                state: OfferState::Declined,
                received_at: NOW,
            })
            .await
            .expect("offer");
        b.receive_erasure(a_id, vault).await.expect("acknowledged");
        assert_eq!(
            b.store.leaves(vault).await.expect("leaves").len(),
            1,
            "an offer on file erased nothing"
        );

        // Once the admin accepted the vault, a peer that isn't its home may not erase it, and its
        // home may.
        b.accept_vault(vault, a_id, vec![b_id])
            .await
            .expect("accept");
        let other = identity(3, NOW, &Suite::IMPLEMENTED);
        b.pin_peer(&other.descriptor, NOW).await.expect("pin");
        assert!(b.receive_erasure(other.server, vault).await.is_err());
        assert_eq!(b.store.leaves(vault).await.expect("leaves").len(), 1);
        b.receive_erasure(a_id, vault).await.expect("erased");
        assert!(b.store.leaves(vault).await.expect("leaves").is_empty());
    }
}
