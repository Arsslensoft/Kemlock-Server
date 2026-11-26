//! A replica holds a vault only after its own admin accepts it, and the home makes its members'
//! accounts follow the vault.
//!
//! - **Offers.** A vault's home offers it to each replica it names ([`Request::Offer`]). The
//!   replica keeps the offer until its admin accepts or declines; only an accepted vault is
//!   federated here and replicated from the peers. The home asks again at each session, so an
//!   admin's later answer reaches it, and an accepted vault learns a new replica order.
//! - **Member accounts.** The home publishes each member's account as a home record
//!   ([`crate::members`]); a replica applies the records its pull stored as applied.

use crate::error::{FedError, Result};
use crate::extra::{MemberApply, StoredOffer};
use crate::home::{HomeRecord, Policy, VaultFederation};
use crate::members::{self, MemberAccount};
use crate::message::{OfferState, Request, Response};
use crate::ports::PeerState;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_domain::{Owner, ServerId};

impl<S: FedStore> Replica<S> {
    /// Handles an offer from `peer`, which must be the vault's home: remembers it for the admin, or
    /// says where it stands.
    pub(crate) async fn receive_offer(
        &self,
        peer: ServerId,
        vault: Owner,
        home: ServerId,
        epoch: u64,
        replicas: &[ServerId],
        now: u64,
    ) -> Result<OfferState> {
        let paired = self
            .store
            .get_peer(peer)
            .await?
            .is_some_and(|p| p.state == PeerState::Paired);
        if !paired {
            return Err(FedError::UnknownPeer);
        }
        let me = self.server_id();
        if peer != home {
            return Err(FedError::Refused("only a vault's home offers it"));
        }
        if epoch == 0 || !replicas.contains(&me) || replicas.contains(&home) {
            return Err(FedError::Refused(
                "the offer does not name this server as a replica",
            ));
        }
        if let Some(held) = self.store.get_vault(vault).await? {
            if held.policy == Policy::Federated && held.home == home && held.epoch == epoch {
                if held.replicas != replicas {
                    let mut next = held.clone();
                    next.replicas = replicas.to_vec();
                    self.store.put_vault(&next).await?;
                }
                return Ok(OfferState::Accepted);
            }
            return Err(FedError::Refused(
                "this server holds that vault under another home",
            ));
        }
        if self.store.owns_vault(vault).await? {
            return Err(FedError::Refused("this server already holds that vault"));
        }
        match self.store.offer(vault).await? {
            Some(mut existing) if existing.home == home => {
                if existing.state == OfferState::Pending
                    && (existing.epoch != epoch || existing.replicas != replicas)
                {
                    existing.epoch = epoch;
                    existing.replicas = replicas.to_vec();
                    self.store.put_offer(&existing).await?;
                }
                Ok(existing.state)
            }
            _ => {
                self.store
                    .put_offer(&StoredOffer {
                        vault,
                        home,
                        epoch,
                        replicas: replicas.to_vec(),
                        state: OfferState::Pending,
                        received_at: now,
                    })
                    .await?;
                Ok(OfferState::Pending)
            }
        }
    }

    /// The admin accepts the offered vault: this server now holds it as a replica.
    pub async fn accept_offer(&self, vault: Owner) -> Result<VaultFederation> {
        let mut offer = self
            .store
            .offer(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        if offer.state == OfferState::Accepted {
            return self
                .store
                .get_vault(vault)
                .await?
                .ok_or(FedError::UnknownVault);
        }
        let federation = VaultFederation {
            epoch: offer.epoch,
            ..VaultFederation::federated(vault, offer.home, offer.replicas.clone())
        };
        if !federation.holds(self.server_id()) {
            return Err(FedError::Refused("this server is not in the vault's set"));
        }
        self.store.put_vault(&federation).await?;
        offer.state = OfferState::Accepted;
        self.store.put_offer(&offer).await?;
        Ok(federation)
    }

    /// The admin declines the offered vault. The home is told at its next session.
    pub async fn decline_offer(&self, vault: Owner) -> Result<()> {
        let mut offer = self
            .store
            .offer(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        if offer.state == OfferState::Accepted {
            return Err(FedError::Refused("an accepted vault can't be declined"));
        }
        offer.state = OfferState::Declined;
        self.store.put_offer(&offer).await?;
        Ok(())
    }

    /// Offers `vault` to `peer` over `channel`, and returns where the offer stands there. The
    /// vault must be one this server is the home of, with `peer` among its replicas.
    pub async fn offer_vault<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<OfferState> {
        let settings = self
            .store
            .get_vault(vault)
            .await?
            .filter(|v| v.policy == Policy::Federated && v.home == self.server_id())
            .ok_or(FedError::UnknownVault)?;
        if !settings.replicas.contains(&peer) {
            return Err(FedError::Refused("the peer is not a replica of the vault"));
        }
        let response = channel
            .call(&Request::Offer {
                vault,
                home: settings.home,
                epoch: settings.epoch,
                replicas: settings.replicas.clone(),
            })
            .await?;
        match response {
            Response::OfferStatus { vault: v, state } if v == vault => Ok(state),
            Response::Error { detail, .. } => Err(FedError::Remote(detail)),
            _ => Err(FedError::Malformed("an unexpected response to an offer")),
        }
    }

    /// Applies a home record this server stored as applied. A kind this server doesn't know is
    /// kept (for relaying) and otherwise ignored.
    pub(crate) async fn apply_home_record(&self, record: &HomeRecord) {
        if crate::chain::is_chain_kind(&record.kind) {
            self.apply_chain_home_record(record.vault, &record.payload)
                .await;
            return;
        }
        if crate::spaces::is_space_kind(&record.kind) {
            self.apply_space_home_record(record.vault, &record.kind, &record.payload)
                .await;
            return;
        }
        if record.kind != members::KIND {
            tracing::debug!(kind = %record.kind, "a home record of a kind this server doesn't apply");
            return;
        }
        let account = match MemberAccount::from_payload(&record.payload) {
            Ok(account) => account,
            Err(e) => {
                tracing::warn!(error = %e, "a member account record is not valid");
                return;
            }
        };
        // The home may only publish accounts that belong to its vault: the owner of a personal
        // vault, or a confirmed member of a space as this server knows it. Otherwise the home of
        // any vault this server replicates could replace the copy of a user who belongs to
        // another vault, devices and keys included.
        let belongs = match record.vault {
            Owner::User(owner) => account.id == owner,
            Owner::Space(_) => self
                .store
                .member_ids(record.vault)
                .await
                .is_ok_and(|ids| ids.contains(&account.id)),
        };
        if !belongs {
            tracing::warn!(
                user = %account.id,
                vault = ?record.vault,
                "a member account record for an account that is not in the vault was refused"
            );
            return;
        }
        match self
            .store
            .apply_member_account(record.signer, &account)
            .await
        {
            Ok(MemberApply::Refused) => tracing::warn!(
                user = %account.id,
                "a member's account was not copied: this server has an account with that id or email"
            ),
            Ok(MemberApply::Applied | MemberApply::Unchanged) => {}
            Err(e) => tracing::warn!(error = %e, "a member account could not be stored"),
        }
    }

    /// At the home: publishes a home record for every member account of `vault` that changed since
    /// its last record. Returns how many records it made. Does nothing at a replica.
    pub async fn publish_members(&self, vault: Owner) -> Result<usize> {
        let Some(mut publisher) = self.publisher(vault).await? else {
            return Ok(0);
        };
        for user in self.store.member_ids(vault).await? {
            let Some(account) = self.store.member_account(user).await? else {
                continue;
            };
            self.publish(&mut publisher, members::KIND, account.to_payload())
                .await?;
        }
        Ok(publisher.made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::suite::Suite;
    use crate::testing::identity;
    use kemlock_domain::{AccountMode, DeviceKind, KdfParams, SpaceId, UserId};
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    fn account(id: UserId) -> MemberAccount {
        MemberAccount {
            id,
            email: "ada@example.org".to_owned(),
            name: None,
            mode: AccountMode::KemlockOnly,
            kdf: KdfParams::new_account([3; 16]),
            wrapped_root_key: vec![1; 80],
            public_bundle: vec![2; 300],
            bundle_signature: vec![3; 100],
            sealed_private_keys: vec![4; 200],
            key_version: 1,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            devices: vec![members::MemberDevice {
                id: kemlock_domain::DeviceId::random(),
                name: "Pixel".to_owned(),
                kind: DeviceKind::KemlockAndroid,
                dpop_jkt: Some("thumbprint".to_owned()),
                created_at: 1_700_000_050,
            }],
        }
    }

    fn record(vault: Owner, signer: ServerId, account: &MemberAccount) -> HomeRecord {
        HomeRecord {
            vault,
            index: crate::home::home_index(1, 1),
            epoch: 1,
            kind: members::KIND.to_owned(),
            payload: account.to_payload(),
            signer,
        }
    }

    fn replica() -> Replica<MemoryStore> {
        let id = identity(1, NOW, &Suite::IMPLEMENTED);
        Replica::new(MemoryStore::new(id.server), Arc::new(id))
    }

    #[tokio::test]
    async fn a_personal_vaults_home_can_only_publish_that_vaults_account() {
        let r = replica();
        let home = ServerId::random();
        let owner = UserId::random();
        let other = UserId::random();
        // The home of the vault of `owner` carries the account of someone else: refused.
        r.apply_home_record(&record(Owner::User(owner), home, &account(other)))
            .await;
        assert!(r.store.applied_accounts().is_empty());
        // Its own account goes through.
        r.apply_home_record(&record(Owner::User(owner), home, &account(owner)))
            .await;
        assert_eq!(r.store.applied_accounts(), vec![(home, owner)]);
    }

    #[tokio::test]
    async fn a_spaces_home_can_only_publish_accounts_of_its_confirmed_members() {
        let r = replica();
        let home = ServerId::random();
        let space = Owner::Space(SpaceId::random());
        let member = UserId::random();
        let stranger = UserId::random();
        r.store.set_members(space, vec![member]);
        r.apply_home_record(&record(space, home, &account(stranger)))
            .await;
        assert!(r.store.applied_accounts().is_empty());
        r.apply_home_record(&record(space, home, &account(member)))
            .await;
        assert_eq!(r.store.applied_accounts(), vec![(home, member)]);
    }
}
