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
use crate::ports::{PeerState, StoredHomeRecord};
use crate::publish::entity_key;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_domain::{Owner, ServerId, UserId};

/// Whether the account's bundle parses and carries a valid signature of its own `sig1` key.
fn bundle_is_signed(account: &MemberAccount) -> bool {
    kemlock_crypto::bundle::Bundle::from_bytes(&account.public_bundle)
        .and_then(|bundle| bundle.verify_self_signature(&account.bundle_signature))
        .is_ok()
}

/// Whether the latest `member-account` record of `user` among `records` was made before the first
/// `space-member` record of the same user: the order a home used before replicas needed the member
/// first.
fn account_predates_member(records: &[StoredHomeRecord], user: UserId) -> bool {
    let key = user.0.as_bytes().to_vec();
    let about = |kind: &str| {
        records
            .iter()
            .filter(|r| r.record.kind == kind)
            .filter(|r| entity_key(&r.record.payload).as_deref() == Some(key.as_slice()))
            .map(|r| r.record.index)
    };
    match (
        about(members::KIND).max(),
        about(crate::spaces::KIND_MEMBER).min(),
    ) {
        (Some(account), Some(member)) => account < member,
        _ => false,
    }
}

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
            // Held under another home or epoch. Said apart from "nobody asked about this", an
            // answer would tell a paired server that this vault is federated here.
            tracing::info!(%peer, "ignored an offer of a vault this server holds under another home");
            return Ok(OfferState::Pending);
        }
        if self.store.owns_vault(vault).await? {
            // The vault's account or space lives here. Said apart from an offer that waits for the
            // admin, "refused" would tell a paired server that this id exists here; the answer is
            // the same, and nothing is kept.
            tracing::info!(%peer, "ignored an offer of a vault that lives on this server");
            return Ok(OfferState::Pending);
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
        self.apply_member_record(record).await;
    }

    /// Applies a `member-account` home record this server stored as applied.
    pub(crate) async fn apply_member_record(&self, record: &HomeRecord) {
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
        // The server keeps only a public-key bundle whose own signature verifies (docs/crypto.md),
        // and a peer's copy is no exception. An account with no keys yet has an empty bundle.
        if !account.public_bundle.is_empty() && !bundle_is_signed(&account) {
            tracing::warn!(
                user = %account.id,
                "a member account record whose public-key bundle does not verify was refused"
            );
            return;
        }
        match self
            .store
            .apply_member_account(record.vault, record.signer, &account)
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
        // Account records a space's home made before its member records (the order before a
        // replica needed the member first) were refused by a replica that caught up later, and an
        // unchanged payload is never made again: such an account is published once more.
        let existing = match vault {
            Owner::Space(_) => self.store.home_records(vault, 0, u32::MAX).await?,
            Owner::User(_) => Vec::new(),
        };
        for user in self.store.member_ids(vault).await? {
            let Some(account) = self.store.member_account(user).await? else {
                continue;
            };
            if account_predates_member(&existing, user) {
                publisher.forget(members::KIND, user.0.as_bytes().to_vec());
            }
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

    /// A public-key bundle and its signature by its own key, as an account has.
    fn signed_bundle() -> (Vec<u8>, Vec<u8>) {
        use kemlock_crypto::{bundle::Bundle, kx1, sig1};
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let bundle = Bundle {
            account_id: [1; 16],
            key_version: 1,
            kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("a key"),
            sig1_public: crate::crypto::sign_public(&key).expect("a public key"),
        };
        let signature = bundle.sign(&key).expect("a signature");
        (bundle.to_bytes(), signature)
    }

    fn account(id: UserId) -> MemberAccount {
        let (public_bundle, bundle_signature) = signed_bundle();
        MemberAccount {
            id,
            email: "ada@example.org".to_owned(),
            name: None,
            mode: AccountMode::KemlockOnly,
            kdf: KdfParams::new_account([3; 16]),
            wrapped_root_key: vec![1; 80],
            public_bundle,
            bundle_signature,
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
    #[tokio::test]
    async fn a_copy_whose_bundle_does_not_verify_under_its_own_key_is_refused() {
        let r = replica();
        let home = ServerId::random();
        let owner = UserId::random();
        let vault = Owner::User(owner);

        let mut forged = account(owner);
        let last = forged.bundle_signature.len() - 1;
        forged.bundle_signature[last] ^= 1;
        r.apply_home_record(&record(vault, home, &forged)).await;
        let mut garbled = account(owner);
        garbled.public_bundle = vec![2; 300];
        r.apply_home_record(&record(vault, home, &garbled)).await;
        // A bundle signed by another key than the one it carries.
        let mut swapped = account(owner);
        swapped.bundle_signature = {
            use kemlock_crypto::{bundle::Bundle, sig1};
            let other = sig1::SigningKey::from_bytes(&[6; 64]);
            Bundle::from_bytes(&swapped.public_bundle)
                .expect("a bundle")
                .sign(&other)
                .expect("a signature")
        };
        r.apply_home_record(&record(vault, home, &swapped)).await;
        assert!(r.store.applied_accounts().is_empty());

        // The real one, and an account with no keys yet, are taken.
        r.apply_home_record(&record(vault, home, &account(owner)))
            .await;
        let mut keyless = account(owner);
        keyless.public_bundle = Vec::new();
        keyless.bundle_signature = Vec::new();
        r.apply_home_record(&record(vault, home, &keyless)).await;
        assert_eq!(r.store.applied_accounts().len(), 2);
    }

    #[tokio::test]
    async fn an_offer_gets_the_same_answer_whether_or_not_the_vault_lives_here() {
        use crate::extra::FedAdminRepo as _;
        use crate::ports::VaultRepo as _;
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let (home, me) = (ia.server, ib.server);
        let replica = Replica::new(MemoryStore::new(me), Arc::new(ib));
        replica.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let ours = Owner::User(UserId::random());
        let theirs = Owner::User(UserId::random());
        replica.store.set_owned(ours, true);
        replica.store.set_owned(theirs, false);

        // A paired server offers an id that is an account of this server, and one that isn't.
        let about_ours = replica
            .receive_offer(home, ours, home, 1, &[me], NOW)
            .await;
        let about_theirs = replica
            .receive_offer(home, theirs, home, 1, &[me], NOW)
            .await;
        assert_eq!(about_ours, Ok(OfferState::Pending));
        assert_eq!(about_ours, about_theirs, "it can't tell which id exists here");
        // Only the one that doesn't live here waits for the admin; nothing is kept for the other.
        assert_eq!(replica.store.offer(ours).await, Ok(None));
        assert!(replica.store.offer(theirs).await.expect("read").is_some());
        // A vault held here under another home is answered the same way.
        let mut held = VaultFederation::federated(
            Owner::User(UserId::random()),
            ServerId::random(),
            vec![me],
        );
        held.epoch = 3;
        replica.store.put_vault(&held).await.expect("put");
        let about_held = replica
            .receive_offer(home, held.owner, home, 1, &[me], NOW)
            .await;
        assert_eq!(about_held, Ok(OfferState::Pending));
        assert_eq!(replica.store.offer(held.owner).await, Ok(None));
    }

    #[tokio::test]
    async fn an_account_that_came_before_its_member_record_is_applied_once_the_member_arrives() {
        use crate::ports::{HomeStatus, StoredHomeRecord};
        use crate::spaces::{KIND_MEMBER, encode_member};
        let r = replica();
        let home = ServerId::random();
        let snapshot = crate::testing::space_snapshot(SpaceId::random());
        let space = Owner::Space(snapshot.state.space.id);
        let member = snapshot.state.members[0].clone();
        let acct = account(member.user);

        // The home made the account record first (as homes did before this change), and the
        // replica refused it for want of the member record. It is stored as applied all the same.
        let made = record(space, home, &acct);
        r.store
            .put_home_record(&StoredHomeRecord {
                signed: Vec::new(),
                record: made.clone(),
                status: HomeStatus::Applied,
            })
            .await
            .expect("stored");
        r.apply_home_record(&made).await;
        assert!(r.store.applied_accounts().is_empty());

        // The member record arrives and the replica knows the member: the account follows, with
        // nothing republished.
        r.store.set_members(space, vec![member.user]);
        r.apply_home_record(&HomeRecord {
            vault: space,
            index: crate::home::home_index(1, 2),
            epoch: 1,
            kind: KIND_MEMBER.to_owned(),
            payload: encode_member(&member),
            signer: home,
        })
        .await;
        assert_eq!(r.store.applied_accounts(), vec![(home, member.user)]);
    }

    #[tokio::test]
    async fn an_account_made_before_its_space_member_record_is_published_once_more() {
        use crate::ports::{HomeStatus, StoredHomeRecord};
        use crate::spaces::{KIND_MEMBER, encode_member};
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let snapshot = crate::testing::space_snapshot(SpaceId::random());
        let space = Owner::Space(snapshot.state.space.id);
        let member = snapshot.state.members[0].clone();
        let acct = account(member.user);
        a.federate(space, vec![ServerId::random()])
            .await
            .expect("federate");
        a.store.set_members(space, vec![member.user]);
        a.store.set_member_account(acct.clone());
        let keep = |index: u64, kind: &str, payload: Vec<u8>| StoredHomeRecord {
            signed: Vec::new(),
            record: HomeRecord {
                vault: space,
                index: crate::home::home_index(1, index),
                epoch: 1,
                kind: kind.to_owned(),
                payload,
                signer: ia.server,
            },
            status: HomeStatus::Applied,
        };
        // The old order: the account, then the member.
        a.store
            .put_home_record(&keep(1, members::KIND, acct.to_payload()))
            .await
            .expect("stored");
        a.store
            .put_home_record(&keep(2, KIND_MEMBER, encode_member(&member)))
            .await
            .expect("stored");

        assert_eq!(a.publish_members(space).await.expect("published"), 1);
        assert_eq!(
            a.publish_members(space).await.expect("published"),
            0,
            "once, not at every visit"
        );
    }

}
