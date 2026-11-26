//! Relaying changes across a chain of pairings.
//!
//! "A vault's home and replicas only need to form a connected chain of pairings, because each
//! change carries its origin id and servers pass on the changes of vaults they hold." A server
//! that is paired only with the next one in the chain still has to check the origin signature of a
//! change made by a server it never paired with, so it needs that server's identity key.
//!
//! It learns it from a peer that holds the vault. [`Request::OriginKeys`] asks a peer for the
//! identity keys of the other servers in a vault's set; the peer answers with one **attestation**
//! for each key it holds (pinned at pairing, or learned itself): an envelope signed with
//! `sig1("federation-key-attestation", body)` by the peer's identity key.
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | vault (an owner, 17 bytes) |
//! | 2 | server id: the server whose key it is |
//! | 3 | its identity key, 1984 bytes |
//! | 4 | attester: the server that signs, the peer that answers |
//! | 5 | issued at, Unix seconds |
//!
//! The receiver trusts the attester as it trusts the chain's pairings: it checks the signature
//! under the key it pinned for the attester, that the attester is the peer that answered, that the
//! record is for this vault and names a server in the vault's set, and that it isn't about this
//! server. A key learned this way is kept (`learned_keys`) and used only to verify records of
//! servers it isn't directly paired with: a key from pairing always wins, a different key from
//! another attester than the first is refused, and a revocation or rotation of the server's key
//! (see [`crate::keyrecs`]) updates or drops it. A change from an origin that is neither paired nor
//! in the vault's set is refused whatever key signed it.

use crate::cbor::Value;
use crate::error::{FedError, Result};
use crate::message::{Request, Response};
use crate::ports::PeerState;
use crate::replicate::{Channel, FedStore, Replica};
use crate::session::unix_now;
use crate::signed::Signed;
use crate::wire::{owner, server_id};
use kemlock_app::ports::StoreError;
use kemlock_crypto::sig1;
use kemlock_domain::{Owner, ServerId};
use std::collections::HashMap;
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// The attestation format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of an attestation.
pub const CONTEXT: &str = "federation-key-attestation";

/// The identity key of a server this server isn't paired with, as a peer vouched for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedKey {
    pub server: ServerId,
    /// A `sig1` public key.
    pub key: Vec<u8>,
    /// The peer that vouched for it.
    pub via: ServerId,
    /// Unix seconds.
    pub learned_at: u64,
}

/// What federation needs from storage to keep learned keys. The defaults keep nothing.
pub trait OriginKeys: Send + Sync {
    /// Keeps the key, replacing one held for the same server.
    fn put_learned_key(&self, _key: &LearnedKey) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn learned_keys(&self) -> impl Future<Output = R<Vec<LearnedKey>>> + Send {
        ready(Ok(Vec::new()))
    }

    fn remove_learned_key(&self, _server: ServerId) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }
}

/// One server's key, as an attester signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub vault: Owner,
    pub server: ServerId,
    pub key: Vec<u8>,
    pub attester: ServerId,
    pub issued_at: u64,
}

impl Attestation {
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(&self.vault.to_bytes())),
            (2, Value::bytes(self.server.as_bytes())),
            (3, Value::bytes(&self.key)),
            (4, Value::bytes(self.attester.as_bytes())),
            (5, Value::Uint(self.issued_at)),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<Attestation> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown attestation version"));
        }
        let key = f.bytes(3)?;
        if key.len() != sig1::PUBLIC_KEY_LEN {
            return Err(FedError::Malformed("an identity key has the wrong length"));
        }
        Ok(Attestation {
            vault: owner(f.fixed::<17>(1)?)?,
            server: server_id(f.fixed::<16>(2)?),
            key: key.to_vec(),
            attester: server_id(f.fixed::<16>(4)?),
            issued_at: f.uint(5)?,
        })
    }

    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, CONTEXT, self.to_body())
    }
}

impl<S: FedStore> Replica<S> {
    /// The identity key this server holds for `server`: pinned at pairing, or else learned.
    pub(crate) async fn known_key(&self, server: ServerId) -> Result<Option<Vec<u8>>> {
        if let Some(peer) = self.store.get_peer(server).await? {
            return Ok(Some(peer.identity_key));
        }
        Ok(self
            .store
            .learned_keys()
            .await?
            .into_iter()
            .find(|l| l.server == server)
            .map(|l| l.key))
    }

    /// Answers a request for the keys of a vault's set: one attestation for each server of it, other
    /// than the requester and this server, whose key this server holds.
    pub(crate) async fn serve_origin_keys(&self, peer: ServerId, vault: Owner) -> Result<Response> {
        let settings = self.authorize(peer, vault).await?;
        let me = self.server_id();
        let now = unix_now();
        let mut records = Vec::new();
        for server in settings.order() {
            if server == me || server == peer {
                continue;
            }
            // A server that was paired and then revoked is not vouched for.
            if let Some(held) = self.store.get_peer(server).await?
                && held.state != PeerState::Paired
            {
                continue;
            }
            let Some(key) = self.known_key(server).await? else {
                continue;
            };
            let attestation = Attestation {
                vault,
                server,
                key,
                attester: me,
                issued_at: now,
            };
            records.push(attestation.sign(&self.identity().signing)?.encode());
        }
        Ok(Response::OriginKeys { vault, records })
    }

    /// Asks `peer` for the keys of the other servers that hold `vault` and keeps those this server
    /// doesn't hold already. Returns how many were new.
    pub async fn learn_origin_keys<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<usize> {
        let settings = self.authorize(peer, vault).await?;
        let response = channel.call(&Request::OriginKeys { vault }).await?;
        let records = match response {
            Response::OriginKeys { vault: v, records } if v == vault => records,
            Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
            _ => return Err(FedError::Malformed("an unexpected response to origin keys")),
        };
        let keys = self.peer_keys().await?;
        let attester_key = keys.get(&peer).ok_or(FedError::UnknownPeer)?;
        let me = self.server_id();
        let now = unix_now();
        let learned = self.store.learned_keys().await?;
        let mut new = 0;
        for envelope in records {
            let signed = Signed::decode(&envelope)?;
            let a = Attestation::from_body(&signed.body)?;
            if a.to_body() != signed.body {
                return Err(FedError::Invalid("an attestation is not canonical"));
            }
            signed.verify(attester_key, CONTEXT)?;
            if a.attester != peer || a.vault != vault {
                return Err(FedError::Invalid(
                    "an attestation is not from this peer for this vault",
                ));
            }
            if a.server == me || !settings.holds(a.server) {
                continue;
            }
            // A key from pairing always wins.
            if let Some(direct) = self.store.get_peer(a.server).await? {
                if direct.identity_key != a.key {
                    tracing::warn!(
                        server = %a.server,
                        via = %peer,
                        "a peer vouched for a key other than the one pinned at pairing: ignored"
                    );
                }
                continue;
            }
            if sig1::PublicKey::from_bytes(&a.key).is_err() {
                return Err(FedError::Malformed("an attested key is not valid"));
            }
            match learned.iter().find(|l| l.server == a.server) {
                Some(held) if held.key == a.key => continue,
                Some(held) if held.via != peer => {
                    tracing::warn!(
                        server = %a.server,
                        "two peers vouched for different keys of one server: the first is kept"
                    );
                    continue;
                }
                _ => {}
            }
            self.store
                .put_learned_key(&LearnedKey {
                    server: a.server,
                    key: a.key,
                    via: peer,
                    learned_at: now,
                })
                .await?;
            new += 1;
        }
        Ok(new)
    }

    /// The keys that may sign the changes this server accepts: those of the peers it is paired
    /// with, those it learned for servers it isn't paired with, and its own, since its own changes
    /// come back through relays. A peer that was revoked, or that is known at all, is not replaced by
    /// a learned key.
    pub(crate) async fn directory(&self) -> Result<HashMap<ServerId, sig1::PublicKey>> {
        let mut keys = HashMap::new();
        let peers = self.store.list_peers().await?;
        for learned in self.store.learned_keys().await? {
            if peers.iter().all(|p| p.id != learned.server)
                && let Ok(key) = sig1::PublicKey::from_bytes(&learned.key)
            {
                keys.insert(learned.server, key);
            }
        }
        for peer in peers {
            if peer.state == PeerState::Paired {
                keys.insert(peer.id, peer.key()?);
            }
        }
        keys.insert(self.server_id(), self.identity().public.clone());
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::ports::{PeerRepo, ReplicaStore};
    use crate::suite::Suite;
    use crate::testing::{draft, identity};
    use kemlock_domain::{ItemId, UserId};
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self
                .remote
                .serve(self.caller, request, unix_now())
                .await
                .response)
        }
    }

    /// A chain a - b - c: b is the home, paired with both; a and c never paired.
    struct Chain {
        a: Replica<MemoryStore>,
        b: Replica<MemoryStore>,
        c: Replica<MemoryStore>,
        vault: Owner,
    }

    async fn chain() -> Chain {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let ic = identity(3, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        let c = Replica::new(MemoryStore::new(ic.server), Arc::new(ic.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ic.descriptor, NOW).await.expect("pin");
        c.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        b.federate(vault, vec![ia.server, ic.server])
            .await
            .expect("federate");
        for replica in [&a, &c] {
            replica
                .accept_vault(vault, ib.server, vec![ia.server, ic.server])
                .await
                .expect("accept");
        }
        Chain { a, b, c, vault }
    }

    #[test]
    fn an_attestation_round_trips_signed() {
        let a = Attestation {
            vault: Owner::User(UserId::random()),
            server: ServerId::random(),
            key: vec![7; sig1::PUBLIC_KEY_LEN],
            attester: ServerId::random(),
            issued_at: NOW,
        };
        assert_eq!(Attestation::from_body(&a.to_body()), Ok(a.clone()));
        let key = sig1::SigningKey::from_bytes(&[4; 64]);
        let public = crate::crypto::sign_public(&key).expect("public");
        a.sign(&key)
            .expect("sign")
            .verify(&public, CONTEXT)
            .expect("verifies");
        let mut short = a.clone();
        short.key = vec![1; 10];
        assert!(Attestation::from_body(&short.to_body()).is_err());
    }

    #[tokio::test]
    async fn a_change_from_a_server_never_paired_arrives_through_the_peer_between() {
        let t = chain().await;
        let item = ItemId::random();
        t.a.store
            .put(draft(item, t.vault, None, 1, 1_000))
            .expect("a write at A");
        // B takes A's change: it is paired with A.
        let mut from_a = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        t.b.pull(&mut from_a, t.a.server_id(), t.vault)
            .await
            .expect("pull");
        assert!(t.b.store.get(item).is_some());

        // C has no key for A, so it can't take A's change from B.
        let mut from_b = Direct {
            remote: &t.b,
            caller: t.c.server_id(),
        };
        assert!(
            t.c.pull(&mut from_b, t.b.server_id(), t.vault)
                .await
                .is_err()
        );
        assert!(t.c.store.get(item).is_none());

        // It learns A's key from B, which vouches for it, and then it can.
        assert_eq!(
            t.c.learn_origin_keys(&mut from_b, t.b.server_id(), t.vault)
                .await,
            Ok(1)
        );
        assert_eq!(
            t.c.learn_origin_keys(&mut from_b, t.b.server_id(), t.vault)
                .await,
            Ok(0),
            "once"
        );
        let report =
            t.c.pull(&mut from_b, t.b.server_id(), t.vault)
                .await
                .expect("pull");
        assert_eq!(report.counts.applied, 1);
        assert!(t.c.store.get(item).is_some());
        // The change is still A's: signed by A, with A as its origin.
        assert_eq!(
            t.c.store.get(item).expect("the item").change.origin,
            t.a.server_id()
        );
        // A key learned is not a pairing: C still has one peer.
        assert_eq!(t.c.store.list_peers().await.expect("peers").len(), 1);
    }

    #[tokio::test]
    async fn a_forged_change_in_the_name_of_a_learned_origin_is_still_refused() {
        let t = chain().await;
        let mut from_b = Direct {
            remote: &t.b,
            caller: t.c.server_id(),
        };
        t.c.learn_origin_keys(&mut from_b, t.b.server_id(), t.vault)
            .await
            .expect("learned");
        // B holds a change that claims A as its origin but is signed with B's own key.
        let item = ItemId::random();
        t.b.store
            .put(draft(item, t.vault, None, 1, 1_000))
            .expect("a write at B");
        let stored =
            t.b.store
                .export_since(t.vault, &kemlock_domain::VersionVector::new(), 10)
                .await
                .expect("export");
        let mut record = crate::change::ChangeRecord::from_item(&stored.entries[0].item, vec![]);
        record.change.origin = t.a.server_id();
        let forged = record.sign(&t.b.identity().signing).expect("sign").encode();
        assert!(crate::change::open(&forged, &t.c.directory().await.expect("keys")).is_err());
    }

    #[tokio::test]
    async fn an_origin_outside_the_vaults_set_is_refused_even_with_a_key_someone_vouched_for() {
        let t = chain().await;
        let outsider = identity(5, NOW, &Suite::IMPLEMENTED);
        let stranger = Replica::new(
            MemoryStore::new(outsider.server),
            Arc::new(outsider.clone()),
        );
        let item = ItemId::random();
        stranger
            .store
            .put(draft(item, t.vault, None, 1, 1_000))
            .expect("a write");
        let stored = stranger
            .store
            .export_since(t.vault, &kemlock_domain::VersionVector::new(), 10)
            .await
            .expect("export");
        let record = crate::change::ChangeRecord::from_item(&stored.entries[0].item, vec![]);
        let envelope = record.sign(&outsider.signing).expect("sign").encode();
        t.c.store
            .put_learned_key(&LearnedKey {
                server: outsider.server,
                key: outsider.public.as_bytes().to_vec(),
                via: t.b.server_id(),
                learned_at: NOW,
            })
            .await
            .expect("kept");
        assert!(
            t.c.apply_envelopes(t.b.server_id(), t.vault, &[envelope]).await.is_err(),
            "an origin outside the set"
        );
        assert!(t.c.store.get(item).is_none());
    }
}
