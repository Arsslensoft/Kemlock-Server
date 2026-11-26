//! Signed identity-key rotation and revocation records.
//!
//! "A new identity key is accepted only through a rotation signed by the old key, or by pairing
//! again with a new code", and "a stolen identity key: a signed revocation goes to every peer from
//! the admin console". Both are envelopes with a body of deterministic CBOR:
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | kind: `1` rotation, `2` revocation |
//! | 2 | server id |
//! | 3 | the key being replaced (rotation) or revoked (revocation), 1984 bytes |
//! | 4 | issued at, Unix seconds |
//! | 5 | rotation only: the new descriptor, the envelope bytes, self-signed by the new key |
//!
//! A **rotation** is signed with `sig1("federation-key-rotation", body)` by the *old* key. The
//! receiver accepts it only when the old key is the one it holds for that server, and the new
//! descriptor is for the same server, verifies under its own key and carries another key; it then
//! pins the new key. A **revocation** is signed with `sig1("federation-key-revocation", body)` by
//! the key it revokes (a thief can sign it too, which only revokes a key that is stolen anyway);
//! the receiver that holds that key stops trusting the server until it is paired again.
//!
//! Records are delivered over plain HTTP (`POST /fed/v1/keys`), not a session: after a rotation the
//! sessions of the new key are refused until the record is applied. Each server keeps the newest
//! record of each kind for each server and passes them on to its other peers, so a revocation
//! reaches peers the revoked server isn't paired with. Records are idempotent: applying one twice,
//! or one about a key that was already replaced, does nothing.

use crate::cbor::Value;
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::identity::LocalIdentity;
use crate::ports::PeerState;
use crate::relay::LearnedKey;
use crate::replicate::{FedStore, Replica};
use crate::signed::Signed;
use crate::wire::server_id;
use kemlock_app::ports::StoreError;
use kemlock_crypto::sig1;
use kemlock_domain::ServerId;
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// The record format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of a rotation.
pub const ROTATION_CONTEXT: &str = "federation-key-rotation";
/// The `sig1` context of a revocation.
pub const REVOCATION_CONTEXT: &str = "federation-key-revocation";
/// The largest record accepted.
pub const MAX_RECORD: usize = 32 * 1024;

/// A rotation or a revocation of one server's identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRecord {
    Rotation {
        server: ServerId,
        /// The key that is replaced.
        old_key: Vec<u8>,
        /// The new descriptor, self-signed by the new key.
        new_descriptor: Vec<u8>,
        issued_at: u64,
    },
    Revocation {
        server: ServerId,
        /// The key that is revoked.
        key: Vec<u8>,
        issued_at: u64,
    },
}

impl KeyRecord {
    pub fn server(&self) -> ServerId {
        match self {
            KeyRecord::Rotation { server, .. } | KeyRecord::Revocation { server, .. } => *server,
        }
    }

    pub fn issued_at(&self) -> u64 {
        match self {
            KeyRecord::Rotation { issued_at, .. } | KeyRecord::Revocation { issued_at, .. } => {
                *issued_at
            }
        }
    }

    /// `"rotation"` or `"revocation"`.
    pub fn kind(&self) -> &'static str {
        match self {
            KeyRecord::Rotation { .. } => "rotation",
            KeyRecord::Revocation { .. } => "revocation",
        }
    }

    fn context(&self) -> &'static str {
        match self {
            KeyRecord::Rotation { .. } => ROTATION_CONTEXT,
            KeyRecord::Revocation { .. } => REVOCATION_CONTEXT,
        }
    }

    pub fn to_body(&self) -> Vec<u8> {
        let entries = match self {
            KeyRecord::Rotation {
                server,
                old_key,
                new_descriptor,
                issued_at,
            } => vec![
                (0, Value::Uint(VERSION)),
                (1, Value::Uint(1)),
                (2, Value::bytes(server.as_bytes())),
                (3, Value::bytes(old_key)),
                (4, Value::Uint(*issued_at)),
                (5, Value::bytes(new_descriptor)),
            ],
            KeyRecord::Revocation {
                server,
                key,
                issued_at,
            } => vec![
                (0, Value::Uint(VERSION)),
                (1, Value::Uint(2)),
                (2, Value::bytes(server.as_bytes())),
                (3, Value::bytes(key)),
                (4, Value::Uint(*issued_at)),
            ],
        };
        Value::map(entries).encode()
    }

    pub fn from_body(body: &[u8]) -> Result<KeyRecord> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown key record version"));
        }
        let key = f.bytes(3)?;
        if key.len() != sig1::PUBLIC_KEY_LEN {
            return Err(FedError::Malformed("an identity key has the wrong length"));
        }
        let server = server_id(f.fixed::<16>(2)?);
        let issued_at = f.uint(4)?;
        match f.uint(1)? {
            1 => Ok(KeyRecord::Rotation {
                server,
                old_key: key.to_vec(),
                new_descriptor: f.bytes(5)?.to_vec(),
                issued_at,
            }),
            2 => {
                if f.get(5).is_some() {
                    return Err(FedError::Malformed("a revocation carries no descriptor"));
                }
                Ok(KeyRecord::Revocation {
                    server,
                    key: key.to_vec(),
                    issued_at,
                })
            }
            _ => Err(FedError::Malformed("an unknown key record kind")),
        }
    }

    /// Signs the record: a rotation with the old key, a revocation with the revoked key.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, self.context(), self.to_body())
    }
}

/// How long after a server's key was replaced a revocation signed by that old key still counts, in
/// seconds. A thief who rotates a stolen key away from its owner is answered by the owner's
/// revocation of that key; after this time the old key is forgotten, so a copy of it that leaks
/// much later can't revoke the server.
pub const PAST_KEY_REVOKES_SECS: u64 = 30 * 86_400;

/// An identity key a peer used before its current one, with when this server replaced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PastKey {
    pub key: Vec<u8>,
    /// Unix seconds.
    pub replaced_at: u64,
}

/// The addresses, operator and suites a peer's rotation brought, kept until this server's admin
/// approves them: a rotation is signed by a key that may be stolen, and the addresses decide where
/// this server connects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAddresses {
    pub peer: ServerId,
    pub operator: String,
    pub addresses: Vec<String>,
    pub suites: Vec<String>,
    /// Unix seconds the rotation was applied.
    pub received_at: u64,
}

/// A key record as stored, to pass on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredKeyRecord {
    pub server: ServerId,
    /// `"rotation"` or `"revocation"`.
    pub kind: String,
    /// Unix seconds.
    pub issued_at: u64,
    /// The signed envelope.
    pub envelope: Vec<u8>,
}

/// What federation needs from storage for key records. The defaults answer "nothing", so a store
/// that keeps none needs only an empty `impl`.
pub trait KeyStore: Send + Sync {
    /// Keeps the record unless a record of the same server and kind that is as new or newer is
    /// held. True when it was kept.
    fn put_key_record(&self, _record: &StoredKeyRecord) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(false))
    }

    /// Every record held.
    fn key_records(&self) -> impl Future<Output = R<Vec<StoredKeyRecord>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Replaces the identity key pinned for a peer. `NotFound` for an unknown peer.
    fn set_peer_identity(
        &self,
        _peer: ServerId,
        _key: &[u8],
    ) -> impl Future<Output = R<()>> + Send {
        ready(Err(StoreError::NotFound))
    }

    /// The keys a peer used before its current one, oldest first. Forgotten with the peer.
    fn past_keys(&self, _peer: ServerId) -> impl Future<Output = R<Vec<PastKey>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Adds a key the peer no longer uses.
    fn push_past_key(
        &self,
        _peer: ServerId,
        _key: &[u8],
        _replaced_at: u64,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    /// Keeps (or replaces) the address change a rotation of `peer` brought, for its admin.
    fn put_pending_addresses(
        &self,
        _pending: &PendingAddresses,
    ) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }

    fn pending_addresses(
        &self,
        _peer: ServerId,
    ) -> impl Future<Output = R<Option<PendingAddresses>>> + Send {
        ready(Ok(None))
    }

    /// Every address change waiting for the admin.
    fn list_pending_addresses(&self) -> impl Future<Output = R<Vec<PendingAddresses>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Drops the address change waiting for `peer`, if any.
    fn clear_pending_addresses(&self, _peer: ServerId) -> impl Future<Output = R<()>> + Send {
        ready(Ok(()))
    }
}

/// Makes this server's next identity key and keeps it where the identity is kept. The server id and
/// the identity's addresses and operator stay; the signing key and the KEM keys are new.
pub trait IdentityRotator: Send + Sync {
    fn rotate(&self, current: &LocalIdentity, now: u64) -> Result<LocalIdentity>;

    /// Makes a new KEM key and keeps it where the identity is kept. The identity key, the server id,
    /// the addresses and the operator stay, and the descriptor is signed afresh; the previous KEM
    /// key stays for the overlap so a hello addressed to it still opens.
    fn rotate_kem(&self, _current: &LocalIdentity, _now: u64) -> Result<LocalIdentity> {
        Err(FedError::Refused("this server can't replace its KEM key"))
    }

    /// Signs the descriptor afresh with `suites` (most preferred first) and keeps the choice where
    /// the identity is kept, so a restart doesn't undo it. Keys stay.
    fn set_suites(
        &self,
        _current: &LocalIdentity,
        _suites: &[crate::suite::Suite],
        _now: u64,
    ) -> Result<LocalIdentity> {
        Err(FedError::Refused("this server can't change its suites"))
    }

    /// When the current KEM key was made, Unix seconds, if the keeper knows.
    fn kem_made_at(&self) -> Option<u64> {
        None
    }
}

/// What accepting a record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRecordOutcome {
    /// The record changed what this server trusts.
    Applied,
    /// It was already applied, or is about a key this server no longer holds.
    Known,
}

/// Whether two address lists name the same places: ignoring order, case and a trailing slash.
fn same_addresses(a: &[String], b: &[String]) -> bool {
    let normal = |list: &[String]| {
        let mut out: Vec<String> = list
            .iter()
            .map(|s| s.trim().trim_end_matches('/').to_ascii_lowercase())
            .collect();
        out.sort();
        out.dedup();
        out
    };
    normal(a) == normal(b)
}

fn public_key(bytes: &[u8]) -> Result<sig1::PublicKey> {
    sig1::PublicKey::from_bytes(bytes)
        .map_err(|_| FedError::Malformed("an identity key is not valid"))
}

impl<S: FedStore> Replica<S> {
    /// Takes a signed key record, from a peer or relayed, and applies it. A record about a server
    /// this server holds no key for, about this server itself, from the future, or signed by a key
    /// other than the one held (or, for a revocation, one it replaced lately) is refused.
    ///
    /// - A **rotation** pins the new key and remembers the old one. The addresses, operator and
    ///   suites of the new descriptor take effect at once only when the addresses are the ones
    ///   already known; otherwise they wait for the admin ([`PendingAddresses`]), because a thief
    ///   holding the old key could otherwise send this server wherever it likes.
    /// - A **revocation** of the held key revokes the peer. So does one signed by a key this server
    ///   replaced in the last [`PAST_KEY_REVOKES_SECS`]: that is how the owner of a stolen key
    ///   answers a thief's rotation, and a rotation signed by a key that turned out stolen can't be
    ///   told from the thief's. The peer must be paired again.
    pub async fn accept_key_record(&self, envelope: &[u8], now: u64) -> Result<KeyRecordOutcome> {
        if envelope.len() > MAX_RECORD {
            return Err(FedError::Malformed("a key record is too large"));
        }
        let signed = Signed::decode(envelope)?;
        let record = KeyRecord::from_body(&signed.body)?;
        if record.to_body() != signed.body {
            return Err(FedError::Invalid("the key record body is not canonical"));
        }
        // A record is as old as the key change it describes. A rotation older than a descriptor
        // lives carries a descriptor that has expired anyway.
        if record.issued_at() > now.saturating_add(crate::descriptor::SKEW_SECS) {
            return Err(FedError::Refused("a key record from the future"));
        }
        if matches!(record, KeyRecord::Rotation { .. })
            && record
                .issued_at()
                .saturating_add(crate::descriptor::VALIDITY_SECS)
                < now
        {
            return Err(FedError::Refused("a rotation too old to take"));
        }
        let server = record.server();
        if server == self.server_id() {
            return Err(FedError::Refused("a key record about this server"));
        }
        let peer = self.store.get_peer(server).await?;
        // A server we aren't paired with may be one whose key a peer vouched for (see `relay`).
        let learned = if peer.is_none() {
            self.store
                .learned_keys()
                .await?
                .into_iter()
                .find(|l| l.server == server)
        } else {
            None
        };
        let Some(held) = peer
            .as_ref()
            .map(|p| p.identity_key.clone())
            .or_else(|| learned.as_ref().map(|l| l.key.clone()))
        else {
            return Err(FedError::Refused(
                "a key record for a server we hold no key for",
            ));
        };
        let outcome = match &record {
            KeyRecord::Rotation {
                old_key,
                new_descriptor,
                ..
            } => {
                let new = SignedDescriptor::parse(new_descriptor)?;
                if *old_key != held {
                    // Already applied: the held key is the one the record introduces.
                    return if new.descriptor.identity_key.as_bytes().as_slice() == held.as_slice() {
                        Ok(KeyRecordOutcome::Known)
                    } else {
                        Err(FedError::Refused(
                            "the rotation is not from the key we hold",
                        ))
                    };
                }
                signed.verify(&public_key(&held)?, ROTATION_CONTEXT)?;
                if new.descriptor.server != server {
                    return Err(FedError::Refused(
                        "the new descriptor is for another server",
                    ));
                }
                // Self-signed by the new key, and valid now.
                let new_key = new.descriptor.identity_key.clone();
                new.verify(now, Some(&new_key))?;
                if new.descriptor.identity_key.as_bytes().as_slice() == held.as_slice() {
                    return Err(FedError::Refused("a rotation to the same key"));
                }
                if let Some(known) = &peer {
                    self.store
                        .set_peer_identity(server, new.descriptor.identity_key.as_bytes())
                        .await?;
                    self.store.push_past_key(server, &held, now).await?;
                    let d = &new.descriptor;
                    if same_addresses(&d.addresses, &known.addresses) {
                        self.store
                            .update_peer_descriptor(server, &d.operator, &d.addresses, &d.suites)
                            .await?;
                        self.store.clear_pending_addresses(server).await?;
                    } else {
                        // The rotation moves the server: its admin decides whether to follow.
                        self.store
                            .put_pending_addresses(&PendingAddresses {
                                peer: server,
                                operator: d.operator.clone(),
                                addresses: d.addresses.clone(),
                                suites: d.suites.clone(),
                                received_at: now,
                            })
                            .await?;
                        tracing::warn!(%server, "a rotation brought other addresses: held for the admin");
                    }
                } else if let Some(vouched) = &learned {
                    self.store
                        .put_learned_key(&LearnedKey {
                            server,
                            key: new.descriptor.identity_key.as_bytes().to_vec(),
                            via: vouched.via,
                            learned_at: now,
                        })
                        .await?;
                }
                tracing::info!(%server, "a server rotated its identity key");
                KeyRecordOutcome::Applied
            }
            KeyRecord::Revocation { key, .. } => {
                // The key that revokes: the held one, or a paired peer's earlier one, lately.
                let revoker = if *key == held {
                    Some(held.clone())
                } else if peer.is_some() {
                    self.store
                        .past_keys(server)
                        .await?
                        .into_iter()
                        .find(|past| {
                            past.key == *key
                                && now <= past.replaced_at.saturating_add(PAST_KEY_REVOKES_SECS)
                        })
                        .map(|past| past.key)
                } else {
                    None
                };
                let Some(revoker) = revoker else {
                    return Ok(KeyRecordOutcome::Known);
                };
                signed.verify(&public_key(&revoker)?, REVOCATION_CONTEXT)?;
                let paired = peer.as_ref().is_some_and(|p| p.state == PeerState::Paired);
                if paired {
                    self.store
                        .set_peer_state(server, PeerState::Revoked)
                        .await?;
                    self.store.clear_pending_addresses(server).await?;
                    tracing::warn!(%server, "a peer revoked its identity key: it is no longer trusted");
                    KeyRecordOutcome::Applied
                } else if learned.is_some() && *key == held {
                    self.store.remove_learned_key(server).await?;
                    tracing::warn!(%server, "a server revoked its identity key: its learned key was dropped");
                    KeyRecordOutcome::Applied
                } else {
                    KeyRecordOutcome::Known
                }
            }
        };
        self.store
            .put_key_record(&StoredKeyRecord {
                server,
                kind: record.kind().to_owned(),
                issued_at: record.issued_at(),
                envelope: envelope.to_vec(),
            })
            .await?;
        Ok(outcome)
    }

    /// The address changes that came with rotations and wait for the admin.
    pub async fn pending_address_changes(&self) -> Result<Vec<PendingAddresses>> {
        Ok(self.store.list_pending_addresses().await?)
    }

    /// The admin accepts the address change that came with `peer`'s rotation: it takes effect now.
    /// `Refused` when none waits.
    pub async fn approve_address_change(&self, peer: ServerId) -> Result<()> {
        let pending = self
            .store
            .pending_addresses(peer)
            .await?
            .ok_or(FedError::Refused("no address change waits for this peer"))?;
        self.store
            .update_peer_descriptor(
                peer,
                &pending.operator,
                &pending.addresses,
                &pending.suites,
            )
            .await?;
        self.store.clear_pending_addresses(peer).await?;
        Ok(())
    }

    /// The admin refuses the address change that came with `peer`'s rotation: the addresses this
    /// server knows stay. `Refused` when none waits.
    pub async fn refuse_address_change(&self, peer: ServerId) -> Result<()> {
        self.store
            .pending_addresses(peer)
            .await?
            .ok_or(FedError::Refused("no address change waits for this peer"))?;
        self.store.clear_pending_addresses(peer).await?;
        Ok(())
    }

    /// Replaces this server's identity with `identity`, which has a new signing key, and makes the
    /// signed `record` (made with the old key) ready to deliver to the peers. The server id must
    /// not change.
    pub async fn install_rotated_identity(
        &self,
        identity: std::sync::Arc<LocalIdentity>,
        record: &KeyRecord,
        signed: Vec<u8>,
    ) -> Result<()> {
        if identity.server != self.server_id() || record.server() != self.server_id() {
            return Err(FedError::Invalid("a rotation keeps the server id"));
        }
        self.store
            .put_key_record(&StoredKeyRecord {
                server: record.server(),
                kind: record.kind().to_owned(),
                issued_at: record.issued_at(),
                envelope: signed,
            })
            .await?;
        self.set_identity(identity);
        Ok(())
    }
}

/// The rotation record of a server whose identity `old` is replaced by `new`: the key it replaces,
/// the new descriptor, signed with the old key.
pub fn rotation_record(
    old: &LocalIdentity,
    new: &LocalIdentity,
    now: u64,
) -> Result<(KeyRecord, Signed)> {
    let record = KeyRecord::Rotation {
        server: old.server,
        old_key: old.public.as_bytes().to_vec(),
        new_descriptor: new.descriptor.to_bytes(),
        issued_at: now,
    };
    let signed = record.sign(&old.signing)?;
    Ok((record, signed))
}

/// The revocation record of the identity `old`, signed with its own key.
pub fn revocation_record(old: &LocalIdentity, now: u64) -> Result<(KeyRecord, Signed)> {
    let record = KeyRecord::Revocation {
        server: old.server,
        key: old.public.as_bytes().to_vec(),
        issued_at: now,
    };
    let signed = record.sign(&old.signing)?;
    Ok((record, signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::ports::PeerRepo;
    use crate::suite::Suite;
    use crate::testing::identity;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn records_round_trip_and_refuse_nonsense() {
        let old = identity(1, NOW, &Suite::IMPLEMENTED);
        let new = identity(2, NOW, &Suite::IMPLEMENTED);
        let rotation = KeyRecord::Rotation {
            server: old.server,
            old_key: old.public.as_bytes().to_vec(),
            new_descriptor: new.descriptor.to_bytes(),
            issued_at: NOW,
        };
        let revocation = KeyRecord::Revocation {
            server: old.server,
            key: old.public.as_bytes().to_vec(),
            issued_at: NOW,
        };
        for record in [rotation.clone(), revocation.clone()] {
            assert_eq!(KeyRecord::from_body(&record.to_body()), Ok(record));
        }
        let mut longer = rotation.to_body();
        longer.push(0);
        assert!(KeyRecord::from_body(&longer).is_err());
        // A revocation that carries a descriptor, and a key of the wrong length.
        let mut value = Value::decode(&revocation.to_body()).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((5, Value::bytes(&[1])));
        }
        assert!(KeyRecord::from_body(&value.encode()).is_err());
        let short = KeyRecord::Revocation {
            server: old.server,
            key: vec![1; 10],
            issued_at: NOW,
        };
        assert!(KeyRecord::from_body(&short.to_body()).is_err());
    }

    struct Pair {
        /// The server whose key rotates, and the peer that pinned it.
        a: Replica<MemoryStore>,
        b: Replica<MemoryStore>,
        old: LocalIdentity,
    }

    async fn pair() -> Pair {
        let old = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(old.server), Arc::new(old.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&old.descriptor, NOW).await.expect("pin");
        Pair { a, b, old }
    }

    /// A new identity for the same server, with another signing key.
    fn next(old: &LocalIdentity, seed: u8) -> LocalIdentity {
        let fresh = identity(seed, NOW, &Suite::IMPLEMENTED);
        LocalIdentity::new(
            old.server,
            fresh.signing.clone(),
            fresh.kems.clone(),
            crate::identity::DescriptorParams {
                suites: Suite::IMPLEMENTED.to_vec(),
                addresses: old.descriptor.descriptor.addresses.clone(),
                operator: old.descriptor.descriptor.operator.clone(),
                not_before: NOW,
                not_after: NOW + crate::descriptor::VALIDITY_SECS,
            },
        )
        .expect("an identity")
    }

    #[tokio::test]
    async fn a_peer_takes_a_new_key_only_through_a_rotation_signed_by_the_old_one() {
        let p = pair().await;
        let new = next(&p.old, 5);
        assert_ne!(new.public, p.old.public);
        let (record, signed) = rotation_record(&p.old, &new, NOW).expect("a record");
        let envelope = signed.encode();

        // Signed by the new key (a thief that learned nothing), or by a third key: refused.
        let forged = record.sign(&new.signing).expect("sign").encode();
        assert!(p.b.accept_key_record(&forged, NOW).await.is_err());
        let stranger = identity(9, NOW, &Suite::IMPLEMENTED);
        let forged = record.sign(&stranger.signing).expect("sign").encode();
        assert!(p.b.accept_key_record(&forged, NOW).await.is_err());
        let held =
            p.b.store
                .get_peer(p.old.server)
                .await
                .expect("get")
                .expect("peer");
        assert_eq!(
            held.identity_key,
            p.old.public.as_bytes().to_vec(),
            "nothing changed"
        );

        // The real one is applied, once; a second time is a no-op.
        assert_eq!(
            p.b.accept_key_record(&envelope, NOW).await,
            Ok(KeyRecordOutcome::Applied)
        );
        let held =
            p.b.store
                .get_peer(p.old.server)
                .await
                .expect("get")
                .expect("peer");
        assert_eq!(held.identity_key, new.public.as_bytes().to_vec());
        assert_eq!(held.state, PeerState::Paired);
        assert_eq!(
            p.b.accept_key_record(&envelope, NOW).await,
            Ok(KeyRecordOutcome::Known)
        );
        // B keeps the record to pass on.
        let kept = p.b.store.key_records().await.expect("records");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, "rotation");
    }

    /// A new identity for the same server, with another signing key and these addresses.
    fn moved(old: &LocalIdentity, seed: u8, addresses: &[&str]) -> LocalIdentity {
        let fresh = identity(seed, NOW, &Suite::IMPLEMENTED);
        LocalIdentity::new(
            old.server,
            fresh.signing.clone(),
            fresh.kems.clone(),
            crate::identity::DescriptorParams {
                suites: Suite::IMPLEMENTED.to_vec(),
                addresses: addresses.iter().map(|a| (*a).to_owned()).collect(),
                operator: old.descriptor.descriptor.operator.clone(),
                not_before: NOW,
                not_after: NOW + crate::descriptor::VALIDITY_SECS,
            },
        )
        .expect("an identity")
    }

    async fn peer_of(p: &Pair) -> crate::ports::Peer {
        p.b.store
            .get_peer(p.old.server)
            .await
            .expect("get")
            .expect("peer")
    }

    #[tokio::test]
    async fn a_rotation_that_moves_the_server_waits_for_the_admin_before_the_addresses_change() {
        let p = pair().await;
        let before = peer_of(&p).await;
        // A thief holding the old key rotates it to its own, and says it lives elsewhere.
        let thief = moved(&p.old, 5, &["https://thief.example.net"]);
        let (_, rotation) = rotation_record(&p.old, &thief, NOW).expect("a record");
        assert_eq!(
            p.b.accept_key_record(&rotation.encode(), NOW).await,
            Ok(KeyRecordOutcome::Applied)
        );
        // The key is pinned (the rotation is signed by the held one), but this server still dials
        // the addresses it knew.
        let after = peer_of(&p).await;
        assert_eq!(after.identity_key, thief.public.as_bytes().to_vec());
        assert_eq!(after.addresses, before.addresses);
        let waiting = p.b.pending_address_changes().await.expect("list");
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].peer, p.old.server);
        assert_eq!(waiting[0].addresses, vec!["https://thief.example.net"]);

        // The admin refuses it: the addresses stay, nothing waits.
        p.b.refuse_address_change(p.old.server)
            .await
            .expect("refused");
        assert!(
            p.b.pending_address_changes()
                .await
                .expect("list")
                .is_empty()
        );
        assert_eq!(peer_of(&p).await.addresses, before.addresses);
        assert!(p.b.refuse_address_change(p.old.server).await.is_err());
        assert!(p.b.approve_address_change(p.old.server).await.is_err());
    }

    #[tokio::test]
    async fn the_admin_can_follow_a_server_that_moved() {
        let p = pair().await;
        let moved_to = moved(&p.old, 5, &["https://new-home.example.org"]);
        let (_, rotation) = rotation_record(&p.old, &moved_to, NOW).expect("a record");
        p.b.accept_key_record(&rotation.encode(), NOW)
            .await
            .expect("rotated");
        assert_ne!(
            peer_of(&p).await.addresses,
            vec!["https://new-home.example.org".to_owned()]
        );
        p.b.approve_address_change(p.old.server)
            .await
            .expect("approved");
        assert_eq!(
            peer_of(&p).await.addresses,
            vec!["https://new-home.example.org".to_owned()]
        );
        assert!(
            p.b.pending_address_changes()
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_owners_revocation_of_a_stolen_key_still_counts_after_a_thief_rotated_it_away() {
        let p = pair().await;
        let thief = moved(&p.old, 5, &["https://thief.example.net"]);
        let (_, rotation) = rotation_record(&p.old, &thief, NOW).expect("a record");
        p.b.accept_key_record(&rotation.encode(), NOW)
            .await
            .expect("rotated");
        // The real operator, who still holds the old key, revokes it.
        let (_, revocation) = revocation_record(&p.old, NOW + 60).expect("a record");
        assert_eq!(
            p.b.accept_key_record(&revocation.encode(), NOW + 60).await,
            Ok(KeyRecordOutcome::Applied)
        );
        assert_eq!(peer_of(&p).await.state, PeerState::Revoked);
        assert!(
            p.b.pending_address_changes()
                .await
                .expect("list")
                .is_empty(),
            "the thief's addresses go with it"
        );

        // Someone who never held a key of the server can't revoke it this way.
        let p = pair().await;
        let thief = moved(&p.old, 5, &["https://thief.example.net"]);
        let (_, rotation) = rotation_record(&p.old, &thief, NOW).expect("a record");
        p.b.accept_key_record(&rotation.encode(), NOW)
            .await
            .expect("rotated");
        let stranger = identity(9, NOW, &Suite::IMPLEMENTED);
        let forged = KeyRecord::Revocation {
            server: p.old.server,
            key: p.old.public.as_bytes().to_vec(),
            issued_at: NOW + 60,
        }
        .sign(&stranger.signing)
        .expect("sign")
        .encode();
        assert!(p.b.accept_key_record(&forged, NOW + 60).await.is_err());
        assert_eq!(peer_of(&p).await.state, PeerState::Paired);
    }

    #[tokio::test]
    async fn an_old_key_revokes_nothing_once_the_window_has_passed() {
        let p = pair().await;
        let new = next(&p.old, 5);
        let (_, rotation) = rotation_record(&p.old, &new, NOW).expect("a record");
        p.b.accept_key_record(&rotation.encode(), NOW)
            .await
            .expect("rotated");
        let later = NOW + PAST_KEY_REVOKES_SECS + 10;
        let (_, revocation) = revocation_record(&p.old, later).expect("a record");
        assert_eq!(
            p.b.accept_key_record(&revocation.encode(), later).await,
            Ok(KeyRecordOutcome::Known)
        );
        assert_eq!(peer_of(&p).await.state, PeerState::Paired);
        // A key this server never held, however it signs, revokes nothing.
        let stranger = identity(9, NOW, &Suite::IMPLEMENTED);
        let about_it = KeyRecord::Revocation {
            server: p.old.server,
            key: stranger.public.as_bytes().to_vec(),
            issued_at: NOW,
        }
        .sign(&stranger.signing)
        .expect("sign")
        .encode();
        assert_eq!(
            p.b.accept_key_record(&about_it, NOW).await,
            Ok(KeyRecordOutcome::Known)
        );
        assert_eq!(peer_of(&p).await.state, PeerState::Paired);
    }

    #[tokio::test]
    async fn a_record_from_the_future_or_a_rotation_gone_stale_is_refused() {
        let p = pair().await;
        let new = next(&p.old, 5);
        let future = NOW + crate::descriptor::SKEW_SECS + 1;
        let (_, rotation) = rotation_record(&p.old, &new, future).expect("a record");
        assert!(matches!(
            p.b.accept_key_record(&rotation.encode(), NOW).await,
            Err(FedError::Refused(_))
        ));
        let (_, revocation) = revocation_record(&p.old, future).expect("a record");
        assert!(matches!(
            p.b.accept_key_record(&revocation.encode(), NOW).await,
            Err(FedError::Refused(_))
        ));
        let (_, rotation) = rotation_record(&p.old, &new, NOW).expect("a record");
        let stale = NOW + crate::descriptor::VALIDITY_SECS + 1;
        assert!(matches!(
            p.b.accept_key_record(&rotation.encode(), stale).await,
            Err(FedError::Refused(_))
        ));
        assert_eq!(
            peer_of(&p).await.identity_key,
            p.old.public.as_bytes().to_vec()
        );
    }

    #[tokio::test]
    async fn a_rotation_to_another_servers_descriptor_or_the_same_key_is_refused() {
        let p = pair().await;
        // A descriptor of another server.
        let other = identity(7, NOW, &Suite::IMPLEMENTED);
        let (_, signed) = rotation_record(&p.old, &other, NOW).expect("a record");
        assert!(p.b.accept_key_record(&signed.encode(), NOW).await.is_err());
        // The same key again.
        let (_, signed) = rotation_record(&p.old, &p.old, NOW).expect("a record");
        assert!(p.b.accept_key_record(&signed.encode(), NOW).await.is_err());
        // About this server itself, or a server nobody pinned.
        let new = next(&p.old, 5);
        let (_, signed) = rotation_record(&p.old, &new, NOW).expect("a record");
        assert!(p.a.accept_key_record(&signed.encode(), NOW).await.is_err());
        let c = Replica::new(
            MemoryStore::new(ServerId::random()),
            Arc::new(identity(3, NOW, &Suite::IMPLEMENTED)),
        );
        assert!(c.accept_key_record(&signed.encode(), NOW).await.is_err());
    }

    #[tokio::test]
    async fn a_revocation_stops_trusting_the_server_and_a_stale_one_does_nothing() {
        let p = pair().await;
        let (_, revocation) = revocation_record(&p.old, NOW).expect("a record");
        let envelope = revocation.encode();
        // A revocation signed by another key is refused.
        let stranger = identity(9, NOW, &Suite::IMPLEMENTED);
        let forged = KeyRecord::Revocation {
            server: p.old.server,
            key: p.old.public.as_bytes().to_vec(),
            issued_at: NOW,
        }
        .sign(&stranger.signing)
        .expect("sign")
        .encode();
        assert!(p.b.accept_key_record(&forged, NOW).await.is_err());
        assert_eq!(
            p.b.store
                .get_peer(p.old.server)
                .await
                .expect("get")
                .expect("peer")
                .state,
            PeerState::Paired
        );

        assert_eq!(
            p.b.accept_key_record(&envelope, NOW).await,
            Ok(KeyRecordOutcome::Applied)
        );
        assert_eq!(
            p.b.store
                .get_peer(p.old.server)
                .await
                .expect("get")
                .expect("peer")
                .state,
            PeerState::Revoked
        );
        // No session is accepted from it now.
        assert!(
            !p.b.peer_keys()
                .await
                .expect("keys")
                .contains_key(&p.old.server)
        );
        assert_eq!(
            p.b.accept_key_record(&envelope, NOW).await,
            Ok(KeyRecordOutcome::Known)
        );
    }

    #[tokio::test]
    async fn a_revocation_by_the_replaced_key_counts_for_a_while() {
        let p = pair().await;
        let new = next(&p.old, 5);
        let (_, rotation) = rotation_record(&p.old, &new, NOW).expect("a record");
        p.b.accept_key_record(&rotation.encode(), NOW)
            .await
            .expect("rotated");
        let (_, revocation) = revocation_record(&p.old, NOW + 1).expect("a record");
        assert_eq!(
            p.b.accept_key_record(&revocation.encode(), NOW).await,
            Ok(KeyRecordOutcome::Applied)
        );
        assert_eq!(peer_of(&p).await.state, PeerState::Revoked);
    }
}
