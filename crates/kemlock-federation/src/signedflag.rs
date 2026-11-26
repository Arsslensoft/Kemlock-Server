//! The signed-only flag of an owner as a home record (docs/crypto.md, "The signed-only flag";
//! docs/federation.md, "Writer signatures").
//!
//! The owner asks for signed writes only at the home (or turns it off there, with the password
//! again). The home publishes the flag as one home record of kind [`KIND`], so every replica refuses
//! unsigned `kem1` writes of that owner too, and takes the flag off again when the owner does. A
//! server that doesn't know the kind keeps the record and ignores it.
//!
//! The payload is deterministic CBOR:
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | the owner, 17 bytes (the entity this record is about) |
//! | 2 | whether the owner takes signed writes only: `1` or `0` |

use crate::cbor::Value;
use crate::error::{FedError, Result};
use crate::home::HomeRecord;
use crate::replicate::{FedStore, Replica};
use kemlock_domain::Owner;

/// The home-record kind that carries the flag of one owner.
pub const KIND: &str = "signed-writes";
/// The payload format version.
pub const VERSION: u64 = 1;

/// The payload that says `required` for `owner`.
pub fn payload(owner: Owner, required: bool) -> Vec<u8> {
    Value::map(vec![
        (0, Value::Uint(VERSION)),
        (1, Value::bytes(&owner.to_bytes())),
        (2, Value::flag(required)),
    ])
    .encode()
}

/// The owner and the flag a payload says, when it is one.
pub fn read(payload_bytes: &[u8]) -> Result<(Owner, bool)> {
    let value = Value::decode(payload_bytes)?;
    let fields = value.as_fields()?;
    if fields.uint(0)? != VERSION {
        return Err(FedError::Malformed("an unknown signed-writes version"));
    }
    let owner = Owner::from_bytes(
        fields
            .bytes(1)?
            .try_into()
            .map_err(|_| FedError::Malformed("an owner is 17 bytes"))?,
    )
    .ok_or(FedError::Malformed("an owner is not valid"))?;
    let required = fields.flag(2)?;
    if payload(owner, required) != payload_bytes {
        return Err(FedError::Invalid(
            "the signed-writes record is not canonical",
        ));
    }
    Ok((owner, required))
}

impl<S: FedStore> Replica<S> {
    /// At the home: publishes the flag of `vault` when it differs from what the last record said.
    /// An owner that never asked has no record; one that asked and cleared has one that says so.
    /// Returns whether a record was made. Does nothing at a replica.
    pub async fn publish_signed_writes(&self, vault: Owner) -> Result<bool> {
        let Some(mut publisher) = self.publisher(vault).await? else {
            return Ok(false);
        };
        let required = self.store.owner_signed_only(vault).await?;
        let key = vault.to_bytes().to_vec();
        let asked_before = publisher
            .last(KIND, &key)
            .and_then(|last| read(last).ok())
            .is_some_and(|(_, was)| was);
        if !required && !asked_before {
            return Ok(false);
        }
        self.publish(&mut publisher, KIND, payload(vault, required))
            .await
    }

    /// Applies a `signed-writes` home record this server stored as applied. The home speaks only
    /// for its own vault: a record that names another owner is ignored.
    pub(crate) async fn apply_signed_writes_record(&self, record: &HomeRecord) {
        let (owner, required) = match read(&record.payload) {
            Ok(read) => read,
            Err(e) => {
                tracing::warn!(error = %e, "a signed-writes record is not valid");
                return;
            }
        };
        if owner != record.vault {
            tracing::warn!(
                vault = ?record.vault,
                "a signed-writes record for another owner was refused"
            );
            return;
        }
        if let Err(e) = self.store.set_owner_signed_only(owner, required).await {
            tracing::warn!(error = %e, "the signed-only flag could not be stored");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::ports::{HomeStatus, ReplicaStore, VaultRepo};
    use crate::suite::Suite;
    use crate::testing::identity;
    use kemlock_domain::{ServerId, UserId};
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    fn replica(seed: u8) -> Replica<MemoryStore> {
        let id = identity(seed, NOW, &Suite::IMPLEMENTED);
        Replica::new(MemoryStore::new(id.server), Arc::new(id))
    }

    #[test]
    fn a_payload_names_its_owner_and_round_trips() {
        let owner = Owner::User(UserId::random());
        for required in [true, false] {
            let bytes = payload(owner, required);
            assert_eq!(read(&bytes), Ok((owner, required)));
        }
        let mut other = payload(owner, true);
        other.push(0);
        assert!(read(&other).is_err());
        assert!(read(&[0xff]).is_err());
    }

    #[tokio::test]
    async fn the_home_publishes_the_flag_when_it_is_set_and_when_it_is_cleared() {
        use crate::ports::{Peer, PeerRepo, PeerState};
        let a = replica(1);
        let owner = Owner::User(UserId::random());
        let peer = ServerId::random();
        a.store
            .insert_peer(&Peer {
                id: peer,
                operator: "Other".to_owned(),
                identity_key: vec![1; 8],
                addresses: vec!["https://other.example.org".to_owned()],
                suites: Vec::new(),
                state: PeerState::Paired,
                paired_at: NOW,
                last_seen: None,
            })
            .await
            .expect("a peer");
        a.federate(owner, vec![peer]).await.expect("federate");
        let made = |a: &Replica<MemoryStore>| {
            let store = a.store.clone();
            async move {
                store
                    .home_records(owner, 0, u32::MAX)
                    .await
                    .expect("records")
                    .iter()
                    .filter(|r| r.record.kind == KIND)
                    .count()
            }
        };

        // An owner that never asked has nothing to say.
        assert!(!a.publish_signed_writes(owner).await.expect("published"));
        assert_eq!(made(&a).await, 0);
        a.store.set_signed_only(owner, true);
        assert!(a.publish_signed_writes(owner).await.expect("published"));
        // The same flag is not said again; clearing it is.
        assert!(!a.publish_signed_writes(owner).await.expect("published"));
        a.store.set_signed_only(owner, false);
        assert!(a.publish_signed_writes(owner).await.expect("published"));
        assert!(!a.publish_signed_writes(owner).await.expect("published"));
        assert_eq!(made(&a).await, 2);
        let last = a
            .store
            .home_records(owner, 0, u32::MAX)
            .await
            .expect("records")
            .into_iter()
            .filter(|r| r.record.kind == KIND)
            .max_by_key(|r| r.record.index)
            .expect("a record");
        assert_eq!(last.status, HomeStatus::Applied);
        assert_eq!(read(&last.record.payload), Ok((owner, false)));
    }

    #[tokio::test]
    async fn a_replica_takes_the_flag_from_the_home_and_for_its_own_vault_only() {
        let b = replica(2);
        let owner = Owner::User(UserId::random());
        let home = ServerId::random();
        let record = |vault: Owner, said: Owner, required: bool| HomeRecord {
            vault,
            index: crate::home::home_index(1, 1),
            epoch: 1,
            kind: KIND.to_owned(),
            payload: payload(said, required),
            signer: home,
        };
        b.apply_home_record(&record(owner, owner, true)).await;
        assert!(b.store.owner_signed_only(owner).await.expect("flag"));
        // The home of one vault can't set the flag of another owner.
        let other = Owner::User(UserId::random());
        b.apply_home_record(&record(owner, other, true)).await;
        assert!(!b.store.owner_signed_only(other).await.expect("flag"));
        // And takes it off again when the owner did.
        b.apply_home_record(&record(owner, owner, false)).await;
        assert!(!b.store.owner_signed_only(owner).await.expect("flag"));
    }
}
