//! A space's signed chain as home records (docs/crypto.md, "Space chain", G4).
//!
//! The home accepts chain records; replicas may serve the chain, and records are signed, so a
//! replica needs no trust in the home to hold them. Each chain record travels as one home record of
//! kind `space-chain`, named by its `seq` (8 bytes, big endian, under key 1) so the home makes one
//! per record and never again for the same one. The payload carries the record's exact bytes and
//! signatures, and the boxes and sealed names it committed:
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | `seq`, 8 bytes big endian |
//! | 2 | `seq` |
//! | 3 | link (32 bytes) |
//! | 4 | epoch |
//! | 5 | signer (account id, 16 bytes) |
//! | 6 | `at` |
//! | 7 | record bytes |
//! | 8 | signature |
//! | 9 | cosignature (a `rekey` only) |
//! | 10 | seals: `[{0 key, 1 version, 2 member, 3 bundle version, 4 box}]` |
//! | 11 | names: `[{0 target, 1 version, 2 hash, 3 sealed name}]` |
//!
//! After a promotion the new home accepts no chain record until an Owner's client has signed the
//! `fence` that names it (the append route checks that); the replicas simply keep what the home
//! publishes.

use crate::cbor::Value;
use crate::error::{FedError, Result};
use crate::replicate::{FedStore, Replica};
use kemlock_domain::Owner;

/// The kind of home record that carries a chain record.
pub const KIND: &str = "space-chain";
/// The payload format version.
pub const VERSION: u64 = 1;

/// Whether `kind` is the chain's.
pub fn is_chain_kind(kind: &str) -> bool {
    kind == KIND
}

/// A sealed key a record committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireSeal {
    /// `space` or `collection:<uuid>`.
    pub key: String,
    pub version: u32,
    pub member: [u8; 16],
    pub bundle_version: u32,
    pub sealed: Vec<u8>,
}

/// A sealed name a record committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireName {
    /// `space`, `collection:<uuid>` or `group:<uuid>`.
    pub target: String,
    pub version: u32,
    pub hash: [u8; 32],
    pub sealed: Vec<u8>,
}

/// One chain record with what it committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainWire {
    pub seq: u64,
    pub link: [u8; 32],
    pub epoch: u32,
    pub by: [u8; 16],
    pub at: u64,
    pub entry: Vec<u8>,
    pub signature: Vec<u8>,
    pub cosignature: Option<Vec<u8>>,
    pub seals: Vec<WireSeal>,
    pub names: Vec<WireName>,
}

fn small(n: u64) -> Result<u32> {
    u32::try_from(n).map_err(|_| FedError::Malformed("a number is out of range"))
}

impl ChainWire {
    /// The home record's payload.
    pub fn payload(&self) -> Vec<u8> {
        let mut entries = vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(&self.seq.to_be_bytes())),
            (2, Value::Uint(self.seq)),
            (3, Value::bytes(&self.link)),
            (4, Value::Uint(u64::from(self.epoch))),
            (5, Value::bytes(&self.by)),
            (6, Value::Uint(self.at)),
            (7, Value::bytes(&self.entry)),
            (8, Value::bytes(&self.signature)),
        ];
        if let Some(c) = &self.cosignature {
            entries.push((9, Value::bytes(c)));
        }
        entries.push((
            10,
            Value::Array(
                self.seals
                    .iter()
                    .map(|s| {
                        Value::map(vec![
                            (0, Value::text(&s.key)),
                            (1, Value::Uint(u64::from(s.version))),
                            (2, Value::bytes(&s.member)),
                            (3, Value::Uint(u64::from(s.bundle_version))),
                            (4, Value::bytes(&s.sealed)),
                        ])
                    })
                    .collect(),
            ),
        ));
        entries.push((
            11,
            Value::Array(
                self.names
                    .iter()
                    .map(|n| {
                        Value::map(vec![
                            (0, Value::text(&n.target)),
                            (1, Value::Uint(u64::from(n.version))),
                            (2, Value::bytes(&n.hash)),
                            (3, Value::bytes(&n.sealed)),
                        ])
                    })
                    .collect(),
            ),
        ));
        Value::map(entries).encode()
    }

    /// Reads a payload, refusing one that isn't what [`payload`](Self::payload) writes.
    pub fn from_payload(payload: &[u8]) -> Result<ChainWire> {
        let value = Value::decode(payload)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("an unknown chain record version"));
        }
        let seq = f.uint(2)?;
        if f.bytes(1)? != seq.to_be_bytes() {
            return Err(FedError::Invalid("a chain record names another seq"));
        }
        let mut seals = Vec::new();
        for v in f.array(10)? {
            let s = v.as_fields()?;
            s.only(&[0, 1, 2, 3, 4])?;
            seals.push(WireSeal {
                key: s.text(0)?.to_owned(),
                version: small(s.uint(1)?)?,
                member: s.fixed::<16>(2)?,
                bundle_version: small(s.uint(3)?)?,
                sealed: s.bytes(4)?.to_vec(),
            });
        }
        let mut names = Vec::new();
        for v in f.array(11)? {
            let n = v.as_fields()?;
            n.only(&[0, 1, 2, 3])?;
            names.push(WireName {
                target: n.text(0)?.to_owned(),
                version: small(n.uint(1)?)?,
                hash: n.fixed::<32>(2)?,
                sealed: n.bytes(3)?.to_vec(),
            });
        }
        let wire = ChainWire {
            seq,
            link: f.fixed::<32>(3)?,
            epoch: small(f.uint(4)?)?,
            by: f.fixed::<16>(5)?,
            at: f.uint(6)?,
            entry: f.bytes(7)?.to_vec(),
            signature: f.bytes(8)?.to_vec(),
            cosignature: f
                .get(9)
                .map(|v| v.as_bytes().map(<[u8]>::to_vec))
                .transpose()?,
            seals,
            names,
        };
        if wire.payload() != payload {
            return Err(FedError::Invalid("a chain record is not canonical"));
        }
        Ok(wire)
    }
}

impl<S: FedStore> Replica<S> {
    /// At the home of a space: makes a home record for each chain record not yet published.
    /// Returns how many. Does nothing for a personal vault or at a replica.
    pub async fn publish_chain(&self, vault: Owner) -> Result<usize> {
        let Owner::Space(space) = vault else {
            return Ok(0);
        };
        let Some(mut publisher) = self.publisher(vault).await? else {
            return Ok(0);
        };
        let published = publisher
            .live_keys(KIND)
            .iter()
            .filter_map(|key| <[u8; 8]>::try_from(key.as_slice()).ok())
            .map(u64::from_be_bytes)
            .max();
        let records = self.store.chain_records_after(space, published).await?;
        for record in records {
            self.publish(&mut publisher, KIND, record.payload()).await?;
        }
        Ok(publisher.made)
    }

    /// Applies a chain home record this server stored as applied: the replica keeps the record and
    /// what it committed, in order. A payload that doesn't parse is logged and left.
    pub(crate) async fn apply_chain_home_record(&self, vault: Owner, payload: &[u8]) {
        let Owner::Space(space) = vault else {
            return;
        };
        match ChainWire::from_payload(payload) {
            Ok(wire) => {
                if let Err(e) = self.store.apply_chain_record(space, &wire).await {
                    tracing::warn!(error = %e, seq = wire.seq, "a chain record could not be kept");
                }
            }
            Err(e) => tracing::warn!(error = %e, "a chain record is not valid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> ChainWire {
        ChainWire {
            seq: 7,
            link: [1; 32],
            epoch: 2,
            by: [3; 16],
            at: 1_800_000_000,
            entry: vec![4; 400],
            signature: vec![5; 3373],
            cosignature: Some(vec![6; 3373]),
            seals: vec![WireSeal {
                key: "space".to_owned(),
                version: 2,
                member: [7; 16],
                bundle_version: 1,
                sealed: vec![8; 1661],
            }],
            names: vec![WireName {
                target: "collection:00000000-0000-4000-8000-000000000001".to_owned(),
                version: 2,
                hash: [9; 32],
                sealed: vec![10; 40],
            }],
        }
    }

    #[test]
    fn a_chain_record_round_trips_and_is_named_by_its_seq() {
        let w = wire();
        let payload = w.payload();
        assert_eq!(ChainWire::from_payload(&payload).expect("parses"), w);
        assert_eq!(
            crate::publish::entity_key(&payload),
            Some(7u64.to_be_bytes().to_vec())
        );
        let mut plain = w;
        plain.cosignature = None;
        plain.seals.clear();
        plain.names.clear();
        assert_eq!(
            ChainWire::from_payload(&plain.payload()).expect("parses"),
            plain
        );
    }

    #[test]
    fn a_payload_that_names_another_seq_or_isnt_canonical_is_refused() {
        let mut w = wire();
        let payload = w.payload();
        w.seq = 8;
        // Key 1 still says 7 while key 2 says 8.
        let mismatched = {
            let value = Value::decode(&payload).expect("cbor");
            let f = value.as_fields().expect("map");
            let mut entries = vec![
                (0, Value::Uint(VERSION)),
                (1, Value::bytes(&7u64.to_be_bytes())),
                (2, Value::Uint(8)),
                (3, Value::bytes(&w.link)),
                (4, Value::Uint(2)),
                (5, Value::bytes(&w.by)),
                (6, Value::Uint(w.at)),
                (7, Value::bytes(&w.entry)),
                (8, Value::bytes(&w.signature)),
            ];
            let _ = f;
            entries.push((10, Value::Array(Vec::new())));
            entries.push((11, Value::Array(Vec::new())));
            Value::map(entries).encode()
        };
        assert!(ChainWire::from_payload(&mismatched).is_err());
        assert!(ChainWire::from_payload(&[0xff]).is_err());
        assert!(is_chain_kind(KIND) && !is_chain_kind("space"));
    }
}
