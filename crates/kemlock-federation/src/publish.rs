//! Writing home records at a vault's home.
//!
//! A home record is one home-only write on its way to the replicas. The home keeps, for each
//! (kind, entity) pair, the payload it last published, and makes a new record only when the
//! payload changed; the entity is named by the byte string under key 1 of every payload (a user
//! id, a collection id, ...). Each record's index is [`home_index`] of the vault's epoch and the
//! next count within that epoch, so a home that was replaced and the one that replaced it never
//! make two records with one index.

use crate::cbor::Value;
use crate::error::Result;
use crate::home::{HomeRecord, MAX_PAYLOAD, Policy, VaultFederation, home_index, index_seq};
use crate::ports::{HomeStatus, StoredHomeRecord};
use crate::replicate::{FedStore, Replica};
use kemlock_domain::Owner;
use std::collections::HashMap;

/// The map key that marks a payload as "this entity is gone".
pub(crate) const GONE_KEY: u64 = 15;

/// The entity a payload is about: its key 1, a byte string.
pub(crate) fn entity_key(payload: &[u8]) -> Option<Vec<u8>> {
    let value = Value::decode(payload).ok()?;
    let fields = value.as_fields().ok()?;
    fields.bytes(1).ok().map(<[u8]>::to_vec)
}

/// Whether a payload says its entity is gone.
pub(crate) fn is_gone(payload: &[u8]) -> bool {
    Value::decode(payload)
        .ok()
        .and_then(|v| v.as_fields().ok().map(|f| f.get(GONE_KEY).is_some()))
        .unwrap_or(false)
}

/// Publishing for one vault, in one pass.
pub(crate) struct Publisher {
    settings: VaultFederation,
    next_seq: u64,
    /// The last applied payload of each (kind, entity).
    latest: HashMap<(String, Vec<u8>), Vec<u8>>,
    /// How many records this pass has made.
    pub(crate) made: usize,
}

impl Publisher {
    /// The entities of `kind` that have a live (not gone) record.
    pub(crate) fn live_keys(&self, kind: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for ((k, key), payload) in &self.latest {
            if k == kind && !is_gone(payload) {
                out.push(key.clone());
            }
        }
        out
    }
}

impl<S: FedStore> Replica<S> {
    /// Starts publishing for `vault`, or `None` unless this server is the home of a federated
    /// vault: a replica makes no home records.
    pub(crate) async fn publisher(&self, vault: Owner) -> Result<Option<Publisher>> {
        let Some(settings) = self.store.get_vault(vault).await? else {
            return Ok(None);
        };
        if settings.policy != Policy::Federated || settings.home != self.server_id() {
            return Ok(None);
        }
        let existing = self.store.home_records(vault, 0, u32::MAX).await?;
        let mut next_seq = 1;
        let mut latest = HashMap::new();
        for stored in &existing {
            if stored.record.epoch == settings.epoch {
                next_seq = next_seq.max(index_seq(stored.record.index) + 1);
            }
            if stored.status == HomeStatus::Applied
                && let Some(key) = entity_key(&stored.record.payload)
            {
                latest.insert(
                    (stored.record.kind.clone(), key),
                    stored.record.payload.clone(),
                );
            }
        }
        Ok(Some(Publisher {
            settings,
            next_seq,
            latest,
            made: 0,
        }))
    }

    /// Makes a home record of `kind` with `payload` unless the last one for that entity said the
    /// same. False when nothing was made.
    pub(crate) async fn publish(
        &self,
        publisher: &mut Publisher,
        kind: &str,
        payload: Vec<u8>,
    ) -> Result<bool> {
        let Some(key) = entity_key(&payload) else {
            return Ok(false);
        };
        if publisher.latest.get(&(kind.to_owned(), key.clone())) == Some(&payload) {
            return Ok(false);
        }
        if payload.len() > MAX_PAYLOAD {
            tracing::warn!(%kind, "a home record is too large to replicate");
            return Ok(false);
        }
        let record = HomeRecord {
            vault: publisher.settings.owner,
            index: home_index(publisher.settings.epoch, publisher.next_seq),
            epoch: publisher.settings.epoch,
            kind: kind.to_owned(),
            payload: payload.clone(),
            signer: self.server_id(),
        };
        let signed = record.sign(&self.identity().signing)?.encode();
        self.store
            .put_home_record(&StoredHomeRecord {
                signed,
                record,
                status: HomeStatus::Applied,
            })
            .await?;
        publisher.next_seq += 1;
        publisher.made += 1;
        publisher.latest.insert((kind.to_owned(), key), payload);
        Ok(true)
    }

    /// Makes one home record of `kind` for `vault` at its home. `None` at a server that is not the
    /// home. The payload must be a CBOR map with the entity's id as a byte string under key 1.
    pub async fn publish_home_record(
        &self,
        vault: Owner,
        kind: &str,
        payload: Vec<u8>,
    ) -> Result<Option<bool>> {
        let Some(mut publisher) = self.publisher(vault).await? else {
            return Ok(None);
        };
        Ok(Some(self.publish(&mut publisher, kind, payload).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(entity: u8, fill: u8, gone: bool) -> Vec<u8> {
        let mut entries = vec![
            (0, Value::Uint(1)),
            (1, Value::bytes(&[entity; 16])),
            (2, Value::bytes(&[fill])),
        ];
        if gone {
            entries.push((GONE_KEY, Value::flag(true)));
        }
        Value::map(entries).encode()
    }

    #[test]
    fn a_payload_names_its_entity_and_may_say_it_is_gone() {
        assert_eq!(entity_key(&payload(7, 1, false)), Some(vec![7; 16]));
        assert!(!is_gone(&payload(7, 1, false)));
        assert!(is_gone(&payload(7, 1, true)));
        assert_eq!(entity_key(&[0xff]), None);
        assert!(!is_gone(&[0xff]));
    }
}
