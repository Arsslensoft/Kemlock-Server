//! `KeyStore` on `SqlStore`: the signed key records to pass on, and the identity key pinned for a
//! peer.

use crate::convert::{from_i64, to_i64};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::federation::peers;
use crate::tables::federation_keys::{
    key_records, learned_keys, peer_held_rotations, peer_key_history, peer_pending_addresses,
};
use kemlock_app::ports::StoreError;
use kemlock_domain::ServerId;
use kemlock_federation::keyrecs::{
    HeldRotation, KeyStore, MAX_HELD_ROTATIONS, PastKey, PendingAddresses, StoredKeyRecord,
};
use kemlock_federation::relay::{LearnedKey, OriginKeys};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

/// One address change as the domain has it.
fn pending_of(row: peer_pending_addresses::Model) -> Result<PendingAddresses, StoreError> {
    let lines = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    Ok(PendingAddresses {
        peer: ServerId(row.peer),
        operator: row.operator,
        addresses: lines(&row.addresses),
        suites: lines(&row.suites),
        received_at: from_i64(row.received_at, "address change time")?,
    })
}

impl KeyStore for SqlStore {
    async fn put_key_record(&self, record: &StoredKeyRecord) -> Result<bool, StoreError> {
        let issued_at = to_i64(record.issued_at, "key record time")?;
        let held = key_records::Entity::find_by_id((record.server.0, record.kind.clone()))
            .one(self.writer())
            .await
            .store()?;
        match held {
            Some(row) if row.issued_at >= issued_at => Ok(false),
            Some(_) => {
                key_records::Entity::update_many()
                    .col_expr(key_records::Column::IssuedAt, Expr::value(issued_at))
                    .col_expr(
                        key_records::Column::Envelope,
                        Expr::value(record.envelope.clone()),
                    )
                    .filter(key_records::Column::Server.eq(record.server.0))
                    .filter(key_records::Column::Kind.eq(record.kind.clone()))
                    .exec(self.writer())
                    .await
                    .store()?;
                Ok(true)
            }
            None => {
                key_records::Entity::insert(key_records::ActiveModel {
                    server: Set(record.server.0),
                    kind: Set(record.kind.clone()),
                    issued_at: Set(issued_at),
                    envelope: Set(record.envelope.clone()),
                })
                .exec(self.writer())
                .await
                .store()?;
                Ok(true)
            }
        }
    }

    async fn key_records(&self) -> Result<Vec<StoredKeyRecord>, StoreError> {
        key_records::Entity::find()
            .order_by_asc(key_records::Column::Server)
            .order_by_asc(key_records::Column::Kind)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok::<StoredKeyRecord, StoreError>(StoredKeyRecord {
                    server: ServerId(row.server),
                    kind: row.kind,
                    issued_at: from_i64(row.issued_at, "key record time")?,
                    envelope: row.envelope,
                })
            })
            .collect()
    }

    async fn set_peer_identity(&self, peer: ServerId, key: &[u8]) -> Result<(), StoreError> {
        let updated = peers::Entity::update_many()
            .col_expr(peers::Column::IdentityKey, Expr::value(key.to_vec()))
            .filter(peers::Column::Id.eq(peer.0))
            .exec(self.writer())
            .await
            .store()?;
        if updated.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn past_keys(&self, peer: ServerId) -> Result<Vec<PastKey>, StoreError> {
        peer_key_history::Entity::find()
            .filter(peer_key_history::Column::Peer.eq(peer.0))
            .order_by_asc(peer_key_history::Column::Position)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok::<PastKey, StoreError>(PastKey {
                    key: row.identity_key,
                    replaced_at: from_i64(row.replaced_at, "key replacement time")?,
                })
            })
            .collect()
    }

    async fn push_past_key(
        &self,
        peer: ServerId,
        key: &[u8],
        replaced_at: u64,
    ) -> Result<(), StoreError> {
        let position = peer_key_history::Entity::find()
            .filter(peer_key_history::Column::Peer.eq(peer.0))
            .order_by_desc(peer_key_history::Column::Position)
            .one(self.writer())
            .await
            .store()?
            .map_or(0, |last| last.position + 1);
        peer_key_history::Entity::insert(peer_key_history::ActiveModel {
            peer: Set(peer.0),
            position: Set(position),
            identity_key: Set(key.to_vec()),
            replaced_at: Set(to_i64(replaced_at, "key replacement time")?),
        })
        .exec(self.writer())
        .await
        .store()?;
        Ok(())
    }

    async fn put_pending_addresses(&self, pending: &PendingAddresses) -> Result<(), StoreError> {
        peer_pending_addresses::Entity::delete_by_id(pending.peer.0)
            .exec(self.writer())
            .await
            .store()?;
        peer_pending_addresses::Entity::insert(peer_pending_addresses::ActiveModel {
            peer: Set(pending.peer.0),
            operator: Set(pending.operator.chars().take(128).collect()),
            addresses: Set(pending.addresses.join("\n")),
            suites: Set(pending.suites.join("\n")),
            received_at: Set(to_i64(pending.received_at, "address change time")?),
        })
        .exec(self.writer())
        .await
        .store()?;
        Ok(())
    }

    async fn pending_addresses(
        &self,
        peer: ServerId,
    ) -> Result<Option<PendingAddresses>, StoreError> {
        peer_pending_addresses::Entity::find_by_id(peer.0)
            .one(self.reader())
            .await
            .store()?
            .map(pending_of)
            .transpose()
    }

    async fn list_pending_addresses(&self) -> Result<Vec<PendingAddresses>, StoreError> {
        peer_pending_addresses::Entity::find()
            .order_by_asc(peer_pending_addresses::Column::ReceivedAt)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(pending_of)
            .collect()
    }

    async fn clear_pending_addresses(&self, peer: ServerId) -> Result<(), StoreError> {
        peer_pending_addresses::Entity::delete_by_id(peer.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn put_held_rotation(&self, held: &HeldRotation) -> Result<bool, StoreError> {
        let already =
            peer_held_rotations::Entity::find_by_id((held.server.0, held.fingerprint.clone()))
                .one(self.writer())
                .await
                .store()?
                .is_some();
        if already {
            return Ok(true);
        }
        let waiting = peer_held_rotations::Entity::find()
            .filter(peer_held_rotations::Column::Server.eq(held.server.0))
            .all(self.writer())
            .await
            .store()?
            .len();
        if waiting >= MAX_HELD_ROTATIONS {
            return Ok(false);
        }
        peer_held_rotations::Entity::insert(peer_held_rotations::ActiveModel {
            server: Set(held.server.0),
            fingerprint: Set(held.fingerprint.clone()),
            issued_at: Set(to_i64(held.issued_at, "rotation time")?),
            received_at: Set(to_i64(held.received_at, "rotation receipt time")?),
            envelope: Set(held.envelope.clone()),
        })
        .exec(self.writer())
        .await
        .store()?;
        Ok(true)
    }

    async fn held_rotations(&self) -> Result<Vec<HeldRotation>, StoreError> {
        peer_held_rotations::Entity::find()
            .order_by_asc(peer_held_rotations::Column::ReceivedAt)
            .order_by_asc(peer_held_rotations::Column::Server)
            .order_by_asc(peer_held_rotations::Column::Fingerprint)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok::<HeldRotation, StoreError>(HeldRotation {
                    server: ServerId(row.server),
                    fingerprint: row.fingerprint,
                    issued_at: from_i64(row.issued_at, "rotation time")?,
                    received_at: from_i64(row.received_at, "rotation receipt time")?,
                    envelope: row.envelope,
                })
            })
            .collect()
    }

    async fn drop_held_rotations(&self, server: ServerId) -> Result<(), StoreError> {
        peer_held_rotations::Entity::delete_many()
            .filter(peer_held_rotations::Column::Server.eq(server.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}

impl OriginKeys for SqlStore {
    async fn put_learned_key(&self, key: &LearnedKey) -> Result<(), StoreError> {
        let learned_at = to_i64(key.learned_at, "learned key time")?;
        let held = learned_keys::Entity::find_by_id(key.server.0)
            .one(self.writer())
            .await
            .store()?
            .is_some();
        if held {
            learned_keys::Entity::update_many()
                .col_expr(
                    learned_keys::Column::IdentityKey,
                    Expr::value(key.key.clone()),
                )
                .col_expr(learned_keys::Column::Via, Expr::value(key.via.0))
                .col_expr(learned_keys::Column::LearnedAt, Expr::value(learned_at))
                .filter(learned_keys::Column::Server.eq(key.server.0))
                .exec(self.writer())
                .await
                .store()?;
        } else {
            learned_keys::Entity::insert(learned_keys::ActiveModel {
                server: Set(key.server.0),
                identity_key: Set(key.key.clone()),
                via: Set(key.via.0),
                learned_at: Set(learned_at),
            })
            .exec(self.writer())
            .await
            .store()?;
        }
        Ok(())
    }

    async fn learned_keys(&self) -> Result<Vec<LearnedKey>, StoreError> {
        learned_keys::Entity::find()
            .order_by_asc(learned_keys::Column::Server)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok::<LearnedKey, StoreError>(LearnedKey {
                    server: ServerId(row.server),
                    key: row.identity_key,
                    via: ServerId(row.via),
                    learned_at: from_i64(row.learned_at, "learned key time")?,
                })
            })
            .collect()
    }

    async fn remove_learned_key(&self, server: ServerId) -> Result<(), StoreError> {
        learned_keys::Entity::delete_many()
            .filter(learned_keys::Column::Server.eq(server.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
