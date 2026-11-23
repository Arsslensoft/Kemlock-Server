//! `KeyStore` on `SqlStore`: the signed key records to pass on, and the identity key pinned for a
//! peer.

use crate::convert::{from_i64, to_i64};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::federation::peers;
use crate::tables::federation_keys::{key_records, learned_keys};
use kemlock_app::ports::StoreError;
use kemlock_domain::ServerId;
use kemlock_federation::keyrecs::{KeyStore, StoredKeyRecord};
use kemlock_federation::relay::{LearnedKey, OriginKeys};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

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
