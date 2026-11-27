//! `EventSync` on `SqlStore`: the events of a federated vault's members, read from `events`, and
//! the entries a peer sent, kept in `peer_events`.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::admin::event_rows;
use crate::tables::federation_logs::peer_events;
use crate::tables::items::owner_parts;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Owner, ServerId};
use kemlock_federation::eventsync::{EventSync, LogEntry, MAX_ACTION, MAX_TARGET, PeerEvent};
use kemlock_federation::extra::MemberStore;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use uuid::Uuid;

/// The most events kept from one peer for one vault: past it the oldest go, so a peer that sends
/// events without end can't fill the disk. The cursor is the newest id, which stays.
pub const MAX_PEER_EVENTS: u64 = 10_000;

fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn entry_of(row: event_rows::Model) -> LogEntry {
    LogEntry {
        id: *row.id.as_bytes(),
        at_ms: u64::try_from(row.at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
        actor: row.actor.map(|u| *u.as_bytes()),
        device: row.device.map(|u| *u.as_bytes()),
        action: cut(&row.action, MAX_ACTION),
        target: row.target.map(|t| cut(&t, MAX_TARGET)),
    }
}

impl EventSync for SqlStore {
    async fn vault_events(
        &self,
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    ) -> Result<Vec<LogEntry>, StoreError> {
        let members: Vec<Uuid> = MemberStore::member_ids(self, vault)
            .await?
            .into_iter()
            .map(|u| u.0)
            .collect();
        if members.is_empty() {
            return Ok(Vec::new());
        }
        Ok(event_rows::Entity::find()
            .filter(event_rows::Column::Actor.is_in(members))
            .filter(event_rows::Column::Id.gt(Uuid::from_bytes(after)))
            .order_by_asc(event_rows::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(entry_of)
            .collect())
    }

    async fn store_peer_events(
        &self,
        peer: ServerId,
        vault: Owner,
        events: &[LogEntry],
    ) -> Result<usize, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let mut new = 0;
        for e in events {
            let id = Uuid::from_bytes(e.id);
            let held = peer_events::Entity::find_by_id((peer.0, owner_type, owner_id, id))
                .one(self.writer())
                .await
                .store()?
                .is_some();
            if held {
                continue;
            }
            peer_events::Entity::insert(peer_events::ActiveModel {
                peer: Set(peer.0),
                owner_type: Set(owner_type),
                owner_id: Set(owner_id),
                id: Set(id),
                at_ms: Set(i64::try_from(e.at_ms).unwrap_or(i64::MAX)),
                actor: Set(e.actor.map(Uuid::from_bytes)),
                device: Set(e.device.map(Uuid::from_bytes)),
                action: Set(cut(&e.action, MAX_ACTION)),
                target: Set(e.target.as_deref().map(|t| cut(t, MAX_TARGET))),
            })
            .exec(self.writer())
            .await
            .store()?;
            new += 1;
        }
        if new > 0 {
            // The oldest beyond the newest `MAX_PEER_EVENTS` go.
            let oldest_kept = peer_events::Entity::find()
                .filter(peer_events::Column::Peer.eq(peer.0))
                .filter(peer_events::Column::OwnerType.eq(owner_type))
                .filter(peer_events::Column::OwnerId.eq(owner_id))
                .order_by_desc(peer_events::Column::Id)
                .offset(MAX_PEER_EVENTS)
                .one(self.writer())
                .await
                .store()?;
            if let Some(row) = oldest_kept {
                peer_events::Entity::delete_many()
                    .filter(peer_events::Column::Peer.eq(peer.0))
                    .filter(peer_events::Column::OwnerType.eq(owner_type))
                    .filter(peer_events::Column::OwnerId.eq(owner_id))
                    .filter(peer_events::Column::Id.lte(row.id))
                    .exec(self.writer())
                    .await
                    .store()?;
            }
        }
        Ok(new)
    }

    async fn peer_events_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
    ) -> Result<[u8; 16], StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let newest = peer_events::Entity::find()
            .filter(peer_events::Column::Peer.eq(peer.0))
            .filter(peer_events::Column::OwnerType.eq(owner_type))
            .filter(peer_events::Column::OwnerId.eq(owner_id))
            .order_by_desc(peer_events::Column::Id)
            .one(self.reader())
            .await
            .store()?;
        Ok(newest.map_or([0; 16], |row| *row.id.as_bytes()))
    }

    async fn peer_events(&self, vault: Owner, limit: u32) -> Result<Vec<PeerEvent>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        Ok(peer_events::Entity::find()
            .filter(peer_events::Column::OwnerType.eq(owner_type))
            .filter(peer_events::Column::OwnerId.eq(owner_id))
            .order_by_desc(peer_events::Column::AtMs)
            .order_by_desc(peer_events::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| PeerEvent {
                from: ServerId(row.peer),
                vault,
                entry: LogEntry {
                    id: *row.id.as_bytes(),
                    at_ms: u64::try_from(row.at_ms).unwrap_or(0),
                    actor: row.actor.map(|u| *u.as_bytes()),
                    device: row.device.map(|u| *u.as_bytes()),
                    action: row.action,
                    target: row.target,
                },
            })
            .collect())
    }

    async fn forget_peer_events(&self, peer: ServerId) -> Result<u64, StoreError> {
        let result = peer_events::Entity::delete_many()
            .filter(peer_events::Column::Peer.eq(peer.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}
