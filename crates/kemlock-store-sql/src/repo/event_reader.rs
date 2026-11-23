//! `EventReader` on `events`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::events;
use kemlock_app::event_reader::{EventMatch, EventQuery, EventReader, StoredEvent};
use kemlock_app::ports::StoreError;
use kemlock_domain::{DeviceId, UserId};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect};

fn condition(query: &EventQuery) -> Condition {
    let mut all = Condition::all()
        .add(events::Column::Action.eq(query.action.as_str()))
        .add(events::Column::At.gte(utc(query.from)))
        .add(events::Column::At.lte(utc(query.to)));
    for text in &query.target_all {
        all = all.add(events::Column::Target.contains(text.as_str()));
    }
    if !query.any.is_empty() {
        let mut any = Condition::any();
        for way in &query.any {
            any = match way {
                EventMatch::Target(text) => any.add(events::Column::Target.contains(text.as_str())),
                EventMatch::Actor(user) => any.add(events::Column::Actor.eq(user.0)),
            };
        }
        all = all.add(any);
    }
    all
}

impl EventReader for SqlStore {
    async fn read_events(&self, query: &EventQuery) -> Result<Vec<StoredEvent>, StoreError> {
        let rows = events::Entity::find()
            .filter(condition(query))
            .order_by_desc(events::Column::At)
            .order_by_desc(events::Column::Id)
            .limit(u64::from(query.limit))
            .all(self.reader())
            .await
            .store()?;
        Ok(rows
            .into_iter()
            .map(|row| StoredEvent {
                id: row.id,
                actor: row.actor.map(UserId),
                device: row.device.map(DeviceId),
                action: row.action,
                target: row.target,
                at: row.at,
                ip: row.ip,
            })
            .collect())
    }
}
