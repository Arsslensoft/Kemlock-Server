//! `PushRepo` on `push_tokens` and `settings`, and `NudgeLog` on `live_nudges`.
//!
//! The relay installation is two `settings` rows: `push.installation.id` and
//! `push.installation.key` (the key sealed under `server.key`, as hex).

use crate::convert::{corrupt, utc};
use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::items::{owner_from, owner_parts};
use crate::tables::{live_nudges, push_tokens, settings};
use kemlock_app::ports::StoreError;
use kemlock_app::push::{NudgeEntry, NudgeLog, PushInstallation, PushRegistration, PushRepo};
use kemlock_domain::{DeviceId, Owner, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use time::OffsetDateTime;

const INSTALLATION_ID: &str = "push.installation.id";
const INSTALLATION_KEY: &str = "push.installation.key";

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String can't fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

async fn put_setting<C: sea_orm::ConnectionTrait>(
    db: &C,
    key: &str,
    value: String,
) -> Result<(), StoreError> {
    let row = settings::ActiveModel {
        key: Set(key.to_owned()),
        value: Set(value),
    };
    let conflict = OnConflict::column(settings::Column::Key)
        .update_column(settings::Column::Value)
        .to_owned();
    match settings::Entity::insert(row)
        .on_conflict(conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(err) => Err(map_db(err)),
    }
}

impl PushRepo for SqlStore {
    async fn put_registration(&self, registration: &PushRegistration) -> Result<(), StoreError> {
        let conflict = OnConflict::column(push_tokens::Column::DeviceId)
            .update_columns([
                push_tokens::Column::UserId,
                push_tokens::Column::Kind,
                push_tokens::Column::Token,
                push_tokens::Column::UpdatedAt,
            ])
            .to_owned();
        // A device that doesn't exist is `NotFound` (the foreign key refuses the row).
        match push_tokens::Entity::insert(push_tokens::active(registration))
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            // MySQL counts a replaced row with identical values as zero rows affected.
            Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn remove_registration(&self, device: DeviceId) -> Result<(), StoreError> {
        push_tokens::Entity::delete_many()
            .filter(push_tokens::Column::DeviceId.eq(device.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn registrations_for(
        &self,
        users: &[UserId],
    ) -> Result<Vec<PushRegistration>, StoreError> {
        if users.is_empty() {
            return Ok(Vec::new());
        }
        push_tokens::Entity::find()
            .filter(push_tokens::Column::UserId.is_in(users.iter().map(|u| u.0)))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(push_tokens::Model::into_domain)
            .collect()
    }

    async fn installation(&self) -> Result<Option<PushInstallation>, StoreError> {
        let id = settings::Entity::find_by_id(INSTALLATION_ID.to_owned())
            .one(self.reader())
            .await
            .store()?;
        let key = settings::Entity::find_by_id(INSTALLATION_KEY.to_owned())
            .one(self.reader())
            .await
            .store()?;
        match (id, key) {
            (Some(id), Some(key)) => Ok(Some(PushInstallation {
                id: id.value,
                sealed_key: from_hex(&key.value).ok_or_else(|| corrupt("installation key"))?,
            })),
            _ => Ok(None),
        }
    }

    async fn set_installation(&self, installation: &PushInstallation) -> Result<(), StoreError> {
        let txn = self.writer().begin().await.store()?;
        put_setting(&txn, INSTALLATION_ID, installation.id.clone()).await?;
        put_setting(&txn, INSTALLATION_KEY, to_hex(&installation.sealed_key)).await?;
        txn.commit().await.store()
    }

    async fn clear_installation(&self) -> Result<(), StoreError> {
        settings::Entity::delete_many()
            .filter(settings::Column::Key.is_in([INSTALLATION_ID, INSTALLATION_KEY]))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}

impl NudgeLog for SqlStore {
    async fn append_nudge(&self, owner: Owner) -> Result<i64, StoreError> {
        let (owner_type, owner_id) = owner_parts(owner);
        let inserted = live_nudges::Entity::insert(live_nudges::ActiveModel {
            id: NotSet,
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            created_at: Set(utc(OffsetDateTime::now_utc())),
        })
        .exec(self.writer())
        .await
        .store()?;
        Ok(inserted.last_insert_id)
    }

    async fn nudges_since(&self, after: i64, limit: u32) -> Result<Vec<NudgeEntry>, StoreError> {
        live_nudges::Entity::find()
            .filter(live_nudges::Column::Id.gt(after))
            .order_by_asc(live_nudges::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| {
                Ok(NudgeEntry {
                    id: row.id,
                    owner: owner_from(row.owner_type, row.owner_id)?,
                })
            })
            .collect()
    }

    async fn latest_nudge(&self) -> Result<i64, StoreError> {
        Ok(live_nudges::Entity::find()
            .order_by_desc(live_nudges::Column::Id)
            .one(self.reader())
            .await
            .store()?
            .map_or(0, |row| row.id))
    }

    async fn prune_nudges(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        let result = live_nudges::Entity::delete_many()
            .filter(live_nudges::Column::CreatedAt.lt(utc(before)))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_garbage() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(to_hex(&bytes), "0001abff");
        assert_eq!(from_hex("0001abff"), Some(bytes.to_vec()));
        assert_eq!(from_hex(""), Some(Vec::new()));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("é1"), None);
    }
}
