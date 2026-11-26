//! `SendSync` on `SqlStore`: the Sends federation copies to a replica, as rows of `sends` with the
//! file's bytes in blob storage, and the marker of which rows are copies.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::federation_wiring::federation_replicated_sends as replicated;
use crate::tables::sends::{self, active, untouched};
use kemlock_app::ports::StoreError;
use kemlock_domain::sends::{SendId, SendRecord};
use kemlock_domain::{BlobId, Owner, ServerId};
use kemlock_federation::sendsync::{SendApply, SendSync};
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect};

impl SendSync for SqlStore {
    async fn sends_after(
        &self,
        owner: Owner,
        after: SendId,
        limit: u32,
        not_from: ServerId,
    ) -> Result<Vec<SendRecord>, StoreError> {
        let Owner::User(user) = owner else {
            return Ok(Vec::new());
        };
        // The copies that came from the asker: it holds the originals.
        let theirs: Vec<uuid::Uuid> = replicated::Entity::find()
            .filter(replicated::Column::FromServer.eq(not_from.0))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|m| m.send_id)
            .collect();
        let mut query = sends::Entity::find()
            .filter(sends::Column::OwnerId.eq(user.0))
            .filter(sends::Column::Id.gt(after.0));
        if !theirs.is_empty() {
            query = query.filter(sends::Column::Id.is_not_in(theirs));
        }
        query
            // A note, or a file Send whose bytes have arrived.
            .filter(
                Condition::any()
                    .add(sends::Column::FileBlobId.is_null())
                    .add(sends::Column::FileReady.eq(true)),
            )
            .order_by_asc(sends::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(sends::Model::into_domain)
            .collect()
    }

    async fn send_of_blob(&self, blob: BlobId) -> Result<Option<SendRecord>, StoreError> {
        sends::Entity::find()
            .filter(sends::Column::FileBlobId.eq(blob.to_uuid()))
            .one(self.reader())
            .await
            .store()?
            .map(sends::Model::into_domain)
            .transpose()
    }

    async fn send_row(&self, id: SendId) -> Result<Option<SendRecord>, StoreError> {
        sends::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?
            .map(sends::Model::into_domain)
            .transpose()
    }

    async fn apply_replicated_send(
        &self,
        from: ServerId,
        send: &SendRecord,
    ) -> Result<SendApply, StoreError> {
        let held = sends::Entity::find_by_id(send.id.0)
            .one(self.writer())
            .await
            .store()?
            .map(sends::Model::into_domain)
            .transpose()?;
        let Some(held) = held else {
            match sends::Entity::insert(active(send)?)
                .exec(self.writer())
                .await
            {
                Ok(_) => {}
                // Another visit added it first.
                Err(err) if is_unique_violation(&err) => return Ok(SendApply::Unchanged),
                Err(err) => return Err(map_db(err)),
            }
            let mark = replicated::ActiveModel {
                send_id: Set(send.id.0),
                from_server: Set(from.0),
            };
            match replicated::Entity::insert(mark).exec(self.writer()).await {
                Ok(_) => {}
                Err(err) if is_unique_violation(&err) => {}
                Err(err) => return Err(map_db(err)),
            }
            return Ok(SendApply::Added);
        };
        if held.owner != send.owner {
            return Ok(SendApply::Unchanged);
        }
        // Only the server a copy came from may change it. A Send made here has no such mark, and a
        // copy from one peer isn't for another peer to rewrite (its password, view limit, expiry,
        // deletion date): both stay as they are.
        let copied_from = replicated::Entity::find_by_id(send.id.0)
            .one(self.writer())
            .await
            .store()?
            .map(|mark| mark.from_server);
        if copied_from != Some(from.0) {
            return Ok(SendApply::Unchanged);
        }
        let newer = send.revised_at > held.revised_at;
        let more_views = send.access_count > held.access_count;
        if !newer && !more_views {
            return Ok(SendApply::Unchanged);
        }
        let mut row = untouched();
        if newer {
            row.meta = Set(send.meta.clone());
            row.payload = Set(send.payload.clone());
            row.password_salt = Set(send.password.as_ref().map(|p| p.salt.clone()));
            row.password_hash = Set(send.password.as_ref().map(|p| p.hash.clone()));
            row.max_access = Set(send.max_access.map(i64::from));
            row.hide_email = Set(send.hide_email);
            row.disabled = Set(send.disabled);
            row.expires_at = Set(send.expires_at.map(utc));
            row.deletion_at = Set(utc(send.deletion_at));
            row.revised_at = Set(utc(send.revised_at));
        }
        if more_views {
            row.access_count = Set(i64::from(send.access_count));
        }
        sends::Entity::update_many()
            .set(row)
            .filter(sends::Column::Id.eq(send.id.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(SendApply::Updated)
    }

    async fn replicated_send_ids(
        &self,
        owner: Owner,
        from: ServerId,
    ) -> Result<Vec<SendId>, StoreError> {
        let Owner::User(user) = owner else {
            return Ok(Vec::new());
        };
        let marked: Vec<uuid::Uuid> = replicated::Entity::find()
            .filter(replicated::Column::FromServer.eq(from.0))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|m| m.send_id)
            .collect();
        if marked.is_empty() {
            return Ok(Vec::new());
        }
        Ok(sends::Entity::find()
            .filter(sends::Column::OwnerId.eq(user.0))
            .filter(sends::Column::Id.is_in(marked))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| SendId(row.id))
            .collect())
    }

    async fn drop_replicated_send(&self, id: SendId) -> Result<Option<BlobId>, StoreError> {
        let marked = replicated::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        if marked.rows_affected == 0 {
            // Not a copy: a Send made here is not ours to delete on a peer's say.
            return Ok(None);
        }
        let row = sends::Entity::find_by_id(id.0)
            .one(self.writer())
            .await
            .store()?;
        sends::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(row.and_then(|r| r.file_blob_id).map(BlobId::from_uuid))
    }
}
