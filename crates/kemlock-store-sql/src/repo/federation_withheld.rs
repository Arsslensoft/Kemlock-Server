//! `Withholding` on `SqlStore`: the versions of a vault kept from one peer after an account
//! cancelled the changes waiting for it.

use crate::convert::{corrupt, from_i64, to_i64};
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::federation_wiring::federation_withheld as withheld;
use crate::tables::items::owner_parts;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Owner, ServerId, VersionVector};
use kemlock_federation::outbox::{Withheld, Withholding};
use sea_orm::sea_query::OnConflict;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

impl Withholding for SqlStore {
    async fn withheld(&self, peer: ServerId, vault: Owner) -> Result<Option<Withheld>, StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        // The writer, not the reader: a cancel must be seen by the very next pull.
        let Some(row) = withheld::Entity::find_by_id((peer.0, owner_type, owner_id))
            .one(self.writer())
            .await
            .store()?
        else {
            return Ok(None);
        };
        Ok(Some(Withheld {
            upto: VersionVector::from_cursor_bytes(&row.upto)
                .map_err(|_| corrupt("withheld cursor"))?,
            at: from_i64(row.at, "withheld time")?,
        }))
    }

    async fn withhold(
        &self,
        peer: ServerId,
        vault: Owner,
        upto: &VersionVector,
        at: u64,
    ) -> Result<(), StoreError> {
        let (owner_type, owner_id) = owner_parts(vault);
        let mut merged = self
            .withheld(peer, vault)
            .await?
            .map(|held| held.upto)
            .unwrap_or_default();
        merged.merge(upto);
        let row = withheld::ActiveModel {
            peer: Set(peer.0),
            owner_type: Set(owner_type),
            owner_id: Set(owner_id),
            upto: Set(merged.to_cursor_bytes()),
            at: Set(to_i64(at, "withheld time")?),
        };
        let conflict = OnConflict::columns([
            withheld::Column::Peer,
            withheld::Column::OwnerType,
            withheld::Column::OwnerId,
        ])
        .update_columns([withheld::Column::Upto, withheld::Column::At])
        .to_owned();
        withheld::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn forget_withheld(&self, peer: ServerId) -> Result<(), StoreError> {
        withheld::Entity::delete_many()
            .filter(withheld::Column::Peer.eq(peer.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
