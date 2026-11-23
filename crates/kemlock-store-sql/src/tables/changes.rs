//! `changes`: the change log. Every accepted write appends one row, so federation can replay
//! this server's changes to a peer later without a migration of `items`.

use crate::convert::{to_i64, utc};
use crate::tables::items::owner_parts;
use kemlock_app::ports::StoreError;
use kemlock_domain::Item;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "changes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub origin: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub seq: i64,
    pub hlc: i64,
    pub item_id: Uuid,
    pub owner_type: i16,
    pub owner_id: Uuid,
    pub revision: i64,
    /// Whether the change deleted the item.
    pub deleted: bool,
    pub at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The log entry for the write that produced `item`.
pub(crate) fn active(item: &Item) -> Result<ActiveModel, StoreError> {
    let (owner_type, owner_id) = owner_parts(item.owner);
    Ok(ActiveModel {
        origin: Set(item.change.origin.0),
        seq: Set(to_i64(item.change.seq, "sequence number")?),
        hlc: Set(to_i64(item.change.hlc.0, "hlc")?),
        item_id: Set(item.id.0),
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        revision: Set(to_i64(item.revision.0, "revision")?),
        deleted: Set(item.is_tombstone()),
        at: Set(utc(item.updated_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{
        ChangeId, Hlc, ItemFormat, ItemId, ItemKind, Owner, Revision, ServerId, UserId,
    };
    use time::macros::datetime;

    #[test]
    fn a_tombstone_logs_as_deleted() {
        let item = Item {
            id: ItemId::random(),
            owner: Owner::User(UserId::random()),
            kind: ItemKind::try_from("login".to_owned()).expect("valid kind"),
            format: ItemFormat::Bw,
            revision: Revision(4),
            key_version: 1,
            ciphertext: None,
            item_key: None,
            deleted_at: Some(datetime!(2026-01-02 03:04:05 UTC)),
            updated_at: datetime!(2026-01-02 03:04:05 UTC),
            change: ChangeId {
                origin: ServerId::random(),
                seq: 5,
                hlc: Hlc(6),
            },
        };
        let row = active(&item).expect("fits");
        assert_eq!(row.deleted, Set(true));
        assert_eq!(row.seq, Set(5));
        assert_eq!(row.revision, Set(4));
        assert_eq!(row.item_id, Set(item.id.0));
    }
}
