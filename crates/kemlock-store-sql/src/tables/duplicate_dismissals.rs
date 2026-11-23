//! `duplicate_dismissals`: "Not duplicates" answers, with the group's item ids packed 16 bytes
//! each.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Dismissal, DismissalId, ItemId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "duplicate_dismissals")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    pub owner_type: i16,
    pub owner_id: Uuid,
    /// The group's items, 16 bytes each, sorted.
    pub item_ids: Vec<u8>,
    pub answered_by: Uuid,
    pub answered_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

fn pack(items: &[ItemId]) -> Vec<u8> {
    items.iter().flat_map(|i| *i.as_bytes()).collect()
}

fn unpack(bytes: &[u8]) -> Result<Vec<ItemId>, StoreError> {
    if !bytes.len().is_multiple_of(16) {
        return Err(corrupt("dismissed item ids"));
    }
    Ok(bytes
        .as_chunks::<16>()
        .0
        .iter()
        .map(|chunk| ItemId(Uuid::from_bytes(*chunk)))
        .collect())
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Dismissal, StoreError> {
        Ok(Dismissal {
            id: DismissalId(self.id),
            owner: super::items::owner_from(self.owner_type, self.owner_id)?,
            items: unpack(&self.item_ids)?,
            by: UserId(self.answered_by),
            at: self.answered_at,
        })
    }
}

/// Every column set: fit for an insert.
pub(crate) fn active(dismissal: &Dismissal) -> ActiveModel {
    let (owner_type, owner_id) = super::items::owner_parts(dismissal.owner);
    ActiveModel {
        id: Set(dismissal.id.0),
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        item_ids: Set(pack(&dismissal.items)),
        answered_by: Set(dismissal.by.0),
        answered_at: Set(utc(dismissal.at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::Owner;
    use time::macros::datetime;

    fn dismissal() -> Dismissal {
        Dismissal::new(
            Owner::User(UserId::random()),
            [ItemId::random(), ItemId::random(), ItemId::random()],
            UserId::random(),
            datetime!(2026-01-02 03:04:05 UTC),
        )
        .expect("three items")
    }

    #[test]
    fn items_pack_sixteen_bytes_each() {
        let d = dismissal();
        let packed = pack(&d.items);
        assert_eq!(packed.len(), 48);
        assert_eq!(unpack(&packed), Ok(d.items));
    }

    #[test]
    fn a_dismissal_survives_the_trip_through_a_row() {
        let d = dismissal();
        let Owner::User(user) = d.owner else {
            panic!("a vault owner");
        };
        let model = Model {
            id: d.id.0,
            owner_type: i16::from(Owner::TYPE_USER),
            owner_id: user.0,
            item_ids: pack(&d.items),
            answered_by: d.by.0,
            answered_at: d.at,
        };
        assert_eq!(model.into_domain(), Ok(d));
    }

    #[test]
    fn a_truncated_list_is_refused() {
        assert!(unpack(&[1; 17]).is_err());
        assert_eq!(unpack(&[]), Ok(Vec::new()));
    }
}
