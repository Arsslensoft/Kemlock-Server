//! `items`: the latest revision of every item (or its tombstone), as `kemlock_domain::Item`.
//!
//! The row carries the change that wrote it (`origin`, `seq`, `hlc`), so a delta sync is one
//! indexed read of this table; the full history of changes is in `changes`.

use crate::convert::{corrupt, from_i64, from_i64_u32, to_i64, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{
    ChangeId, Hlc, Item, ItemFormat, ItemId, ItemKind, Owner, Revision, ServerId, SpaceId, UserId,
};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "items")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    pub owner_type: i16,
    pub owner_id: Uuid,
    pub kind: String,
    /// `kem1` or `bw`.
    pub format: String,
    pub revision: i64,
    pub key_version: i64,
    /// Absent on a tombstone.
    pub ciphertext: Option<Vec<u8>>,
    pub item_key: Option<Vec<u8>>,
    pub deleted_at: Option<TimeDateTimeWithTimeZone>,
    pub updated_at: TimeDateTimeWithTimeZone,
    pub origin: Uuid,
    pub seq: i64,
    pub hlc: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The two columns that name an owner.
pub(crate) fn owner_parts(owner: Owner) -> (i16, Uuid) {
    match owner {
        Owner::User(user) => (i16::from(Owner::TYPE_USER), user.0),
        Owner::Space(space) => (i16::from(Owner::TYPE_SPACE), space.0),
    }
}

pub(crate) fn owner_from(owner_type: i16, owner_id: Uuid) -> Result<Owner, StoreError> {
    if owner_type == i16::from(Owner::TYPE_USER) {
        Ok(Owner::User(UserId(owner_id)))
    } else if owner_type == i16::from(Owner::TYPE_SPACE) {
        Ok(Owner::Space(SpaceId(owner_id)))
    } else {
        Err(corrupt("owner type"))
    }
}

fn format_from(s: &str) -> Result<ItemFormat, StoreError> {
    match s {
        "kem1" => Ok(ItemFormat::Kem1),
        "bw" => Ok(ItemFormat::Bw),
        _ => Err(corrupt("item format")),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Item, StoreError> {
        Ok(Item {
            id: ItemId(self.id),
            owner: owner_from(self.owner_type, self.owner_id)?,
            kind: ItemKind::try_from(self.kind).map_err(|_| corrupt("item kind"))?,
            format: format_from(&self.format)?,
            revision: Revision(from_i64(self.revision, "revision")?),
            key_version: from_i64_u32(self.key_version, "key version")?,
            ciphertext: self.ciphertext,
            item_key: self.item_key,
            deleted_at: self.deleted_at,
            updated_at: self.updated_at,
            change: ChangeId {
                origin: ServerId(self.origin),
                seq: from_i64(self.seq, "sequence number")?,
                hlc: Hlc(from_i64(self.hlc, "hlc")?),
            },
            signature: None,
        })
    }
}

/// Every column set, the id included: fit for an insert. An update of the same item drops the
/// id with `ActiveModel { id: NotSet, ..active(item)? }`.
pub(crate) fn active(item: &Item) -> Result<ActiveModel, StoreError> {
    let (owner_type, owner_id) = owner_parts(item.owner);
    Ok(ActiveModel {
        id: Set(item.id.0),
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        kind: Set(item.kind.as_str().to_owned()),
        format: Set(item.format.as_str().to_owned()),
        revision: Set(to_i64(item.revision.0, "revision")?),
        key_version: Set(i64::from(item.key_version)),
        ciphertext: Set(item.ciphertext.clone()),
        item_key: Set(item.item_key.clone()),
        deleted_at: Set(item.deleted_at.map(utc)),
        updated_at: Set(utc(item.updated_at)),
        origin: Set(item.change.origin.0),
        seq: Set(to_i64(item.change.seq, "sequence number")?),
        hlc: Set(to_i64(item.change.hlc.0, "hlc")?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample(owner: Owner) -> Item {
        Item {
            id: ItemId::random(),
            owner,
            kind: ItemKind::try_from("login".to_owned()).expect("valid kind"),
            format: ItemFormat::Kem1,
            revision: Revision(3),
            key_version: 1,
            ciphertext: Some(vec![1; 40]),
            item_key: Some(vec![2; 60]),
            deleted_at: None,
            updated_at: datetime!(2026-01-02 03:04:05 UTC),
            change: ChangeId {
                origin: ServerId::random(),
                seq: 12,
                hlc: Hlc::from_parts(1_700_000_000_000, 3),
            },
            signature: None,
        }
    }

    fn model_of(item: &Item) -> Model {
        let (owner_type, owner_id) = owner_parts(item.owner);
        Model {
            id: item.id.0,
            owner_type,
            owner_id,
            kind: item.kind.as_str().to_owned(),
            format: item.format.as_str().to_owned(),
            revision: 3,
            key_version: 1,
            ciphertext: item.ciphertext.clone(),
            item_key: item.item_key.clone(),
            deleted_at: item.deleted_at,
            updated_at: item.updated_at,
            origin: item.change.origin.0,
            seq: 12,
            hlc: i64::try_from(item.change.hlc.0).expect("fits"),
        }
    }

    #[test]
    fn owners_round_trip() {
        for owner in [
            Owner::User(UserId::random()),
            Owner::Space(SpaceId::random()),
        ] {
            let (t, id) = owner_parts(owner);
            assert_eq!(owner_from(t, id), Ok(owner));
        }
        assert!(owner_from(9, Uuid::nil()).is_err());
    }

    #[test]
    fn an_item_survives_the_trip_through_a_row() {
        let item = sample(Owner::User(UserId::random()));
        assert_eq!(model_of(&item).into_domain(), Ok(item));
    }

    #[test]
    fn a_tombstone_has_no_ciphertext() {
        let mut item = sample(Owner::Space(SpaceId::random()));
        item.ciphertext = None;
        item.item_key = None;
        item.deleted_at = Some(datetime!(2026-02-02 03:04:05 UTC));
        let back = model_of(&item).into_domain().expect("valid row");
        assert!(back.is_tombstone());
        assert_eq!(active(&item).expect("fits").ciphertext, Set(None));
    }

    #[test]
    fn unknown_formats_and_kinds_are_refused() {
        let mut model = model_of(&sample(Owner::User(UserId::random())));
        model.format = "xml".to_owned();
        assert!(model.clone().into_domain().is_err());
        model.format = "bw".to_owned();
        model.kind = "Not Valid".to_owned();
        assert!(model.into_domain().is_err());
    }
}
