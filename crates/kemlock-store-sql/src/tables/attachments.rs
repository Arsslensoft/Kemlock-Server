//! `attachments`: the files attached to items, as `kemlock_domain::Attachment`. The bytes are in
//! blob storage under `blob_id`.

use super::items::{owner_from, owner_parts};
use crate::convert::{corrupt, from_i64, to_i64, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Attachment, AttachmentId, AttachmentStatus, BlobId, ItemId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "attachments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The item the file belongs to; the item may not be stored yet.
    pub item_id: Uuid,
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    pub owner_type: i16,
    pub owner_id: Uuid,
    /// The random id the bytes are stored under.
    pub blob_id: Uuid,
    pub size: i64,
    /// `pending` or `ready`.
    pub status: String,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) const PENDING: &str = "pending";
pub(crate) const READY: &str = "ready";

fn status_from(s: &str) -> Result<AttachmentStatus, StoreError> {
    match s {
        PENDING => Ok(AttachmentStatus::Pending),
        READY => Ok(AttachmentStatus::Ready),
        _ => Err(corrupt("attachment status")),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Attachment, StoreError> {
        Ok(Attachment {
            id: AttachmentId(self.id),
            item: ItemId(self.item_id),
            owner: owner_from(self.owner_type, self.owner_id)?,
            blob: BlobId::from_uuid(self.blob_id),
            size: from_i64(self.size, "attachment size")?,
            status: status_from(&self.status)?,
            created_at: self.created_at,
        })
    }
}

pub(crate) fn active(attachment: &Attachment) -> Result<ActiveModel, StoreError> {
    let (owner_type, owner_id) = owner_parts(attachment.owner);
    Ok(ActiveModel {
        id: Set(attachment.id.0),
        item_id: Set(attachment.item.0),
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        blob_id: Set(attachment.blob.to_uuid()),
        size: Set(to_i64(attachment.size, "attachment size")?),
        status: Set(attachment.status.as_str().to_owned()),
        created_at: Set(utc(attachment.created_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{Owner, SpaceId, UserId};
    use time::macros::datetime;

    fn sample(owner: Owner, status: AttachmentStatus) -> Attachment {
        Attachment {
            id: AttachmentId::random(),
            item: ItemId::random(),
            owner,
            blob: BlobId::random(),
            size: 65_680,
            status,
            created_at: datetime!(2026-01-02 03:04:05 UTC),
        }
    }

    fn model_of(a: &Attachment) -> Model {
        let (owner_type, owner_id) = owner_parts(a.owner);
        Model {
            id: a.id.0,
            item_id: a.item.0,
            owner_type,
            owner_id,
            blob_id: a.blob.to_uuid(),
            size: 65_680,
            status: a.status.as_str().to_owned(),
            created_at: a.created_at,
        }
    }

    #[test]
    fn an_attachment_survives_the_trip_through_a_row() {
        for (owner, status) in [
            (Owner::User(UserId::random()), AttachmentStatus::Pending),
            (Owner::Space(SpaceId::random()), AttachmentStatus::Ready),
        ] {
            let a = sample(owner, status);
            assert_eq!(model_of(&a).into_domain(), Ok(a));
        }
    }

    #[test]
    fn the_row_names_the_blob_by_its_uuid_and_the_status_as_text() {
        let a = sample(Owner::User(UserId::random()), AttachmentStatus::Ready);
        let row = active(&a).expect("fits");
        assert_eq!(row.blob_id, Set(a.blob.to_uuid()));
        assert_eq!(row.status, Set("ready".to_owned()));
        assert_eq!(row.size, Set(65_680));
    }

    #[test]
    fn times_are_stored_in_utc() {
        let mut a = sample(Owner::User(UserId::random()), AttachmentStatus::Pending);
        a.created_at = datetime!(2026-01-02 03:04:05 +02:00);
        assert_eq!(
            active(&a).expect("fits").created_at,
            Set(datetime!(2026-01-02 01:04:05 UTC))
        );
    }

    #[test]
    fn unknown_statuses_sizes_and_owners_are_refused() {
        let a = sample(Owner::User(UserId::random()), AttachmentStatus::Ready);
        let mut row = model_of(&a);
        row.status = "uploading".to_owned();
        assert!(row.into_domain().is_err());
        let mut row = model_of(&a);
        row.size = -1;
        assert!(row.into_domain().is_err());
        let mut row = model_of(&a);
        row.owner_type = 9;
        assert!(row.into_domain().is_err());
    }

    #[test]
    fn a_size_beyond_a_signed_column_is_refused() {
        let mut a = sample(Owner::User(UserId::random()), AttachmentStatus::Ready);
        a.size = u64::MAX;
        assert!(active(&a).is_err());
    }
}
