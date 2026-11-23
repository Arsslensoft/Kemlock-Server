//! `sends`: Sends as `kemlock_domain::sends::SendRecord`. A file Send's bytes are in blob storage
//! under `file_blob_id`.

use crate::convert::{corrupt, from_i64, from_i64_u32, to_i64, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::sends::{SendFile, SendFileFormat, SendId, SendKind, SendPassword, SendRecord};
use kemlock_domain::{BlobId, UserId};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sends")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub owner_id: Uuid,
    /// Bitwarden's type number: 0 text, 1 file.
    pub kind: i16,
    /// The name and notes, sealed under the owner's key.
    pub meta: Vec<u8>,
    /// The Send's key, sealed under the owner's key.
    pub sealed_key: Vec<u8>,
    /// What a recipient opens.
    pub payload: Vec<u8>,
    pub file_blob_id: Option<Uuid>,
    pub file_size: Option<i64>,
    /// `kma1` or `opaque`.
    pub file_format: Option<String>,
    pub file_ready: bool,
    pub password_salt: Option<Vec<u8>>,
    pub password_hash: Option<Vec<u8>>,
    pub max_access: Option<i64>,
    pub access_count: i64,
    pub hide_email: bool,
    pub disabled: bool,
    pub expires_at: Option<TimeDateTimeWithTimeZone>,
    pub deletion_at: TimeDateTimeWithTimeZone,
    pub created_at: TimeDateTimeWithTimeZone,
    pub revised_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<SendRecord, StoreError> {
        let file = match (self.file_blob_id, self.file_size, self.file_format) {
            (Some(blob), Some(size), Some(format)) => Some(SendFile {
                blob: BlobId::from_uuid(blob),
                size: from_i64(size, "send file size")?,
                format: SendFileFormat::parse(&format)
                    .ok_or_else(|| corrupt("send file format"))?,
                ready: self.file_ready,
            }),
            (None, None, None) => None,
            _ => return Err(corrupt("send file")),
        };
        let password = match (self.password_salt, self.password_hash) {
            (Some(salt), Some(hash)) => Some(SendPassword { salt, hash }),
            (None, None) => None,
            _ => return Err(corrupt("send password")),
        };
        Ok(SendRecord {
            id: SendId(self.id),
            owner: UserId(self.owner_id),
            kind: SendKind::from_code(self.kind).ok_or_else(|| corrupt("send kind"))?,
            meta: self.meta,
            sealed_key: self.sealed_key,
            payload: self.payload,
            file,
            password,
            max_access: self
                .max_access
                .map(|n| from_i64_u32(n, "send view limit"))
                .transpose()?,
            access_count: from_i64_u32(self.access_count, "send view count")?,
            hide_email: self.hide_email,
            disabled: self.disabled,
            expires_at: self.expires_at,
            deletion_at: self.deletion_at,
            created_at: self.created_at,
            revised_at: self.revised_at,
        })
    }
}

/// An update that touches nothing: start from it and `Set` what changes.
pub(crate) fn untouched() -> ActiveModel {
    ActiveModel {
        id: NotSet,
        owner_id: NotSet,
        kind: NotSet,
        meta: NotSet,
        sealed_key: NotSet,
        payload: NotSet,
        file_blob_id: NotSet,
        file_size: NotSet,
        file_format: NotSet,
        file_ready: NotSet,
        password_salt: NotSet,
        password_hash: NotSet,
        max_access: NotSet,
        access_count: NotSet,
        hide_email: NotSet,
        disabled: NotSet,
        expires_at: NotSet,
        deletion_at: NotSet,
        created_at: NotSet,
        revised_at: NotSet,
    }
}

/// Every column set, the id included.
pub(crate) fn active(send: &SendRecord) -> Result<ActiveModel, StoreError> {
    Ok(ActiveModel {
        id: Set(send.id.0),
        owner_id: Set(send.owner.0),
        kind: Set(send.kind.code()),
        meta: Set(send.meta.clone()),
        sealed_key: Set(send.sealed_key.clone()),
        payload: Set(send.payload.clone()),
        file_blob_id: Set(send.file.map(|f| f.blob.to_uuid())),
        file_size: Set(send
            .file
            .map(|f| to_i64(f.size, "send file size"))
            .transpose()?),
        file_format: Set(send.file.map(|f| f.format.as_str().to_owned())),
        file_ready: Set(send.file.is_some_and(|f| f.ready)),
        password_salt: Set(send.password.as_ref().map(|p| p.salt.clone())),
        password_hash: Set(send.password.as_ref().map(|p| p.hash.clone())),
        max_access: Set(send.max_access.map(i64::from)),
        access_count: Set(i64::from(send.access_count)),
        hide_email: Set(send.hide_email),
        disabled: Set(send.disabled),
        expires_at: Set(send.expires_at.map(utc)),
        deletion_at: Set(utc(send.deletion_at)),
        created_at: Set(utc(send.created_at)),
        revised_at: Set(utc(send.revised_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample(file: Option<SendFile>, password: Option<SendPassword>) -> SendRecord {
        SendRecord {
            id: SendId::random(),
            owner: UserId::random(),
            kind: if file.is_some() {
                SendKind::File
            } else {
                SendKind::Text
            },
            meta: vec![1; 30],
            sealed_key: vec![2; 90],
            payload: vec![3; 50],
            file,
            password,
            max_access: Some(5),
            access_count: 2,
            hide_email: true,
            disabled: false,
            expires_at: Some(datetime!(2026-06-02 03:04:05 UTC)),
            deletion_at: datetime!(2026-06-08 03:04:05 UTC),
            created_at: datetime!(2026-06-01 03:04:05 UTC),
            revised_at: datetime!(2026-06-01 04:04:05 UTC),
        }
    }

    fn model_of(send: &SendRecord) -> Model {
        Model {
            id: send.id.0,
            owner_id: send.owner.0,
            kind: send.kind.code(),
            meta: send.meta.clone(),
            sealed_key: send.sealed_key.clone(),
            payload: send.payload.clone(),
            file_blob_id: send.file.map(|f| f.blob.to_uuid()),
            file_size: send.file.map(|f| i64::try_from(f.size).expect("fits")),
            file_format: send.file.map(|f| f.format.as_str().to_owned()),
            file_ready: send.file.is_some_and(|f| f.ready),
            password_salt: send.password.as_ref().map(|p| p.salt.clone()),
            password_hash: send.password.as_ref().map(|p| p.hash.clone()),
            max_access: send.max_access.map(i64::from),
            access_count: i64::from(send.access_count),
            hide_email: send.hide_email,
            disabled: send.disabled,
            expires_at: send.expires_at,
            deletion_at: send.deletion_at,
            created_at: send.created_at,
            revised_at: send.revised_at,
        }
    }

    fn file(ready: bool, format: SendFileFormat) -> SendFile {
        SendFile {
            blob: BlobId::random(),
            size: 65_680,
            format,
            ready,
        }
    }

    #[test]
    fn a_note_and_a_file_send_survive_the_trip_through_a_row() {
        let password = SendPassword {
            salt: vec![4; 32],
            hash: vec![5; 32],
        };
        for send in [
            sample(None, None),
            sample(None, Some(password.clone())),
            sample(Some(file(false, SendFileFormat::Kma1)), None),
            sample(Some(file(true, SendFileFormat::Opaque)), Some(password)),
        ] {
            assert_eq!(model_of(&send).into_domain(), Ok(send));
        }
    }

    #[test]
    fn the_row_holds_the_blob_by_its_uuid_and_the_format_as_text() {
        let f = file(true, SendFileFormat::Opaque);
        let send = sample(Some(f), None);
        let row = active(&send).expect("fits");
        assert_eq!(row.file_blob_id, Set(Some(f.blob.to_uuid())));
        assert_eq!(row.file_format, Set(Some("opaque".to_owned())));
        assert_eq!(row.file_size, Set(Some(65_680)));
        assert_eq!(row.file_ready, Set(true));
        assert_eq!(row.kind, Set(1));
    }

    #[test]
    fn times_are_stored_in_utc() {
        let mut send = sample(None, None);
        send.deletion_at = datetime!(2026-06-08 03:04:05 +02:00);
        send.expires_at = Some(datetime!(2026-06-02 03:04:05 +02:00));
        let row = active(&send).expect("fits");
        assert_eq!(row.deletion_at, Set(datetime!(2026-06-08 01:04:05 UTC)));
        assert_eq!(
            row.expires_at,
            Set(Some(datetime!(2026-06-02 01:04:05 UTC)))
        );
    }

    #[test]
    fn half_a_file_or_half_a_password_is_a_corrupt_row() {
        let mut row = model_of(&sample(Some(file(true, SendFileFormat::Kma1)), None));
        row.file_size = None;
        assert!(row.into_domain().is_err());

        let mut row = model_of(&sample(None, None));
        row.password_salt = Some(vec![1; 32]);
        assert!(row.into_domain().is_err());

        let mut row = model_of(&sample(Some(file(true, SendFileFormat::Kma1)), None));
        row.file_format = Some("zip".to_owned());
        assert!(row.into_domain().is_err());
    }

    #[test]
    fn unknown_kinds_and_negative_counts_are_corrupt() {
        let mut row = model_of(&sample(None, None));
        row.kind = 7;
        assert!(row.into_domain().is_err());
        let mut row = model_of(&sample(None, None));
        row.access_count = -1;
        assert!(row.into_domain().is_err());
        let mut row = model_of(&sample(None, None));
        row.max_access = Some(i64::from(u32::MAX) + 1);
        assert!(row.into_domain().is_err());
    }

    #[test]
    fn an_untouched_update_sets_nothing() {
        let row = untouched();
        assert!(matches!(row.deletion_at, sea_orm::ActiveValue::NotSet));
        assert!(matches!(row.id, sea_orm::ActiveValue::NotSet));
    }
}
