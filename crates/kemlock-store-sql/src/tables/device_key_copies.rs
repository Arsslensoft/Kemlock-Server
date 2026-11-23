//! `device_key_copies`: the trusted-device copy of the root key, one row per device.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::DeviceId;
use kemlock_domain::unlock::{DeviceKeyCopy, KeyProtection};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_key_copies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    /// The root key wrapped by a key only the device holds.
    pub wrapped_key: Vec<u8>,
    /// `KeyProtection` as its kebab-case name.
    pub protection: String,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<DeviceKeyCopy, StoreError> {
        Ok(DeviceKeyCopy {
            device: DeviceId(self.device_id),
            wrapped_key: self.wrapped_key,
            protection: KeyProtection::parse(&self.protection)
                .ok_or_else(|| corrupt("key protection"))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

pub(crate) fn active(copy: &DeviceKeyCopy) -> ActiveModel {
    ActiveModel {
        device_id: Set(copy.device.0),
        wrapped_key: Set(copy.wrapped_key.clone()),
        protection: Set(copy.protection.as_str().to_owned()),
        created_at: Set(utc(copy.created_at)),
        updated_at: Set(utc(copy.updated_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_row_becomes_a_copy_and_back() {
        let model = Model {
            device_id: Uuid::new_v4(),
            wrapped_key: vec![9; 92],
            protection: "secure-enclave".to_owned(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            updated_at: datetime!(2026-01-03 03:04:05 UTC),
        };
        let copy = model.into_domain().expect("valid row");
        assert_eq!(copy.protection, KeyProtection::SecureEnclave);
        assert_eq!(active(&copy).protection, Set("secure-enclave".to_owned()));
    }

    #[test]
    fn an_unknown_protection_is_a_corrupt_row() {
        let model = Model {
            device_id: Uuid::new_v4(),
            wrapped_key: vec![1],
            protection: "tpm".to_owned(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            updated_at: datetime!(2026-01-02 03:04:05 UTC),
        };
        assert!(model.into_domain().is_err());
    }
}
