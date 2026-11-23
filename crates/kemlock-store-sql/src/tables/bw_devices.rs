//! `bw_devices`: what the Bitwarden API keeps of a device beyond its row.

use crate::convert::utc;
use kemlock_app::bw_events::{BwDevice, BwPushToken};
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub user_id: Uuid,
    /// The `deviceIdentifier` the app signs in with.
    pub identifier: Uuid,
    pub device_type: i32,
    /// The relay's id for the phone; set together with `push_token`.
    pub push_uuid: Option<Uuid>,
    pub push_token: Option<String>,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> BwDevice {
        let push = match (self.push_uuid, self.push_token) {
            (Some(push_uuid), Some(token)) => Some(BwPushToken { push_uuid, token }),
            _ => None,
        };
        BwDevice {
            device: DeviceId(self.device_id),
            user: UserId(self.user_id),
            identifier: self.identifier,
            device_type: self.device_type,
            push,
            updated_at: self.updated_at,
        }
    }
}

/// A row for a device that signed in, with no push registration.
pub(crate) fn noted(
    device: DeviceId,
    user: UserId,
    identifier: Uuid,
    device_type: i32,
    at: time::OffsetDateTime,
) -> ActiveModel {
    ActiveModel {
        device_id: Set(device.0),
        user_id: Set(user.0),
        identifier: Set(identifier),
        device_type: Set(device_type),
        push_uuid: Set(None),
        push_token: Set(None),
        updated_at: Set(utc(at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn row(push_uuid: Option<Uuid>, push_token: Option<&str>) -> Model {
        Model {
            device_id: Uuid::from_u128(1),
            user_id: Uuid::from_u128(2),
            identifier: Uuid::from_u128(3),
            device_type: 1,
            push_uuid,
            push_token: push_token.map(str::to_owned),
            updated_at: datetime!(2026-11-25 10:00 UTC),
        }
    }

    #[test]
    fn a_row_with_both_push_columns_has_a_registration() {
        let device = row(Some(Uuid::from_u128(9)), Some("tok")).into_domain();
        let push = device.push.expect("a registration");
        assert_eq!(push.push_uuid, Uuid::from_u128(9));
        assert_eq!(push.token, "tok");
        assert_eq!(device.device_type, 1);
        assert_eq!(device.identifier, Uuid::from_u128(3));
    }

    #[test]
    fn a_row_missing_either_column_has_none() {
        assert!(row(None, None).into_domain().push.is_none());
        assert!(
            row(Some(Uuid::from_u128(9)), None)
                .into_domain()
                .push
                .is_none()
        );
        assert!(row(None, Some("tok")).into_domain().push.is_none());
    }
}
