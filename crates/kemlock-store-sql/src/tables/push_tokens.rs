//! `push_tokens`: a device's push token (APNs or UnifiedPush), for the server's own push and the optional relay.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_app::push::{PushKind, PushRegistration};
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "push_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub user_id: Uuid,
    /// `PushKind` as `fcm` or `apns`.
    pub kind: String,
    pub token: String,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<PushRegistration, StoreError> {
        Ok(PushRegistration {
            device: DeviceId(self.device_id),
            user: UserId(self.user_id),
            kind: PushKind::parse(&self.kind).ok_or_else(|| corrupt("push kind"))?,
            token: self.token,
            updated_at: self.updated_at,
        })
    }
}

pub(crate) fn active(registration: &PushRegistration) -> ActiveModel {
    ActiveModel {
        device_id: Set(registration.device.0),
        user_id: Set(registration.user.0),
        kind: Set(registration.kind.as_str().to_owned()),
        token: Set(registration.token.clone()),
        updated_at: Set(utc(registration.updated_at)),
    }
}
