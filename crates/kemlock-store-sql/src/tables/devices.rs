//! `devices`: devices signed in to an account, as `kemlock_domain::Device`.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Device, DeviceId, DeviceKind, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    /// `DeviceKind` as its kebab-case name.
    pub kind: String,
    pub dpop_jkt: Option<String>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub last_seen_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

fn kind_str(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::KemlockAndroid => "kemlock-android",
        DeviceKind::KemlockIos => "kemlock-ios",
        DeviceKind::KemlockWeb => "kemlock-web",
        DeviceKind::KemlockCli => "kemlock-cli",
        DeviceKind::Amethystora => "amethystora",
        DeviceKind::Bitwarden => "bitwarden",
        DeviceKind::Other => "other",
    }
}

fn kind_from(s: &str) -> Result<DeviceKind, StoreError> {
    match s {
        "kemlock-android" => Ok(DeviceKind::KemlockAndroid),
        "kemlock-ios" => Ok(DeviceKind::KemlockIos),
        "kemlock-web" => Ok(DeviceKind::KemlockWeb),
        "kemlock-cli" => Ok(DeviceKind::KemlockCli),
        "amethystora" => Ok(DeviceKind::Amethystora),
        "bitwarden" => Ok(DeviceKind::Bitwarden),
        "other" => Ok(DeviceKind::Other),
        _ => Err(corrupt("device kind")),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<Device, StoreError> {
        Ok(Device {
            id: DeviceId(self.id),
            user: UserId(self.user_id),
            name: self.name,
            kind: kind_from(&self.kind)?,
            dpop_jkt: self.dpop_jkt,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
        })
    }
}

/// Every column set, the id included. An update drops the id with
/// `ActiveModel { id: NotSet, ..active(device) }`.
pub(crate) fn active(device: &Device) -> ActiveModel {
    ActiveModel {
        id: Set(device.id.0),
        user_id: Set(device.user.0),
        name: Set(device.name.clone()),
        kind: Set(kind_str(device.kind).to_owned()),
        dpop_jkt: Set(device.dpop_jkt.clone()),
        created_at: Set(utc(device.created_at)),
        last_seen_at: Set(utc(device.last_seen_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn every_kind_round_trips() {
        for kind in [
            DeviceKind::KemlockAndroid,
            DeviceKind::KemlockIos,
            DeviceKind::KemlockWeb,
            DeviceKind::KemlockCli,
            DeviceKind::Amethystora,
            DeviceKind::Bitwarden,
            DeviceKind::Other,
        ] {
            assert_eq!(kind_from(kind_str(kind)), Ok(kind));
        }
        assert!(kind_from("toaster").is_err());
    }

    #[test]
    fn a_row_becomes_a_device() {
        let id = DeviceId::random();
        let user = UserId::random();
        let model = Model {
            id: id.0,
            user_id: user.0,
            name: "Pixel".to_owned(),
            kind: "kemlock-android".to_owned(),
            dpop_jkt: Some("abc".to_owned()),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            last_seen_at: datetime!(2026-01-03 03:04:05 UTC),
        };
        let device = model.into_domain().expect("valid row");
        assert_eq!(device.id, id);
        assert_eq!(device.user, user);
        assert_eq!(device.kind, DeviceKind::KemlockAndroid);
        assert_eq!(active(&device).kind, Set("kemlock-android".to_owned()));
    }
}
