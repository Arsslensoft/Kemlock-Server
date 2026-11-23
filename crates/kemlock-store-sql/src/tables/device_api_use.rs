//! `device_api_use`: when each device last used each API, as
//! `kemlock_domain::api_use::DeviceApiUse`. A row has a column per API, so one API's write never
//! touches the other's.

use kemlock_domain::DeviceId;
use kemlock_domain::api_use::DeviceApiUse;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_api_use")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub kemlock_used_at: Option<TimeDateTimeWithTimeZone>,
    pub bitwarden_used_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> DeviceApiUse {
        DeviceApiUse {
            device: DeviceId(self.device_id),
            kemlock: self.kemlock_used_at,
            bitwarden: self.bitwarden_used_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_row_becomes_a_use() {
        let id = Uuid::new_v4();
        let model = Model {
            device_id: id,
            kemlock_used_at: Some(datetime!(2026-01-02 03:04:05 UTC)),
            bitwarden_used_at: None,
        };
        let usage = model.into_domain();
        assert_eq!(usage.device, DeviceId(id));
        assert_eq!(usage.kemlock, Some(datetime!(2026-01-02 03:04:05 UTC)));
        assert_eq!(usage.bitwarden, None);
    }
}
