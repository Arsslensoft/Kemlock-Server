//! `dedup_owners`: per owner, the dedup key version and whether server matching is on. An owner
//! without a row is at the first version with matching off.

use crate::convert::{corrupt, from_i64_u32, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{MatchingSettings, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dedup_owners")]
pub struct Model {
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_type: i16,
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_id: Uuid,
    pub dedup_version: i64,
    pub server_matching: bool,
    pub changed_by: Option<Uuid>,
    pub changed_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<MatchingSettings, StoreError> {
        let owner = super::items::owner_from(self.owner_type, self.owner_id)?;
        let version = from_i64_u32(self.dedup_version, "dedup version")?;
        if version == 0 {
            return Err(corrupt("dedup version"));
        }
        Ok(MatchingSettings {
            owner,
            enabled: self.server_matching,
            version,
            changed_by: self.changed_by.map(UserId),
            changed_at: self.changed_at,
        })
    }
}

/// Every column set: fit for an insert.
pub(crate) fn active(settings: &MatchingSettings) -> ActiveModel {
    let (owner_type, owner_id) = super::items::owner_parts(settings.owner);
    ActiveModel {
        owner_type: Set(owner_type),
        owner_id: Set(owner_id),
        dedup_version: Set(i64::from(settings.version)),
        server_matching: Set(settings.enabled),
        changed_by: Set(settings.changed_by.map(|u| u.0)),
        changed_at: Set(settings.changed_at.map(utc)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::Owner;
    use time::macros::datetime;

    fn model() -> Model {
        Model {
            owner_type: i16::from(Owner::TYPE_SPACE),
            owner_id: Uuid::new_v4(),
            dedup_version: 3,
            server_matching: true,
            changed_by: Some(Uuid::new_v4()),
            changed_at: Some(datetime!(2026-01-02 03:04:05 UTC)),
        }
    }

    #[test]
    fn a_row_becomes_settings_and_back() {
        let settings = model().into_domain().expect("valid row");
        assert!(settings.enabled);
        assert_eq!(settings.version, 3);
        assert!(matches!(settings.owner, Owner::Space(_)));
        let row = active(&settings);
        assert_eq!(row.dedup_version, Set(3));
        assert_eq!(row.server_matching, Set(true));
    }

    #[test]
    fn corrupt_rows_are_refused() {
        for bad in [
            Model {
                owner_type: 9,
                ..model()
            },
            Model {
                dedup_version: 0,
                ..model()
            },
            Model {
                dedup_version: -1,
                ..model()
            },
        ] {
            assert!(bad.into_domain().is_err());
        }
    }
}
