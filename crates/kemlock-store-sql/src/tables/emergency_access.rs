//! `emergency_access`: grants, as `kemlock_domain::unlock::EmergencyGrant`.

use crate::convert::{corrupt, from_i64_u32, to_i64, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::unlock::{EmergencyGrant, EmergencyKind, EmergencyState, GrantId};
use kemlock_domain::{Email, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "emergency_access")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub grantor_id: Uuid,
    /// The contact, lower-cased.
    pub grantee_email: String,
    /// Set when the contact accepts; cleared if their account is deleted.
    pub grantee_id: Option<Uuid>,
    /// `view` or `takeover`.
    pub kind: String,
    pub wait_days: i64,
    /// `EmergencyState` as its kebab-case name.
    pub state: String,
    /// The root key sealed to the contact's `kx1` key.
    pub sealed_key: Option<Vec<u8>>,
    pub recovery_initiated_at: Option<TimeDateTimeWithTimeZone>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<EmergencyGrant, StoreError> {
        Ok(EmergencyGrant {
            id: GrantId(self.id),
            grantor: UserId(self.grantor_id),
            grantee_email: Email::parse(&self.grantee_email)
                .map_err(|_| corrupt("emergency contact email"))?,
            grantee: self.grantee_id.map(UserId),
            kind: EmergencyKind::parse(&self.kind).ok_or_else(|| corrupt("emergency kind"))?,
            wait_days: from_i64_u32(self.wait_days, "emergency wait")?,
            state: EmergencyState::parse(&self.state).ok_or_else(|| corrupt("emergency state"))?,
            sealed_key: self.sealed_key,
            recovery_initiated_at: self.recovery_initiated_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Every column set, the id included.
pub(crate) fn active(grant: &EmergencyGrant) -> Result<ActiveModel, StoreError> {
    Ok(ActiveModel {
        id: Set(grant.id.0),
        grantor_id: Set(grant.grantor.0),
        grantee_email: Set(grant.grantee_email.as_str().to_owned()),
        grantee_id: Set(grant.grantee.map(|u| u.0)),
        kind: Set(grant.kind.as_str().to_owned()),
        wait_days: Set(to_i64(u64::from(grant.wait_days), "emergency wait")?),
        state: Set(grant.state.as_str().to_owned()),
        sealed_key: Set(grant.sealed_key.clone()),
        recovery_initiated_at: Set(grant.recovery_initiated_at.map(utc)),
        created_at: Set(utc(grant.created_at)),
        updated_at: Set(utc(grant.updated_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn model() -> Model {
        Model {
            id: Uuid::new_v4(),
            grantor_id: Uuid::new_v4(),
            grantee_email: "friend@example.org".to_owned(),
            grantee_id: Some(Uuid::new_v4()),
            kind: "takeover".to_owned(),
            wait_days: 7,
            state: "recovery-initiated".to_owned(),
            sealed_key: Some(vec![1, 2, 3]),
            recovery_initiated_at: Some(datetime!(2026-01-02 03:04:05 UTC)),
            created_at: datetime!(2026-01-01 03:04:05 UTC),
            updated_at: datetime!(2026-01-02 03:04:05 UTC),
        }
    }

    #[test]
    fn a_row_becomes_a_grant_and_back() {
        let grant = model().into_domain().expect("valid row");
        assert_eq!(grant.kind, EmergencyKind::Takeover);
        assert_eq!(grant.state, EmergencyState::RecoveryInitiated);
        assert_eq!(grant.wait_days, 7);
        let row = active(&grant).expect("fits");
        assert_eq!(row.state, Set("recovery-initiated".to_owned()));
        assert_eq!(row.wait_days, Set(7));
        assert_eq!(row.kind, Set("takeover".to_owned()));
    }

    #[test]
    fn corrupt_rows_are_refused() {
        for bad in [
            Model {
                kind: "own".to_owned(),
                ..model()
            },
            Model {
                state: "done".to_owned(),
                ..model()
            },
            Model {
                wait_days: -1,
                ..model()
            },
            Model {
                grantee_email: "not an email".to_owned(),
                ..model()
            },
        ] {
            assert!(bad.into_domain().is_err());
        }
    }
}
