//! `verified_domains`: email domains an admin claimed, proven by DNS or still pending.

use crate::convert::utc;
use kemlock_app::sso::VerifiedDomain;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "verified_domains")]
pub struct Model {
    /// Lower-case, no trailing dot.
    #[sea_orm(primary_key, auto_increment = false)]
    pub domain: String,
    pub token: String,
    pub created_at: TimeDateTimeWithTimeZone,
    pub verified_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> VerifiedDomain {
        VerifiedDomain {
            domain: self.domain,
            token: self.token,
            created_at: self.created_at,
            verified_at: self.verified_at,
        }
    }
}

pub(crate) fn active(claim: &VerifiedDomain) -> ActiveModel {
    ActiveModel {
        domain: Set(claim.domain.clone()),
        token: Set(claim.token.clone()),
        created_at: Set(utc(claim.created_at)),
        verified_at: Set(claim.verified_at.map(utc)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_claim_survives_the_trip_through_a_row() {
        let claim = VerifiedDomain {
            domain: "example.org".into(),
            token: "abc123".into(),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            verified_at: Some(datetime!(2026-01-03 03:04:05 UTC)),
        };
        let model = Model {
            domain: claim.domain.clone(),
            token: claim.token.clone(),
            created_at: claim.created_at,
            verified_at: claim.verified_at,
        };
        assert_eq!(model.into_domain(), claim);
        assert_eq!(active(&claim).token, Set("abc123".to_owned()));
    }
}
