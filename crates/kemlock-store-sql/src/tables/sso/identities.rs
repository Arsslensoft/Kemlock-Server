//! `sso_identities`: the link between an account and a subject at a provider.

use crate::convert::utc;
use kemlock_app::sso::SsoIdentity;
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sso_identities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub issuer: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub subject: String,
    pub user_id: Uuid,
    pub email: String,
    pub linked_at: TimeDateTimeWithTimeZone,
    pub last_login_at: TimeDateTimeWithTimeZone,
    /// Whether `amr` may stand in for the account's second step (`SsoIdentity::confirmed`).
    pub confirmed: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> SsoIdentity {
        SsoIdentity {
            issuer: self.issuer,
            subject: self.subject,
            user: UserId(self.user_id),
            email: self.email,
            linked_at: self.linked_at,
            last_login_at: self.last_login_at,
            confirmed: self.confirmed,
        }
    }
}

pub(crate) fn active(identity: &SsoIdentity) -> ActiveModel {
    ActiveModel {
        issuer: Set(identity.issuer.clone()),
        subject: Set(identity.subject.clone()),
        user_id: Set(identity.user.0),
        email: Set(identity.email.clone()),
        linked_at: Set(utc(identity.linked_at)),
        last_login_at: Set(utc(identity.last_login_at)),
        confirmed: Set(identity.confirmed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn an_identity_survives_the_trip_through_a_row() {
        let identity = SsoIdentity {
            issuer: "https://idp.example.org".into(),
            subject: "7f3a".into(),
            user: UserId::random(),
            email: "ada@example.org".into(),
            linked_at: datetime!(2026-01-02 03:04:05 UTC),
            last_login_at: datetime!(2026-02-02 03:04:05 UTC),
            confirmed: false,
        };
        let model = Model {
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            user_id: identity.user.0,
            email: identity.email.clone(),
            linked_at: identity.linked_at,
            last_login_at: identity.last_login_at,
            confirmed: identity.confirmed,
        };
        assert_eq!(model.into_domain(), identity);
        assert_eq!(active(&identity).subject, Set("7f3a".to_owned()));
    }
}
