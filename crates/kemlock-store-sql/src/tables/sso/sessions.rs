//! `sso_sessions`: the devices an SSO sign-in started, as `kemlock_app::sso::SsoSession`.

use crate::convert::utc;
use kemlock_app::sso::SsoSession;
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sso_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub session_id: Option<String>,
    pub started_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> SsoSession {
        SsoSession {
            device: DeviceId(self.device_id),
            user: UserId(self.user_id),
            issuer: self.issuer,
            subject: self.subject,
            session_id: self.session_id,
            started_at: self.started_at,
        }
    }
}

pub(crate) fn active(session: &SsoSession) -> ActiveModel {
    ActiveModel {
        device_id: Set(session.device.0),
        user_id: Set(session.user.0),
        issuer: Set(session.issuer.clone()),
        subject: Set(session.subject.clone()),
        session_id: Set(session.session_id.clone()),
        started_at: Set(utc(session.started_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_session_survives_the_trip_through_a_row() {
        let session = SsoSession {
            device: DeviceId::random(),
            user: UserId::random(),
            issuer: "https://idp.example.org".into(),
            subject: "7f3a".into(),
            session_id: Some("sid-1".into()),
            started_at: datetime!(2026-01-02 03:04:05 UTC),
        };
        let model = Model {
            device_id: session.device.0,
            user_id: session.user.0,
            issuer: session.issuer.clone(),
            subject: session.subject.clone(),
            session_id: session.session_id.clone(),
            started_at: session.started_at,
        };
        assert_eq!(model.into_domain(), session);
        assert_eq!(active(&session).session_id, Set(Some("sid-1".to_owned())));
    }
}
