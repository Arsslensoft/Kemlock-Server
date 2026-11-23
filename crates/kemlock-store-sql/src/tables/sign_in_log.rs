//! `sign_in_log`: sign-in attempts with the client's address cut to its /24 or /48. Rows outlive
//! the accounts and devices they name, so there are no foreign keys; erasing an account deletes
//! its rows.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_app::privacy::NewSignIn;
use kemlock_domain::privacy::{SignInEntry, SignInOutcome, StoredIp};
use kemlock_domain::{DeviceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sign_in_log")]
pub struct Model {
    /// A UUID v7, so ids sort by time.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub method: String,
    /// `success` or `failure`.
    pub outcome: String,
    pub at: TimeDateTimeWithTimeZone,
    /// The truncated address.
    pub ip: Option<String>,
    /// The whole address, while the admin keeps full addresses.
    pub ip_full: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<SignInEntry, StoreError> {
        Ok(SignInEntry {
            id: self.id,
            user: self.user_id.map(UserId),
            device: self.device_id.map(DeviceId),
            method: self.method,
            outcome: SignInOutcome::parse(&self.outcome)
                .ok_or_else(|| corrupt("sign-in outcome"))?,
            at: self.at,
            ip: self.ip,
        })
    }
}

pub(crate) fn active(entry: &NewSignIn, ip: Option<StoredIp>) -> ActiveModel {
    let (truncated, full) = match ip {
        Some(ip) => (Some(ip.truncated), ip.full),
        None => (None, None),
    };
    ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(entry.user.map(|u| u.0)),
        device_id: Set(entry.device.map(|d| d.0)),
        method: Set(entry.method.to_owned()),
        outcome: Set(entry.outcome.as_str().to_owned()),
        at: Set(utc(entry.at)),
        ip: Set(truncated),
        ip_full: Set(full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn an_attempt_becomes_a_row_and_back() {
        let user = UserId::random();
        let entry = NewSignIn {
            user: Some(user),
            device: None,
            method: "password",
            outcome: SignInOutcome::Failure,
            at: datetime!(2026-01-02 03:04:05 +01:00),
            ip: None,
        };
        let row = active(
            &entry,
            Some(StoredIp {
                truncated: "203.0.113.0/24".to_owned(),
                full: None,
            }),
        );
        assert_eq!(row.at, Set(datetime!(2026-01-02 02:04:05 UTC)));
        assert_eq!(row.ip, Set(Some("203.0.113.0/24".to_owned())));
        assert_eq!(row.ip_full, Set(None));
        let model = Model {
            id: Uuid::nil(),
            user_id: Some(user.0),
            device_id: None,
            method: "password".to_owned(),
            outcome: "failure".to_owned(),
            at: datetime!(2026-01-02 02:04:05 UTC),
            ip: Some("203.0.113.0/24".to_owned()),
            ip_full: None,
        };
        let back = model.clone().into_domain().expect("a valid row");
        assert_eq!(back.outcome, SignInOutcome::Failure);
        assert_eq!(back.user, Some(user));
        let mut bad = model;
        bad.outcome = "maybe".to_owned();
        assert!(bad.into_domain().is_err());
    }
}
