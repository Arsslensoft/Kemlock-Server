//! `events`: the event log. Rows outlive the accounts and devices they name, so there are no
//! foreign keys.

use crate::convert::utc;
use kemlock_app::ports::Event;
use kemlock_domain::privacy::StoredIp;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "events")]
pub struct Model {
    /// A UUID v7, so ids sort by time.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub actor: Option<Uuid>,
    pub device: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub at: TimeDateTimeWithTimeZone,
    /// The client's address cut to its /24 or /48, when the event was written with one.
    pub ip: Option<String>,
    /// The whole address, while the admin keeps full addresses.
    pub ip_full: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The row for an event written with the client's address.
pub(crate) fn active_with_ip(event: Event, ip: Option<StoredIp>) -> ActiveModel {
    let (truncated, full) = match ip {
        Some(ip) => (Some(ip.truncated), ip.full),
        None => (None, None),
    };
    ActiveModel {
        id: Set(Uuid::now_v7()),
        actor: Set(event.actor.map(|u| u.0)),
        device: Set(event.device.map(|d| d.0)),
        action: Set(event.action.to_owned()),
        target: Set(event.target),
        at: Set(utc(event.at)),
        ip: Set(truncated),
        ip_full: Set(full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::UserId;
    use time::macros::datetime;

    #[test]
    fn an_event_becomes_a_row() {
        let actor = UserId::random();
        let row = active_with_ip(
            Event {
                actor: Some(actor),
                device: None,
                action: "login",
                target: Some("x".to_owned()),
                at: datetime!(2026-01-02 03:04:05 +01:00),
            },
            None,
        );
        assert_eq!(row.actor, Set(Some(actor.0)));
        assert_eq!(row.device, Set(None));
        assert_eq!(row.action, Set("login".to_owned()));
        assert_eq!(row.at, Set(datetime!(2026-01-02 02:04:05 UTC)));
        assert_eq!(row.ip, Set(None));
    }

    #[test]
    fn an_address_is_stored_beside_the_event() {
        let row = active_with_ip(
            Event {
                actor: None,
                device: None,
                action: "login",
                target: None,
                at: datetime!(2026-01-02 03:04:05 UTC),
            },
            Some(StoredIp {
                truncated: "203.0.113.0/24".to_owned(),
                full: Some("203.0.113.9".to_owned()),
            }),
        );
        assert_eq!(row.ip, Set(Some("203.0.113.0/24".to_owned())));
        assert_eq!(row.ip_full, Set(Some("203.0.113.9".to_owned())));
    }
}
