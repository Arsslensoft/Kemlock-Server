//! Reading the event log: the read side of [`EventLog`](crate::ports::EventLog), which only
//! writes.
//!
//! The Bitwarden API's event lists ask for one action's events in a time range, narrowed to an
//! organization, a cipher or a member. Those facts live in the JSON an event's `target` holds, so
//! a query names text the target must contain, and the store matches it however it can. Events
//! come newest first, so a page's last event is where the next one starts.

use crate::ports::StoreError;
use kemlock_domain::{DeviceId, UserId};
use std::future::Future;
use time::OffsetDateTime;
use uuid::Uuid;

/// One way an event can be about the thing asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventMatch {
    /// The event's target contains this text.
    Target(String),
    /// The event was made by this account.
    Actor(UserId),
}

/// What to read: events of one action, between two times (both inclusive), that satisfy every
/// `target_all` text and, when `any` isn't empty, at least one of its matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventQuery {
    pub action: String,
    pub target_all: Vec<String>,
    pub any: Vec<EventMatch>,
    pub from: OffsetDateTime,
    pub to: OffsetDateTime,
    /// The most events to return.
    pub limit: u32,
}

impl EventQuery {
    pub fn new(action: &str, from: OffsetDateTime, to: OffsetDateTime, limit: u32) -> Self {
        EventQuery {
            action: action.to_owned(),
            target_all: Vec::new(),
            any: Vec::new(),
            from,
            to,
            limit,
        }
    }

    /// Only events whose target contains `text`.
    #[must_use]
    pub fn containing(mut self, text: impl Into<String>) -> Self {
        self.target_all.push(text.into());
        self
    }

    /// Adds a way for an event to count; with any added, an event must have one of them.
    #[must_use]
    pub fn or(mut self, way: EventMatch) -> Self {
        self.any.push(way);
        self
    }
}

/// An event as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub id: Uuid,
    pub actor: Option<UserId>,
    pub device: Option<DeviceId>,
    pub action: String,
    pub target: Option<String>,
    pub at: OffsetDateTime,
    /// The address column, when the event was written with one: already cut to a /24 or /48.
    pub ip: Option<String>,
}

pub trait EventReader: Send + Sync {
    /// The events matching `query`, newest first (by time, then id), at most `query.limit`.
    fn read_events(
        &self,
        query: &EventQuery,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_query_collects_its_conditions() {
        let user = UserId::random();
        let query = EventQuery::new(
            "bw.event",
            datetime!(2026-11-01 00:00 UTC),
            datetime!(2026-12-01 00:00 UTC),
            30,
        )
        .containing("\"organizationId\":\"o\"")
        .or(EventMatch::Target(
            "\"organizationUserId\":\"m\"".to_owned(),
        ))
        .or(EventMatch::Actor(user));
        assert_eq!(query.action, "bw.event");
        assert_eq!(query.target_all, ["\"organizationId\":\"o\""]);
        assert_eq!(query.any.len(), 2);
        assert_eq!(query.any[1], EventMatch::Actor(user));
        assert_eq!(query.limit, 30);
    }
}
