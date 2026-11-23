//! The event log: filters, pages, CSV export and retention.
//!
//! Addresses are cut to their /24 or /48 when an event is written (design, "Privacy and
//! compliance"). Events that came from elsewhere may hold a full address, so every address is
//! cut again on the way out: the console and the CSV never show a full one.

use super::error::AdminError;
use super::ports::SettingsRepo;
use super::ports::{AdminEventRepo, EventCursor, EventFilter, EventPage, EventRecord};
use super::settings::{EnvSettings, Settings};
use crate::ports::{Clock, SecretSeal};
use kemlock_domain::unlock::truncate_ip;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The most events a page holds.
pub const MAX_PAGE: u32 = 200;
/// The most rows a CSV export holds.
pub const MAX_EXPORT_ROWS: usize = 100_000;
/// How many events each read of an export takes.
const EXPORT_CHUNK: u32 = 1000;

/// Cuts an address that is written out in full to its /24 or /48; text that isn't an address,
/// and an address that is already cut (`a.b.c.0/24`), passes unchanged.
pub fn cut_ip(text: &str) -> String {
    match text.trim().parse::<IpAddr>() {
        Ok(ip) => truncate_ip(ip),
        Err(_) => text.to_owned(),
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn is_target_char(c: char) -> bool {
    is_name_char(c) || matches!(c, ':' | '/' | '@')
}

/// A filter from request values, checked: an action of letters, digits, `.`, `_`, `-` (and a
/// final `*`), a target of those and `: / @`.
pub fn filter(
    actor: Option<Uuid>,
    action: Option<&str>,
    target: Option<&str>,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
) -> Result<EventFilter, AdminError> {
    let action = action
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(|a| {
            let body = a.strip_suffix('*').unwrap_or(a);
            if a.len() <= 64 && body.chars().all(is_name_char) {
                Ok(a.to_owned())
            } else {
                Err(AdminError::Invalid(
                    "action: letters, digits, . _ - and a final * only".to_owned(),
                ))
            }
        })
        .transpose()?;
    let target = target
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t.len() <= 128 && t.chars().all(is_target_char) {
                Ok(t.to_owned())
            } else {
                Err(AdminError::Invalid(
                    "target: letters, digits, . _ - : / @ only".to_owned(),
                ))
            }
        })
        .transpose()?;
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(AdminError::Invalid("from is after to".to_owned()));
    }
    Ok(EventFilter {
        actor: actor.map(kemlock_domain::UserId),
        action,
        target,
        from,
        to,
    })
}

/// A cursor in its text form: the time in Unix microseconds, a dash and the event id.
pub fn cursor_text(cursor: &EventCursor) -> String {
    format!(
        "{}-{}",
        cursor.at.unix_timestamp_nanos() / 1000,
        cursor.id.simple()
    )
}

/// The cursor `cursor_text` made.
pub fn parse_cursor(text: &str) -> Result<EventCursor, AdminError> {
    let bad = || AdminError::Invalid("the cursor isn't valid".to_owned());
    let (micros, id) = text.split_once('-').ok_or_else(bad)?;
    let micros: i128 = micros.parse().map_err(|_| bad())?;
    let at = OffsetDateTime::from_unix_timestamp_nanos(micros.checked_mul(1000).ok_or_else(bad)?)
        .map_err(|_| bad())?;
    let id = Uuid::parse_str(id).map_err(|_| bad())?;
    Ok(EventCursor { at, id })
}

#[derive(Debug)]
pub struct EventLogView<V> {
    pub events: V,
}

fn cut(mut page: EventPage) -> EventPage {
    for event in &mut page.events {
        event.ip = event.ip.take().map(|ip| cut_ip(&ip));
    }
    page
}

impl<V: AdminEventRepo> EventLogView<V> {
    /// One page, newest first.
    pub async fn page(
        &self,
        filter: &EventFilter,
        after: Option<&EventCursor>,
        limit: u32,
    ) -> Result<EventPage, AdminError> {
        let limit = limit.clamp(1, MAX_PAGE);
        Ok(cut(self.events.query_events(filter, after, limit).await?))
    }

    /// Every event that matches, as CSV (at most [`MAX_EXPORT_ROWS`]; the second value says the
    /// export was cut short).
    pub async fn export_csv(&self, filter: &EventFilter) -> Result<(String, bool), AdminError> {
        let mut out = String::from("time,actor,actor_email,action,target,device,ip\r\n");
        let mut after: Option<EventCursor> = None;
        let mut rows = 0usize;
        loop {
            let page = cut(self
                .events
                .query_events(filter, after.as_ref(), EXPORT_CHUNK)
                .await?);
            for event in &page.events {
                if rows >= MAX_EXPORT_ROWS {
                    return Ok((out, true));
                }
                csv_row(&mut out, event);
                rows += 1;
            }
            match page.next {
                Some(next) => after = Some(next),
                None => return Ok((out, false)),
            }
        }
    }
}

/// One CSV field. A value a spreadsheet would run as a formula (`=`, `+`, `-`, `@`, tab or
/// return first) gets a quote in front, so opening the export never executes anything.
fn csv_field(out: &mut String, value: &str) {
    let risky = value
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let needs_quotes = risky || value.contains([',', '"', '\n', '\r']);
    if !needs_quotes {
        out.push_str(value);
        return;
    }
    out.push('"');
    if risky {
        out.push('\'');
    }
    for c in value.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

fn csv_row(out: &mut String, event: &EventRecord) {
    let time = event.at.format(&Rfc3339).unwrap_or_default();
    let actor = event.actor.map(|a| a.to_string()).unwrap_or_default();
    let device = event.device.map(|d| d.to_string()).unwrap_or_default();
    let fields: [&str; 7] = [
        &time,
        &actor,
        event.actor_email.as_deref().unwrap_or(""),
        &event.action,
        event.target.as_deref().unwrap_or(""),
        &device,
        event.ip.as_deref().unwrap_or(""),
    ];
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        csv_field(out, field);
    }
    out.push_str("\r\n");
}

/// Deletes the events older than the retention setting (`event_log_days`, default a year).
#[derive(Debug)]
pub struct EventRetention<V, R, S, E, C> {
    pub events: V,
    pub settings: Settings<R, S, E>,
    pub clock: C,
}

impl<V: AdminEventRepo, R: SettingsRepo, S: SecretSeal, E: EnvSettings, C: Clock>
    EventRetention<V, R, S, E, C>
{
    /// Returns how many events went.
    pub async fn execute(&self) -> Result<u64, AdminError> {
        let days = self.settings.get_int("event_log_days").await?;
        let before = self.clock.now() - Duration::days(days);
        Ok(self.events.purge_events_before(before).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn full_addresses_are_cut_and_cut_ones_pass() {
        assert_eq!(cut_ip("203.0.113.77"), "203.0.113.0/24");
        assert_eq!(cut_ip("2001:db8:1:2::9"), "2001:db8:1::/48");
        assert_eq!(cut_ip("203.0.113.0/24"), "203.0.113.0/24");
        assert_eq!(cut_ip("not an address"), "not an address");
    }

    #[test]
    fn filters_refuse_wildcards_and_odd_characters() {
        assert!(filter(None, Some("space.*"), Some("user:1@x.org"), None, None).is_ok());
        for bad in ["a%", "a_b*c", "a b", "a;drop"] {
            let result = filter(None, Some(bad), None, None, None);
            // `a_b*c` has its star inside, which is the only other way to say a wildcard.
            assert!(result.is_err(), "{bad}");
        }
        assert!(filter(None, None, Some("100%"), None, None).is_err());
        let from = datetime!(2026-02-01 0:00 UTC);
        let to = datetime!(2026-01-01 0:00 UTC);
        assert!(filter(None, None, None, Some(from), Some(to)).is_err());
    }

    #[test]
    fn a_cursor_round_trips() {
        let cursor = EventCursor {
            at: datetime!(2026-03-04 05:06:07.123456 UTC),
            id: Uuid::from_u128(77),
        };
        assert_eq!(parse_cursor(&cursor_text(&cursor)), Ok(cursor));
        assert!(parse_cursor("nonsense").is_err());
        assert!(parse_cursor("12-notauuid").is_err());
    }

    #[test]
    fn csv_fields_are_quoted_and_formulas_defused() {
        let mut out = String::new();
        csv_field(&mut out, "plain");
        assert_eq!(out, "plain");
        out.clear();
        csv_field(&mut out, "a,\"b\"");
        assert_eq!(out, "\"a,\"\"b\"\"\"");
        out.clear();
        csv_field(&mut out, "=HYPERLINK(\"x\")");
        assert_eq!(out, "\"'=HYPERLINK(\"\"x\"\")\"");
        out.clear();
        csv_field(&mut out, "-1+1");
        assert_eq!(out, "\"'-1+1\"");
    }
}
