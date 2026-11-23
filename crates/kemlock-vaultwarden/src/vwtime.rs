// Partly ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/util.rs (get_display_size), as display_size.
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! Dates as Vaultwarden stores and prints them.
//!
//! The database holds naive UTC date-times (`2024-05-01 10:00:00.123456`). Vaultwarden's API
//! prints them with `format_date`: RFC 3339, six fractional digits and a `Z`.

use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// Parses a date-time as a database prints it: `YYYY-MM-DD HH:MM:SS` with an optional fraction
/// of up to nine digits. A `T` instead of the space and a trailing `Z` are accepted too.
pub fn parse_db_time(text: &str) -> Option<PrimitiveDateTime> {
    let text = text.trim();
    let (date_part, time_part) = text.split_once([' ', 'T'])?;
    let time_part = time_part.strip_suffix('Z').unwrap_or(time_part);

    let mut date = date_part.split('-');
    let year: i32 = date.next()?.parse().ok()?;
    let month: u8 = date.next()?.parse().ok()?;
    let day: u8 = date.next()?.parse().ok()?;
    if date.next().is_some() {
        return None;
    }

    let (clock, fraction) = match time_part.split_once('.') {
        Some((clock, fraction)) => (clock, fraction),
        None => (time_part, ""),
    };
    let mut parts = clock.split(':');
    let hour: u8 = parts.next()?.parse().ok()?;
    let minute: u8 = parts.next()?.parse().ok()?;
    let second: u8 = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut nanos_text: String = fraction.chars().take(9).collect();
    while nanos_text.len() < 9 {
        nanos_text.push('0');
    }
    let nanos: u32 = nanos_text.parse().ok()?;

    let date = Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()?;
    let time = Time::from_hms_nano(hour, minute, second, nanos).ok()?;
    Some(PrimitiveDateTime::new(date, time))
}

/// Vaultwarden's `format_date`: `2024-05-01T10:00:00.123456Z`.
pub fn format_date(dt: PrimitiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.microsecond()
    )
}

/// Vaultwarden's `validate_and_format_date`: an RFC 3339 date-time printed with six fractional
/// digits (`Z` for UTC, the offset otherwise), or the start of 1970 if it doesn't parse.
pub fn validate_and_format_date(text: &str) -> String {
    match OffsetDateTime::parse(text, &Rfc3339) {
        Ok(dt) => {
            let seconds = dt.offset().whole_seconds();
            let zone = if seconds == 0 {
                "Z".to_owned()
            } else {
                let sign = if seconds < 0 { '-' } else { '+' };
                let abs = seconds.abs();
                format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
            };
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}{zone}",
                dt.year(),
                u8::from(dt.month()),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second(),
                dt.microsecond()
            )
        }
        Err(_) => "1970-01-01T00:00:00.000000Z".to_owned(),
    }
}

/// A naive database time as the UTC instant it stands for.
pub fn to_utc(dt: PrimitiveDateTime) -> OffsetDateTime {
    dt.assume_utc()
}

/// Vaultwarden's `get_display_size`: `1.50 KB`.
pub fn display_size(size: i64) -> String {
    const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];
    let mut size = size as f64;
    let mut unit = 0;
    while size > 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.2} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_times_parse_with_and_without_fractions() {
        let dt = parse_db_time("2024-05-01 10:20:30.123456789").expect("parses");
        assert_eq!(format_date(dt), "2024-05-01T10:20:30.123456Z");
        let dt = parse_db_time("2024-05-01 10:20:30").expect("parses");
        assert_eq!(format_date(dt), "2024-05-01T10:20:30.000000Z");
        let dt = parse_db_time("2024-05-01T10:20:30.5Z").expect("parses");
        assert_eq!(format_date(dt), "2024-05-01T10:20:30.500000Z");
    }

    #[test]
    fn nonsense_is_not_a_time() {
        for bad in [
            "",
            "yesterday",
            "2024-13-01 00:00:00",
            "2024-05-01",
            "2024-05-01 10:20:30.x",
        ] {
            assert!(parse_db_time(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn rfc3339_dates_are_reprinted_with_microseconds() {
        assert_eq!(
            validate_and_format_date("2023-10-31T12:00:00Z"),
            "2023-10-31T12:00:00.000000Z"
        );
        assert_eq!(
            validate_and_format_date("2023-10-31T12:00:00.1234567Z"),
            "2023-10-31T12:00:00.123456Z"
        );
        assert_eq!(
            validate_and_format_date("2023-10-31T12:00:00+02:00"),
            "2023-10-31T12:00:00.000000+02:00"
        );
        assert_eq!(
            validate_and_format_date("not a date"),
            "1970-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn sizes_print_as_vaultwarden_prints_them() {
        assert_eq!(display_size(0), "0.00 bytes");
        assert_eq!(display_size(1024), "1024.00 bytes");
        assert_eq!(display_size(1536), "1.50 KB");
        assert_eq!(display_size(5 * 1024 * 1024), "5.00 MB");
    }
}
