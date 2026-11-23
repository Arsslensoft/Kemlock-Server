//! Dates the way Vaultwarden writes and reads them.

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// `2026-11-07T10:16:50.428380Z`: UTC with six fractional digits, as Vaultwarden's `format_date`.
pub(crate) fn format_date(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.microsecond()
    )
}

/// Parses an RFC 3339 time; `None` for anything else, such as the mobile apps'
/// `0001-01-01T00:00:00` (no offset), which Vaultwarden logs and ignores.
pub(crate) fn parse_date(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Re-formats a valid RFC 3339 time; the start of the Unix epoch for anything else, as
/// Vaultwarden's `validate_and_format_date`.
pub(crate) fn validate_and_format_date(text: &str) -> String {
    match parse_date(text) {
        Some(t) => format_date(t),
        None => "1970-01-01T00:00:00.000000Z".to_owned(),
    }
}

/// Milliseconds since the Unix epoch; a time before 1970 counts as 0.
pub(crate) fn epoch_millis(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(0)
        .max(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn dates_have_six_fractional_digits_in_utc() {
        assert_eq!(
            format_date(datetime!(2026-11-07 10:16:50.42838 UTC)),
            "2026-11-07T10:16:50.428380Z"
        );
        assert_eq!(
            format_date(datetime!(2026-11-07 12:00:00 +02:00)),
            "2026-11-07T10:00:00.000000Z"
        );
    }

    #[test]
    fn dates_parse_only_with_an_offset() {
        assert!(parse_date("2026-11-07T10:00:36.364624Z").is_some());
        assert!(parse_date("2026-11-07T10:00:36+02:00").is_some());
        assert!(parse_date("0001-01-01T00:00:00").is_none());
        assert!(parse_date("yesterday").is_none());
    }

    #[test]
    fn a_bad_date_becomes_the_epoch() {
        assert_eq!(
            validate_and_format_date("nonsense"),
            "1970-01-01T00:00:00.000000Z"
        );
        assert_eq!(
            validate_and_format_date("2026-01-02T03:04:05Z"),
            "2026-01-02T03:04:05.000000Z"
        );
    }

    #[test]
    fn milliseconds_since_the_epoch() {
        assert_eq!(epoch_millis(datetime!(1970-01-01 00:00:01.5 UTC)), 1_500);
        assert_eq!(epoch_millis(datetime!(1969-12-31 00:00:00 UTC)), 0);
    }
}
