//! Small conversions between domain values and what the database holds.
//!
//! Every integer is stored as a signed 64-bit column (SQLite and PostgreSQL have no unsigned
//! type), every time in UTC, and every id as a UUID column.

use kemlock_app::ports::StoreError;
use time::{OffsetDateTime, UtcOffset};

/// A value read from the database that the domain refuses: the row is corrupt or was written by
/// something else. The message is for logs.
pub(crate) fn corrupt(what: &str) -> StoreError {
    StoreError::Backend(format!("stored {what} is not valid"))
}

pub(crate) fn to_i64(value: u64, what: &str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| corrupt(what))
}

pub(crate) fn from_i64(value: i64, what: &str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corrupt(what))
}

pub(crate) fn from_i64_u32(value: i64, what: &str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| corrupt(what))
}

/// Times are written in UTC so every backend compares and sorts them the same way (SQLite keeps
/// them as RFC 3339 text, which only sorts right when the offset is the same).
pub(crate) fn utc(time: OffsetDateTime) -> OffsetDateTime {
    time.to_offset(UtcOffset::UTC)
}

/// Milliseconds since the Unix epoch, for the HLC. Times before 1970 count as 0.
pub(crate) fn unix_millis(time: OffsetDateTime) -> u64 {
    let millis = time.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn integers_round_trip_and_refuse_out_of_range() {
        assert_eq!(to_i64(7, "x"), Ok(7));
        assert!(to_i64(u64::MAX, "x").is_err());
        assert_eq!(from_i64(7, "x"), Ok(7));
        assert!(from_i64(-1, "x").is_err());
        assert!(from_i64_u32(i64::from(u32::MAX) + 1, "x").is_err());
    }

    #[test]
    fn times_go_to_utc_and_millis() {
        let t = datetime!(2026-01-02 03:04:05.678 +02:00);
        assert_eq!(utc(t).offset(), UtcOffset::UTC);
        assert_eq!(utc(t), t);
        assert_eq!(unix_millis(datetime!(1970-01-01 00:00:01 UTC)), 1_000);
        assert_eq!(unix_millis(datetime!(1969-12-31 00:00:00 UTC)), 0);
    }
}
