//! Privacy: how long each kind of data is kept, and what a log may keep of an address.
//!
//! The defaults and ranges are the retention table in the design's "Privacy and compliance":
//! the shortest periods by default, an admin may lengthen them within the ranges, and nothing
//! here reads a clock: callers pass `now`.

use crate::ids::{DeviceId, UserId};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub use crate::unlock::truncate_ip;

/// Tombstones are kept this long: the app's own window. Not an admin setting.
pub const TOMBSTONE_DAYS: u32 = 180;
/// A device approval expires after this many minutes. Not an admin setting.
pub const DEVICE_APPROVAL_MINUTES: u32 = 15;

/// A retention setting outside its range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{field} must be between {min} and {max}")]
pub struct RetentionError {
    pub field: &'static str,
    pub min: u32,
    pub max: u32,
}

/// How long the server keeps each kind of data, in days. The admin sets these; the defaults are
/// the table's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Retention {
    /// The event log: 90 days to 7 years. Default 1 year.
    pub event_log_days: u32,
    /// The sign-in log: 7 to 365 days. Default 90.
    pub sign_in_log_days: u32,
    /// How long full addresses are kept beside the truncated ones: 0 (off, the default) or 1 to
    /// 30 days.
    pub full_ip_days: u32,
    /// The trash: 1 to 365 days. Default 30. The server purges only Bitwarden-API items
    /// (it reads their trash date); Kemlock apps keep the date sealed in the item and empty their
    /// own trash on their own schedule.
    pub trash_days: u32,
    /// The grace period of a deleted account: 0 (erased at once, the default) to 30 days.
    pub deleted_account_grace_days: u32,
    /// Backups: 7 to 365 days. Default 30.
    pub backup_days: u32,
    /// The email log (recipient, template, result): 7 to 90 days. Default 30.
    pub email_log_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            event_log_days: 365,
            sign_in_log_days: 90,
            full_ip_days: 0,
            trash_days: 30,
            deleted_account_grace_days: 0,
            backup_days: 30,
            email_log_days: 30,
        }
    }
}

/// 7 years, in days.
const SEVEN_YEARS: u32 = 7 * 365;

impl Retention {
    /// Whether every setting is inside its range; the first one that isn't is named.
    pub fn validate(&self) -> Result<(), RetentionError> {
        let checks = [
            ("eventLogDays", self.event_log_days, 90, SEVEN_YEARS),
            ("signInLogDays", self.sign_in_log_days, 7, 365),
            ("fullIpDays", self.full_ip_days, 0, 30),
            ("trashDays", self.trash_days, 1, 365),
            (
                "deletedAccountGraceDays",
                self.deleted_account_grace_days,
                0,
                30,
            ),
            ("backupDays", self.backup_days, 7, 365),
            ("emailLogDays", self.email_log_days, 7, 90),
        ];
        for (field, value, min, max) in checks {
            if !(min..=max).contains(&value) {
                return Err(RetentionError { field, min, max });
            }
        }
        Ok(())
    }

    /// The same settings, or the first one outside its range.
    pub fn checked(self) -> Result<Self, RetentionError> {
        self.validate().map(|()| self)
    }

    /// Whether full addresses are kept for a while at all.
    pub fn keeps_full_ips(&self) -> bool {
        self.full_ip_days > 0
    }

    pub fn event_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.event_log_days))
    }

    pub fn sign_in_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.sign_in_log_days))
    }

    pub fn full_ip_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.full_ip_days))
    }

    pub fn trash_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.trash_days))
    }

    pub fn backup_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.backup_days))
    }

    pub fn email_log_cutoff(&self, now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(self.email_log_days))
    }

    pub fn tombstone_cutoff(now: OffsetDateTime) -> OffsetDateTime {
        now - Duration::days(i64::from(TOMBSTONE_DAYS))
    }
}

/// What a log row keeps of a client's address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredIp {
    /// Always kept: IPv4 cut to its /24, IPv6 to its /48 (`203.0.113.0/24`, `2001:db8:1::/48`).
    pub truncated: String,
    /// The whole address, only while the admin keeps full addresses.
    pub full: Option<String>,
}

/// Cuts an address to what the log may keep. The whole address is kept too only when `retention`
/// says so; the retention job drops it after `full_ip_days`.
pub fn stored_ip(ip: IpAddr, retention: &Retention) -> StoredIp {
    StoredIp {
        truncated: truncate_ip(ip),
        full: retention
            .keeps_full_ips()
            .then(|| ip.to_canonical().to_string()),
    }
}

/// One record of the event log as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub id: Uuid,
    pub actor: Option<UserId>,
    pub device: Option<DeviceId>,
    pub action: String,
    pub target: Option<String>,
    pub at: OffsetDateTime,
    /// The truncated address, when the event was written with one.
    pub ip: Option<String>,
}

/// How a sign-in attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignInOutcome {
    Success,
    Failure,
}

impl SignInOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SignInOutcome::Success => "success",
            SignInOutcome::Failure => "failure",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "success" => Some(SignInOutcome::Success),
            "failure" => Some(SignInOutcome::Failure),
            _ => None,
        }
    }
}

/// A sign-in attempt as stored: who (when known), how, when and from where. Never an email.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInEntry {
    pub id: Uuid,
    pub user: Option<UserId>,
    pub device: Option<DeviceId>,
    /// `password`, `two-factor`, `passkey`, `device-approval`, `device-key`, `sso`, `refresh`,
    /// `api-key`.
    pub method: String,
    pub outcome: SignInOutcome,
    pub at: OffsetDateTime,
    /// The truncated address.
    pub ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn the_defaults_are_the_tables_and_are_valid() {
        let r = Retention::default();
        assert_eq!(r.event_log_days, 365);
        assert_eq!(r.sign_in_log_days, 90);
        assert_eq!(r.full_ip_days, 0);
        assert_eq!(r.trash_days, 30);
        assert_eq!(r.deleted_account_grace_days, 0);
        assert_eq!(r.backup_days, 30);
        assert_eq!(r.email_log_days, 30);
        assert_eq!(r.validate(), Ok(()));
        assert!(!r.keeps_full_ips());
    }

    #[test]
    fn every_range_accepts_its_ends_and_refuses_beyond() {
        type Set = fn(&mut Retention, u32);
        let cases: [(&str, Set, u32, u32); 7] = [
            ("eventLogDays", |r, v| r.event_log_days = v, 90, 2555),
            ("signInLogDays", |r, v| r.sign_in_log_days = v, 7, 365),
            ("fullIpDays", |r, v| r.full_ip_days = v, 0, 30),
            ("trashDays", |r, v| r.trash_days = v, 1, 365),
            (
                "deletedAccountGraceDays",
                |r, v| r.deleted_account_grace_days = v,
                0,
                30,
            ),
            ("backupDays", |r, v| r.backup_days = v, 7, 365),
            ("emailLogDays", |r, v| r.email_log_days = v, 7, 90),
        ];
        for (field, set, min, max) in cases {
            for ok in [min, max] {
                let mut r = Retention::default();
                set(&mut r, ok);
                assert_eq!(r.validate(), Ok(()), "{field} = {ok}");
            }
            let mut over = Retention::default();
            set(&mut over, max + 1);
            assert_eq!(
                over.validate(),
                Err(RetentionError { field, min, max }),
                "{field} over"
            );
            if min > 0 {
                let mut under = Retention::default();
                set(&mut under, min - 1);
                assert_eq!(
                    under.validate(),
                    Err(RetentionError { field, min, max }),
                    "{field} under"
                );
            }
        }
    }

    #[test]
    fn cutoffs_count_back_from_now() {
        let now = datetime!(2026-12-01 00:00:00 UTC);
        let r = Retention::default();
        assert_eq!(r.event_cutoff(now), datetime!(2025-12-01 00:00:00 UTC));
        assert_eq!(r.sign_in_cutoff(now), datetime!(2026-09-02 00:00:00 UTC));
        assert_eq!(r.trash_cutoff(now), datetime!(2026-11-01 00:00:00 UTC));
        assert_eq!(
            Retention::tombstone_cutoff(now),
            datetime!(2026-06-04 00:00:00 UTC)
        );
    }

    #[test]
    fn partial_json_keeps_the_defaults_and_unknown_keys_are_refused() {
        let r: Retention = serde_json::from_str(r#"{"trashDays": 60}"#).expect("parses");
        assert_eq!(r.trash_days, 60);
        assert_eq!(r.event_log_days, 365);
        assert!(serde_json::from_str::<Retention>(r#"{"trashDay": 60}"#).is_err());
    }

    #[test]
    fn addresses_are_cut_and_the_whole_one_is_kept_only_when_asked() {
        let v4: IpAddr = "203.0.113.77".parse().expect("ip");
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().expect("ip");
        let mapped: IpAddr = "::ffff:198.51.100.9".parse().expect("ip");
        let off = Retention::default();
        assert_eq!(
            stored_ip(v4, &off),
            StoredIp {
                truncated: "203.0.113.0/24".to_owned(),
                full: None
            }
        );
        assert_eq!(stored_ip(v6, &off).truncated, "2001:db8:1::/48");
        assert_eq!(stored_ip(mapped, &off).truncated, "198.51.100.0/24");

        let on = Retention {
            full_ip_days: 7,
            ..Retention::default()
        };
        assert_eq!(stored_ip(v4, &on).full.as_deref(), Some("203.0.113.77"));
        assert_eq!(
            stored_ip(mapped, &on).full.as_deref(),
            Some("198.51.100.9"),
            "a mapped address is kept as the IPv4 it is"
        );
    }

    #[test]
    fn outcomes_round_trip() {
        for o in [SignInOutcome::Success, SignInOutcome::Failure] {
            assert_eq!(SignInOutcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(SignInOutcome::parse("maybe"), None);
    }
}
