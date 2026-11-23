//! Which API a device last used, per API.
//!
//! One phone is one device row on both APIs (the Bitwarden API derives its device id from the
//! identifier the app sends, and the Kemlock API accepts that identifier at sign-in). The device's
//! `last_seen_at` can't say which API the phone still talks to, so each API records its own last
//! use here. The app reads both to tell whether anything still syncs through the Bitwarden API.

use crate::ids::DeviceId;
use time::OffsetDateTime;

/// An API a device authenticates against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiKind {
    /// `/kem/v1`.
    Kemlock,
    /// `/api` and `/identity`, the Bitwarden API.
    Bitwarden,
}

/// When a device last used each API; `None` for an API it never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceApiUse {
    pub device: DeviceId,
    pub kemlock: Option<OffsetDateTime>,
    pub bitwarden: Option<OffsetDateTime>,
}

impl DeviceApiUse {
    /// A device that used neither API.
    pub fn none(device: DeviceId) -> Self {
        DeviceApiUse {
            device,
            kemlock: None,
            bitwarden: None,
        }
    }

    /// The time of the last use of `api`.
    pub fn of(&self, api: ApiKind) -> Option<OffsetDateTime> {
        match api {
            ApiKind::Kemlock => self.kemlock,
            ApiKind::Bitwarden => self.bitwarden,
        }
    }

    /// The later of the two uses.
    pub fn latest(&self) -> Option<OffsetDateTime> {
        self.kemlock.into_iter().chain(self.bitwarden).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_device_reports_each_api_and_the_later_use() {
        let device = DeviceId::random();
        let mut usage = DeviceApiUse::none(device);
        assert_eq!(usage.latest(), None);
        usage.bitwarden = Some(datetime!(2026-01-01 00:00:00 UTC));
        assert_eq!(usage.of(ApiKind::Kemlock), None);
        assert_eq!(usage.latest(), usage.of(ApiKind::Bitwarden));
        usage.kemlock = Some(datetime!(2026-02-01 00:00:00 UTC));
        assert_eq!(usage.latest(), Some(datetime!(2026-02-01 00:00:00 UTC)));
    }
}
