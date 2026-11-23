//! Devices signed in to an account.

use crate::ids::{DeviceId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What kind of app a device is, for the Devices screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceKind {
    KemlockAndroid,
    KemlockIos,
    KemlockWeb,
    KemlockCli,
    Amethystora,
    Bitwarden,
    Other,
}

/// A device. Its tokens are bound to its DPoP key, so a token copied off it is useless elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub user: UserId,
    pub name: String,
    pub kind: DeviceKind,
    /// The RFC 7638 thumbprint of the device's DPoP public key.
    pub dpop_jkt: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
}

impl Device {
    pub const MAX_NAME_LEN: usize = 64;

    /// A device name as shown: trimmed, control characters dropped, at most 64 characters.
    pub fn clean_name(raw: &str) -> String {
        let cleaned: String = raw
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(Self::MAX_NAME_LEN)
            .collect();
        if cleaned.is_empty() {
            "Unnamed device".to_owned()
        } else {
            cleaned
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        assert_eq!(Device::clean_name("  Pixel\u{7}  "), "Pixel");
        assert_eq!(Device::clean_name(""), "Unnamed device");
        assert_eq!(Device::clean_name(&"x".repeat(100)).len(), 64);
    }
}
