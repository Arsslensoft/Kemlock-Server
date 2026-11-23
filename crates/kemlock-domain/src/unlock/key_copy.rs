//! The trusted-device copy of the root key.

use crate::ids::DeviceId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A wrapped root key is an AEAD seal or an enclave-wrapped blob, a few hundred bytes at most.
pub const MAX_WRAPPED_KEY_LEN: usize = 1024;

/// What holds the key that wrapped the copy. Only the device knows; the server shows it in the
/// devices list so a person can tell a hardware key from software.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProtection {
    SecureEnclave,
    Keystore,
    /// A non-extractable WebCrypto key.
    WebCrypto,
    /// A key kept sealed in the vault, for a phone without hardware keys.
    Software,
}

impl KeyProtection {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyProtection::SecureEnclave => "secure-enclave",
            KeyProtection::Keystore => "keystore",
            KeyProtection::WebCrypto => "web-crypto",
            KeyProtection::Software => "software",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "secure-enclave" => KeyProtection::SecureEnclave,
            "keystore" => KeyProtection::Keystore,
            "web-crypto" => KeyProtection::WebCrypto,
            "software" => KeyProtection::Software,
            _ => return None,
        })
    }
}

/// The root key wrapped by a key only its device holds (`device_key_copies`, one row per device).
/// The server keeps the copy and never the wrapping key, and signing the device out deletes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeyCopy {
    pub device: DeviceId,
    pub wrapped_key: Vec<u8>,
    pub protection: KeyProtection,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protections_round_trip_through_their_names() {
        for p in [
            KeyProtection::SecureEnclave,
            KeyProtection::Keystore,
            KeyProtection::WebCrypto,
            KeyProtection::Software,
        ] {
            assert_eq!(KeyProtection::parse(p.as_str()), Some(p));
        }
        assert_eq!(KeyProtection::parse("tpm"), None);
    }

    #[test]
    fn serde_names_match_the_stored_names() {
        let json = serde_json::to_string(&KeyProtection::SecureEnclave).expect("serialises");
        assert_eq!(json, "\"secure-enclave\"");
    }
}
