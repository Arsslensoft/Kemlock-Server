//! One phone, one device on both APIs.
//!
//! The Bitwarden API knows a device by the identifier its client sends at sign-in and makes the
//! device's id from it and the account's id. The Kemlock app signs in on `/kem/v1` with that same
//! identifier (`bitwardenDeviceIdentifier`), and this module makes the same id, so the row the
//! Bitwarden API wrote is the row the Kemlock API signs in to, and the device list shows one
//! device for both. `kemlock-api-bw` calls this too, so the two can never drift apart.

use kemlock_domain::{DeviceId, UserId};

/// The label that keeps these ids apart from any other hash of the same bytes.
const LABEL: &[u8] = b"kemlock/bitwarden/device";

/// The longest identifier the Kemlock API accepts. Bitwarden clients send a UUID (36 characters).
pub const MAX_IDENTIFIER_LEN: usize = 256;

/// The id of the device `identifier` names on `user`'s account:
/// `uuid(SHA-256("kemlock/bitwarden/device" ‖ user id (16) ‖ identifier)[..16])`, with the version
/// and variant bits of a version-4 UUID set. It includes the account, so one phone signed in to
/// two accounts with the same identifier is two devices.
pub fn bitwarden_device_id(
    sha256: impl FnOnce(&[u8]) -> [u8; 32],
    user: UserId,
    identifier: &str,
) -> DeviceId {
    let mut input = Vec::with_capacity(LABEL.len() + 16 + identifier.len());
    input.extend_from_slice(LABEL);
    input.extend_from_slice(user.as_bytes());
    input.extend_from_slice(identifier.as_bytes());
    let digest = sha256(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    DeviceId(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in hash that folds every input byte into the output, so a change anywhere in the
    /// input (the user id sits after the 24-byte label) changes the digest, as a real hash would.
    fn echo(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            out[i % 32] = out[i % 32].rotate_left(3) ^ byte;
        }
        out
    }

    #[test]
    fn the_input_is_label_user_identifier() {
        let user = UserId::random();
        let id = bitwarden_device_id(
            |data| {
                assert_eq!(&data[..24], b"kemlock/bitwarden/device");
                assert_eq!(&data[24..40], user.as_bytes());
                assert_eq!(&data[40..], b"abc");
                echo(data)
            },
            user,
            "abc",
        );
        // The version and variant bits of a version-4 UUID.
        assert_eq!(id.0.get_version_num(), 4);
    }

    #[test]
    fn the_same_identifier_makes_the_same_id_per_account() {
        let (a, b) = (UserId::random(), UserId::random());
        assert_eq!(
            bitwarden_device_id(echo, a, "phone"),
            bitwarden_device_id(echo, a, "phone")
        );
        assert_ne!(
            bitwarden_device_id(echo, a, "phone"),
            bitwarden_device_id(echo, b, "phone")
        );
    }
}
