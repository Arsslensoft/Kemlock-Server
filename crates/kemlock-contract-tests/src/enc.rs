//! Strings shaped like Bitwarden's encrypted strings, `2.<iv>|<ciphertext>|<mac>` in standard
//! base64.
//!
//! The server never decrypts anything: it stores what clients send. So the tests carry no
//! cryptography. The "ciphertext" of [`enc`] is the plain text itself in base64, which lets a test
//! read a value back with [`dec`] and lets the fixtures' strings travel through the server as
//! arbitrary bytes. The iv and the mac are random and as long as the real ones, 16 and 32 bytes,
//! which is all Bitwarden's own server checks of an encrypted string.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// `count` random bytes, from version 4 UUIDs.
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count + 16);
    while out.len() < count {
        out.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    out.truncate(count);
    out
}

/// The bytes of anything that holds bytes, such as a hash's output.
pub fn bytes_of<T: AsRef<[u8]>>(value: T) -> Vec<u8> {
    value.as_ref().to_vec()
}

/// Standard base64 with padding.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Base64url without padding, as WebAuthn writes it.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
pub fn unb64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// An encrypted string of type 2 whose "ciphertext" is `plain`.
pub fn enc_bytes(plain: &[u8]) -> String {
    format!(
        "2.{}|{}|{}",
        b64(&random_bytes(16)),
        b64(plain),
        b64(&random_bytes(32))
    )
}

/// An encrypted string of type 2 holding `plain`.
pub fn enc(plain: &str) -> String {
    enc_bytes(plain.as_bytes())
}

/// What [`enc`] was given: the middle part of `text`, decoded, as text.
pub fn dec(text: &str) -> Option<String> {
    let body = text.strip_prefix("2.")?;
    let mut parts = body.split('|');
    let _iv = parts.next()?;
    let middle = parts.next()?;
    let bytes = STANDARD.decode(middle).ok()?;
    String::from_utf8(bytes).ok()
}

/// Whether `text` has the shape the server expects of a type 2 string: three base64 parts, the
/// first 16 bytes and the last 32.
pub fn is_enc_string(text: &str) -> bool {
    let Some(body) = text.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() != 3 {
        return false;
    }
    let lengths: Vec<Option<usize>> = parts
        .iter()
        .map(|part| STANDARD.decode(part).ok().map(|bytes| bytes.len()))
        .collect();
    lengths[0] == Some(16) && lengths[1].is_some() && lengths[2] == Some(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_goes_in_comes_out() {
        let text = enc("ünïcode \"quoted\"\nline | pipe");
        assert!(is_enc_string(&text), "{text}");
        assert_eq!(
            dec(&text).as_deref(),
            Some("ünïcode \"quoted\"\nline | pipe")
        );
        assert_ne!(enc("a"), enc("a"), "the iv is random");
    }

    #[test]
    fn random_bytes_have_the_length_asked() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(40).len(), 40);
    }

    #[test]
    fn base64url_round_trips() {
        let bytes = [251u8, 255, 0, 1];
        assert_eq!(unb64url(&b64url(&bytes)), Some(bytes.to_vec()));
    }
}
