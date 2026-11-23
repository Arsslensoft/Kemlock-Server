//! TOTP enrolment: a fresh secret in base32 and the `otpauth://` URI an authenticator app reads.
//!
//! The secret is 20 random bytes (160 bits, RFC 4226's recommendation) from the same random source
//! as every key. Codes are HMAC-SHA-1, 6 digits and 30-second steps, which is what authenticator
//! apps assume when the URI says nothing else, and what the server checks.

use zeroize::Zeroizing;

use crate::error::Error;

/// The length of a fresh secret, in bytes.
pub(crate) const SECRET_LEN: usize = 20;
/// The shortest secret taken from outside: 80 bits, 16 base32 characters.
const MIN_SECRET_LEN: usize = 10;
/// The longest, so a URI stays a sensible size.
const MAX_SECRET_LEN: usize = 128;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, upper case, without padding.
pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Decodes base32 as people paste it: case-insensitive, with spaces, hyphens and `=` padding
/// ignored. Refuses anything else.
pub(crate) fn base32_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'-' | b'=' => continue,
            _ => return Err(Error::Invalid),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// What enrolment shows: the secret to type in and the URI for a QR code.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Enrolment {
    pub(crate) secret: String,
    pub(crate) uri: String,
}

/// A new enrolment, or one for `secret` (base32) when the caller already has it. The secret is
/// returned in its canonical form: upper case, no separators, no padding.
pub(crate) fn enrol(secret: Option<&str>, issuer: &str, account: &str) -> Result<Enrolment, Error> {
    let bytes = match secret {
        Some(text) => Zeroizing::new(base32_decode(text)?),
        None => Zeroizing::new(kemlock_crypto::rand::bytes::<SECRET_LEN>().to_vec()),
    };
    if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&bytes.len()) {
        return Err(Error::Invalid);
    }
    let secret = base32_encode(&bytes);
    let uri = otpauth_uri(&secret, issuer, account);
    Ok(Enrolment { secret, uri })
}

/// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`.
pub(crate) fn otpauth_uri(secret: &str, issuer: &str, account: &str) -> String {
    let issuer = percent_encode(issuer);
    let account = percent_encode(account);
    if issuer.is_empty() {
        return format!(
            "otpauth://totp/{account}?secret={secret}&algorithm=SHA1&digits=6&period=30"
        );
    }
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
         &algorithm=SHA1&digits=6&period=30"
    )
}

/// Percent-encodes everything but RFC 3986's unreserved characters, as a URI label and query value
/// both need.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn base32_decodes_what_people_paste() {
        assert_eq!(base32_decode("MZXW6YTBOI"), Ok(b"foobar".to_vec()));
        assert_eq!(base32_decode("mzxw 6ytb-oi=="), Ok(b"foobar".to_vec()));
        assert_eq!(base32_decode("MZXW1"), Err(Error::Invalid));
        assert_eq!(base32_decode("MZXW6!"), Err(Error::Invalid));
    }

    #[test]
    fn base32_round_trips_every_length() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 11 + 5) as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&data)), Ok(data));
        }
    }

    #[test]
    fn a_fresh_secret_is_160_bits_and_never_repeats() {
        let a = enrol(None, "Kemlock", "alice@example.com").expect("enrolment");
        let b = enrol(None, "Kemlock", "alice@example.com").expect("enrolment");
        assert_eq!(a.secret.len(), 32);
        assert_eq!(base32_decode(&a.secret).expect("base32").len(), SECRET_LEN);
        assert_ne!(a.secret, b.secret);
    }

    #[test]
    fn the_uri_follows_the_key_uri_format() {
        let e = enrol(
            Some("MZXW6YTBOI======"),
            "Kemlock Vault",
            "alice@example.com",
        );
        // Six bytes is under the 80-bit floor.
        assert_eq!(e, Err(Error::Invalid));
        let secret = "JBSWY3DPEHPK3PXP";
        let e = enrol(Some(secret), "Kemlock Vault", "alice@example.com").expect("enrolment");
        assert_eq!(e.secret, secret);
        assert_eq!(
            e.uri,
            "otpauth://totp/Kemlock%20Vault:alice%40example.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=Kemlock%20Vault&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn an_empty_issuer_leaves_the_prefix_out() {
        assert_eq!(
            otpauth_uri("JBSWY3DPEHPK3PXP", "", "bob"),
            "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn a_pasted_secret_is_made_canonical() {
        let e = enrol(Some("jbsw y3dp ehpk 3pxp"), "K", "a").expect("enrolment");
        assert_eq!(e.secret, "JBSWY3DPEHPK3PXP");
    }
}
