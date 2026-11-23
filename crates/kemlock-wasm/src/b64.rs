//! base64url without padding, as docs/crypto.md fixes it: a decoder refuses padding, the standard
//! alphabet, whitespace and any encoding that is not the canonical one.

use crate::error::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `data` as unpadded base64url.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..=chunk.len() {
            let index = (n >> (18 - 6 * i)) & 63;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes unpadded base64url; an error for anything but the canonical encoding of some bytes.
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Invalid);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c).ok_or(Error::Invalid)? << (18 - 6 * i);
        }
        let be = n.to_be_bytes();
        out.extend_from_slice(&be[1..chunk.len()]);
    }
    // Trailing bits must be zero, so one byte string has one encoding.
    if encode(&out) == text {
        Ok(out)
    } else {
        Err(Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn url_alphabet_is_used() {
        assert_eq!(encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode("-__-"), Ok(vec![0xfb, 0xff, 0xfe]));
    }

    #[test]
    fn round_trips_every_length() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(decode(&encode(&data)), Ok(data));
        }
    }

    #[test]
    fn refuses_anything_but_the_canonical_form() {
        for bad in [
            "Zg==", "Zm9v+", "Zm 9v", "Zm9v\n", "Z", "Zh", "Zm9vY", "+/+/",
        ] {
            assert_eq!(decode(bad), Err(Error::Invalid), "{bad:?}");
        }
    }
}
