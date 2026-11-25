//! Base64, just enough for the Apple push key (a PEM file, standard alphabet) and the JWT
//! (URL-safe, no padding). Small enough to keep here rather than add a crate.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// URL-safe base64 without padding: the JWT's encoding.
pub(super) fn encode_url(bytes: &[u8]) -> String {
    encode_with(bytes, URL_SAFE, false)
}

/// Standard base64 with padding.
#[cfg(test)]
pub(super) fn encode_standard(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD, true)
}

/// Decodes either alphabet, with or without trailing `=`, skipping ASCII whitespace. `None` for
/// anything else.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut padding = false;
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            padding = true;
            continue;
        }
        if padding {
            return None;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // A single leftover symbol carries fewer than 8 bits: not a whole number of bytes.
    (bits < 6).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_standard(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain.as_bytes()));
            assert_eq!(
                encode_url(plain.as_bytes()),
                encoded.trim_end_matches('=')
            );
            assert_eq!(
                decode(encoded.trim_end_matches('=')).as_deref(),
                Some(plain.as_bytes())
            );
        }
    }

    #[test]
    fn the_url_alphabet_has_no_plus_or_slash() {
        let bytes = [0xfbu8, 0xff, 0xfe, 0x3e, 0x3f];
        let encoded = encode_url(&bytes);
        assert!(!encoded.contains(['+', '/', '=']));
        assert_eq!(decode(&encoded).as_deref(), Some(bytes.as_slice()));
        assert_eq!(decode(&encode_standard(&bytes)).as_deref(), Some(bytes.as_slice()));
    }

    #[test]
    fn whitespace_is_skipped_and_junk_is_refused() {
        assert_eq!(decode("Zm9v\nYmFy\r\n").as_deref(), Some(b"foobar".as_slice()));
        assert_eq!(decode("Zm9v!"), None);
        assert_eq!(decode("Zg==Zg"), None);
        assert_eq!(decode("Z"), None);
    }
}
