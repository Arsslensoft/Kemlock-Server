//! Unpadded base64url (RFC 4648 section 5), strict: a decoder refuses `=`, `+`, `/`, a length of 1
//! modulo 4, and text that does not encode again to itself.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The unpadded base64url text of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The bytes of unpadded base64url `text`, or `None` for anything that is not the one canonical
/// spelling of some byte string.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let input = text.as_bytes();
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = ((acc << 6) | u32::from(v)) & 0x00ff_ffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1u32 << bits) - 1;
        }
    }
    // The bits that don't make a byte must be zero, or the text isn't canonical.
    if acc != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_unpadded_url_alphabet() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(encode(&[0u8; 32]), "A".repeat(43));
    }

    #[test]
    fn decodes_what_it_encodes() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 7 % 256).unwrap_or(0))
                .collect();
            assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn refuses_everything_but_the_canonical_spelling() {
        for bad in [
            "Zg==",
            "Zg=",
            "Z",
            "Zm9vY",
            "+/8",
            "ab+c",
            "ab/c",
            "Zh",
            "Zm9 v",
            "Zm9vYmF\n",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        assert_eq!(decode("Zg"), Some(b"f".to_vec()));
    }
}
