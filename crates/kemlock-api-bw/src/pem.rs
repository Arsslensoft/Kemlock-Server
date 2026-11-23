//! Standard base64 and the PEM envelope around DER, for `rsa_key.pem`.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes standard base64, ignoring whitespace and trailing `=`; `None` for any other character.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let digits = {
        let end = digits.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
        &digits[..end]
    };
    if digits.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 4 * 3 + 3);
    for chunk in digits.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// `-----BEGIN <label>-----`, the base64 in 64-column lines, `-----END <label>-----`.
pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The label and DER of the first PEM block in `text`.
pub(crate) fn pem_decode(text: &str) -> Option<(String, Vec<u8>)> {
    let start = text.find("-----BEGIN ")?;
    let rest = &text[start + "-----BEGIN ".len()..];
    let label_end = rest.find("-----")?;
    let label = rest[..label_end].to_owned();
    let body = &rest[label_end + 5..];
    let end = body.find(&format!("-----END {label}-----"))?;
    Some((label, decode(&body[..end])?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded), Some(plain.as_bytes().to_vec()), "{coded}");
        }
        assert_eq!(decode("Zm9v\nYmFy\n"), Some(b"foobar".to_vec()));
        assert_eq!(decode("Zm9v!"), None);
        assert_eq!(decode("Z"), None);
    }

    #[test]
    fn binary_data_round_trips_through_a_pem_block() {
        let der: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let pem = pem_encode("RSA PRIVATE KEY", &der);
        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64 || l.starts_with("-----")));
        assert_eq!(pem_decode(&pem), Some(("RSA PRIVATE KEY".to_owned(), der)));
        assert_eq!(pem_decode("not a pem"), None);
    }
}
