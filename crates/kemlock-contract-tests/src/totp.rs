//! An authenticator code (RFC 6238 with SHA-1, six digits, 30 seconds), enough to turn the
//! authenticator on through the web vault's routes and answer the second step.

use sha1::{Digest, Sha1};

/// A base32 text (RFC 4648, any case, no padding needed) as bytes; characters that are not base32
/// are skipped.
pub fn base32_decode(text: &str) -> Vec<u8> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => continue,
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    out
}

fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).iter().copied().collect()
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut block = if key.len() > 64 {
        sha1(key)
    } else {
        key.to_vec()
    };
    block.resize(64, 0);
    let mut inner: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);
    let mut outer: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// The six-digit code of the base32 `secret` at `unix_seconds`.
pub fn code_at(secret: &str, unix_seconds: u64) -> String {
    let key = base32_decode(secret);
    let counter = unix_seconds / 30;
    let mac = hmac_sha1(&key, &counter.to_be_bytes());
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let value = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    format!("{:06}", value % 1_000_000)
}

/// Now, in Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238's SHA-1 vectors, whose secret is the ASCII "12345678901234567890"; the RFC gives
    // eight digits, of which these are the last six.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc_6238_vectors() {
        assert_eq!(code_at(SECRET, 59), "287082");
        assert_eq!(code_at(SECRET, 1_111_111_109), "081804");
        assert_eq!(code_at(SECRET, 1_234_567_890), "005924");
    }

    #[test]
    fn base32_reads_a_known_text() {
        assert_eq!(base32_decode("MZXW6YTBOI"), b"foobar".to_vec());
    }
}
