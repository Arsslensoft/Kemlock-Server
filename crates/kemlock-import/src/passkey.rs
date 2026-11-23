//! Reading passkey parts as formats write them: base64 in either alphabet, PEM, and which COSE
//! algorithm a PKCS#8 key is for.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};

use crate::model::COSE_ES256;

/// Bytes from base64 in the standard or the URL-safe alphabet, with or without padding.
pub fn decode_base64_any(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text
        .trim()
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    STANDARD_NO_PAD.decode(cleaned.as_bytes()).ok()
}

/// Base64url without padding.
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Standard base64 with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// The DER inside a PEM block (the first one in `pem`); `None` when there is none or its base64 is
/// damaged.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            inside = true;
        } else if line.starts_with("-----END") {
            break;
        } else if inside {
            body.push_str(line);
        }
    }
    if body.is_empty() {
        return None;
    }
    STANDARD.decode(body.as_bytes()).ok()
}

/// The COSE algorithm of a PKCS#8 private key, from the algorithm identifier near its start:
/// -7 (ES256) for a P-256 key, -8 (EdDSA) for Ed25519, -257 (RS256) for RSA. `None` for any other
/// key or for bytes that aren't PKCS#8.
pub fn cose_algorithm_of_pkcs8(der: &[u8]) -> Option<i32> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let head = &der[..der.len().min(64)];
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    // id-ecPublicKey with the prime256v1 curve.
    if has(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) {
        Some(COSE_ES256)
    } else if has(&[0x06, 0x03, 0x2B, 0x65, 0x70]) {
        Some(-8)
    } else if has(&[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ]) {
        Some(-257)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PKCS#8 of a P-256 key: the fixed prefix every such key starts with, then a zeroed body.
    fn p256_pkcs8() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
            0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        ];
        der.extend_from_slice(&[0; 100]);
        der
    }

    #[test]
    fn base64_in_either_alphabet() {
        assert_eq!(decode_base64_any("+/8="), Some(vec![0xFB, 0xFF]));
        assert_eq!(decode_base64_any("-_8"), Some(vec![0xFB, 0xFF]));
        assert_eq!(decode_base64_any(" AQID "), Some(vec![1, 2, 3]));
        assert_eq!(decode_base64_any("!!"), None);
        assert_eq!(encode_base64url(&[0xFB, 0xFF]), "-_8");
        assert_eq!(encode_base64(&[0xFB, 0xFF]), "+/8=");
    }

    #[test]
    fn pem_is_unwrapped() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAQID\nBAUG\n-----END PRIVATE KEY-----\n";
        assert_eq!(pem_to_der(pem), Some(vec![1, 2, 3, 4, 5, 6]));
        assert_eq!(pem_to_der("no pem here"), None);
        assert_eq!(pem_to_der("-----BEGIN X-----\n!!\n-----END X-----"), None);
    }

    #[test]
    fn the_algorithm_is_read_from_the_key() {
        assert_eq!(cose_algorithm_of_pkcs8(&p256_pkcs8()), Some(COSE_ES256));
        let mut ed = vec![
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        ];
        ed.extend_from_slice(&[0; 40]);
        assert_eq!(cose_algorithm_of_pkcs8(&ed), Some(-8));
        let mut rsa = vec![
            0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
            0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        ];
        rsa.extend_from_slice(&[0; 40]);
        assert_eq!(cose_algorithm_of_pkcs8(&rsa), Some(-257));
        assert_eq!(cose_algorithm_of_pkcs8(b"not der"), None);
        assert_eq!(cose_algorithm_of_pkcs8(&[]), None);
        assert_eq!(
            cose_algorithm_of_pkcs8(&[0x30, 0x03, 0x01, 0x02, 0x03]),
            None
        );
    }
}
