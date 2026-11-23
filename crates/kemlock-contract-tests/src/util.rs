//! Small checks and conversions the tests share.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// The text of an error answer as the Kemlock app reads it: the first of `message`,
/// `error_description` and `error` (any case, top level) that is a non-empty string.
/// (`mobile/lib/features/sync/vaultwarden/vw_api.dart:714-721`, `_message`)
pub fn message_of(body: &Value) -> Option<String> {
    let object = body.as_object()?;
    for wanted in ["message", "error_description", "error"] {
        for (name, value) in object {
            if name.eq_ignore_ascii_case(wanted)
                && let Some(text) = value.as_str()
                && !text.is_empty()
            {
                return Some(text.to_owned());
            }
        }
    }
    None
}

/// A key of `value`, whatever its case, as the apps match them (`jsonKey` in `vw_api.dart:206-213`).
pub fn key_of<'a>(value: &'a Value, wanted: &str) -> Option<&'a Value> {
    let object = value.as_object()?;
    if let Some(found) = object.get(wanted) {
        return Some(found);
    }
    object
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, found)| found)
}

/// Whether the dotted version `version` is `minimum` or later; anything after the numbers is
/// ignored. (`vw_items.dart:67-81`, `versionAtLeast`)
pub fn version_at_least(version: &str, minimum: &str) -> bool {
    fn parts(text: &str) -> Option<[u64; 3]> {
        let mut out = [0u64; 3];
        let mut seen = 0;
        for (i, piece) in text.trim().split('.').take(3).enumerate() {
            let digits: String = piece.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                break;
            }
            out[i] = digits.parse().ok()?;
            seen += 1;
        }
        if seen == 0 { None } else { Some(out) }
    }
    match (parts(version), parts(minimum)) {
        (Some(a), Some(b)) => a >= b,
        _ => false,
    }
}

/// Whether `text` is a UUID in its hyphenated form.
pub fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    groups.len() == 5
        && groups.iter().zip(lengths).all(|(group, length)| {
            group.len() == length && group.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// Whether `text` is three non-empty base64url parts joined by dots, as a JWT is.
pub fn is_jwt(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The header and the claims of a JWT, decoded; the signature is not checked.
pub fn jwt_parts(token: &str) -> Option<(Value, Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let claims = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    Some((
        serde_json::from_slice(&header).ok()?,
        serde_json::from_slice(&claims).ok()?,
    ))
}

/// The `host:port` part of an address, lower case: `http://Localhost:8080/x` gives `localhost:8080`.
pub fn authority(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase()
}

/// Percent-encodes `text` for a form body or a query: everything but the unreserved characters.
pub fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Bytes from hexadecimal text; pairs that are not hex are left out.
pub fn hex_decode(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .filter_map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_compare_as_the_app_compares_them() {
        assert!(version_at_least("2024.12.0", "2024.12.0"));
        assert!(version_at_least("2026.6.0", "2024.12.0"));
        assert!(version_at_least("2025.1", "2024.12.0"));
        assert!(!version_at_least("2024.11.9", "2024.12.0"));
        assert!(!version_at_least("0.1.0", "2024.12.0"));
        assert!(!version_at_least("banana", "2024.12.0"));
        assert!(version_at_least("2024.12.0-beta", "2024.12.0"));
    }

    #[test]
    fn message_takes_the_first_named_text() {
        assert_eq!(
            message_of(&json!({"Message": "out of date", "error": "x"})).as_deref(),
            Some("out of date")
        );
        assert_eq!(message_of(&json!({"error": ""})), None);
        assert_eq!(message_of(&json!([1])), None);
    }

    #[test]
    fn small_conversions() {
        assert!(is_uuid("6e2c8a25-7c9f-4495-99b2-baca86b89fce"));
        assert!(!is_uuid("6e2c8a25"));
        assert!(is_jwt("a.b.c"));
        assert!(!is_jwt("a.b"));
        assert_eq!(authority("http://Localhost:8080/x?y"), "localhost:8080");
        assert_eq!(percent_encode("a+b/c="), "a%2Bb%2Fc%3D");
        assert_eq!(hex_decode("00ff10"), vec![0, 255, 16]);
    }
}
