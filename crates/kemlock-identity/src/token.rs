//! Reading the claims of a JWT whose signature something else has already checked, and the
//! shape rules for the claims SSO uses. The `openidconnect` crate verifies an ID token and
//! understands the standard claims; `amr`, `groups` and `sid` are read here, from the payload of
//! the same token, after verification.

use kemlock_app::b64url;
use kemlock_app::sso::{IdentityClaims, SsoError};
use serde_json::Value;

/// The longest compact JWT read; real tokens are a few KiB.
pub const MAX_TOKEN_LEN: usize = 32 * 1024;

/// The three parts of a compact JWT: header, payload, signature (all still base64url).
pub fn split(token: &str) -> Option<(&str, &str, &str)> {
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return None;
    }
    Some((header, payload, signature))
}

/// A JWT part decoded to JSON; it must be a JSON object.
pub fn decode_object(part: &str) -> Option<Value> {
    let bytes = b64url::decode(part)?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

/// A claim that is a string, or a list of strings, as a list. Values that aren't strings are
/// dropped. Providers send `amr` and `groups` both ways.
pub fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// A boolean claim, accepting the string `"true"` or `"false"` too, which some providers send.
pub fn flexible_bool(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn text(payload: &Value, name: &str) -> Option<String> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

/// The claims SSO needs from a verified ID token's payload.
pub fn identity_claims(payload: &Value) -> Result<IdentityClaims, SsoError> {
    let issuer = text(payload, "iss")
        .ok_or_else(|| SsoError::Token("the ID token has no iss".to_owned()))?;
    let subject = text(payload, "sub")
        .filter(|s| s.len() <= 255)
        .ok_or_else(|| SsoError::Token("the ID token has no usable sub".to_owned()))?;
    Ok(IdentityClaims {
        issuer,
        subject,
        email: text(payload, "email"),
        email_verified: flexible_bool(payload.get("email_verified")),
        name: text(payload, "name"),
        amr: string_list(payload.get("amr")),
        groups: string_list(payload.get("groups")),
        session_id: text(payload, "sid"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_compact_jwt_splits_in_three() {
        assert_eq!(split("a.b.c"), Some(("a", "b", "c")));
        assert_eq!(split("a.b."), Some(("a", "b", "")));
        assert_eq!(split("a.b"), None);
        assert_eq!(split("a.b.c.d"), None);
        assert_eq!(split(".b.c"), None);
        assert_eq!(split("a..c"), None);
        assert_eq!(split(&"x".repeat(MAX_TOKEN_LEN + 1)), None);
    }

    #[test]
    fn only_json_objects_decode() {
        let object = b64url::encode(br#"{"a":1}"#);
        assert_eq!(decode_object(&object), Some(json!({"a": 1})));
        assert_eq!(decode_object(&b64url::encode(b"[1]")), None);
        assert_eq!(decode_object(&b64url::encode(b"nope")), None);
        assert_eq!(decode_object("not base64!"), None);
    }

    #[test]
    fn lists_come_from_strings_or_arrays() {
        assert_eq!(string_list(Some(&json!("mfa"))), vec!["mfa"]);
        assert_eq!(
            string_list(Some(&json!(["pwd", "otp", 7, null]))),
            vec!["pwd", "otp"]
        );
        assert!(string_list(Some(&json!({"a": 1}))).is_empty());
        assert!(string_list(None).is_empty());
    }

    #[test]
    fn booleans_may_be_strings() {
        assert_eq!(flexible_bool(Some(&json!(true))), Some(true));
        assert_eq!(flexible_bool(Some(&json!("TRUE"))), Some(true));
        assert_eq!(flexible_bool(Some(&json!("false"))), Some(false));
        assert_eq!(flexible_bool(Some(&json!("yes"))), None);
        assert_eq!(flexible_bool(Some(&json!(1))), None);
        assert_eq!(flexible_bool(None), None);
    }

    #[test]
    fn the_claims_sso_needs_are_read() {
        let claims = identity_claims(&json!({
            "iss": "https://idp.example",
            "sub": "7f3a",
            "email": "ada@example.org",
            "email_verified": true,
            "name": "Ada Lovelace",
            "amr": ["pwd", "otp"],
            "groups": ["/eng", "/ops"],
            "sid": "s-1",
        }))
        .expect("valid");
        assert_eq!(claims.issuer, "https://idp.example");
        assert_eq!(claims.subject, "7f3a");
        assert_eq!(claims.email.as_deref(), Some("ada@example.org"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(claims.amr, vec!["pwd", "otp"]);
        assert_eq!(claims.groups, vec!["/eng", "/ops"]);
        assert_eq!(claims.session_id.as_deref(), Some("s-1"));
    }

    #[test]
    fn optional_claims_may_be_missing() {
        let claims = identity_claims(&json!({"iss": "i", "sub": "s"})).expect("valid");
        assert_eq!(claims.email, None);
        assert_eq!(claims.email_verified, None);
        assert!(claims.amr.is_empty());
        assert!(claims.groups.is_empty());
        assert_eq!(claims.session_id, None);
    }

    #[test]
    fn a_token_without_an_issuer_or_a_subject_is_refused() {
        assert!(identity_claims(&json!({"sub": "s"})).is_err());
        assert!(identity_claims(&json!({"iss": "i"})).is_err());
        assert!(identity_claims(&json!({"iss": "i", "sub": ""})).is_err());
        assert!(identity_claims(&json!({"iss": "i", "sub": "x".repeat(256)})).is_err());
    }
}
