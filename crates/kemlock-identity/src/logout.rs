//! Back-channel logout tokens (OpenID Connect Back-Channel Logout 1.0, section 2.4 and 2.6).
//!
//! A logout token is a signed JWT the provider posts to the server when a person's session there
//! ends. It is valid when its signature checks against the provider's keys, its issuer and
//! audience are ours, it is fresh, it carries the `backchannel-logout` event, it names a subject
//! or a session id, and it has no `nonce` (that would make it an ID token, which must not end
//! a session).

use crate::token::{decode_object, split, string_list};
use kemlock_app::b64url;
use kemlock_app::sso::{LogoutClaims, SsoError};
use openidconnect::core::{CoreJsonWebKeySet, CoreJwsSigningAlgorithm};
use openidconnect::{JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyUse, JwsSigningAlgorithm};
use serde_json::Value;

/// The member of `events` that makes a token a back-channel logout token.
pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How far a token's `iat` may be in the future (clock skew), in seconds.
const SKEW_SECS: i64 = 60;
/// How old a token's `iat` may be, in seconds. A provider posts it as the session ends.
const MAX_AGE_SECS: i64 = 10 * 60;

/// Why a token's signature wasn't accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The token isn't a JWT, or names an algorithm this server won't verify (`none`, `HS*`).
    Malformed(String),
    /// None of the provider's keys fits the token's `kid` and algorithm. After a key rotation
    /// this means the cached key set is stale.
    NoKey,
    /// A key fits and the signature doesn't verify.
    Bad,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::Malformed(why) => write!(f, "malformed token: {why}"),
            SignatureError::NoKey => f.write_str("no key of the provider fits the token"),
            SignatureError::Bad => f.write_str("the signature doesn't verify"),
        }
    }
}

/// The signature algorithms accepted: asymmetric ones only. A logout token is never signed with
/// the client secret, and `none` is no signature.
fn allowed(alg: &CoreJwsSigningAlgorithm) -> bool {
    matches!(
        alg,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512
            | CoreJwsSigningAlgorithm::RsaSsaPssSha256
            | CoreJwsSigningAlgorithm::RsaSsaPssSha384
            | CoreJwsSigningAlgorithm::RsaSsaPssSha512
            | CoreJwsSigningAlgorithm::EcdsaP256Sha256
            | CoreJwsSigningAlgorithm::EcdsaP384Sha384
            | CoreJwsSigningAlgorithm::EdDsa
    )
}

/// Checks the token's signature against `jwks` and returns its payload, unchecked otherwise.
pub fn verify_signature(token: &str, jwks: &CoreJsonWebKeySet) -> Result<Value, SignatureError> {
    let malformed = |why: &str| SignatureError::Malformed(why.to_owned());
    let (header_part, payload_part, signature_part) =
        split(token).ok_or_else(|| malformed("not a compact JWT"))?;
    let header = decode_object(header_part).ok_or_else(|| malformed("the header isn't JSON"))?;
    let payload = decode_object(payload_part).ok_or_else(|| malformed("the payload isn't JSON"))?;
    let signature =
        b64url::decode(signature_part).ok_or_else(|| malformed("the signature isn't base64url"))?;

    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("no alg"))?;
    let alg: CoreJwsSigningAlgorithm = serde_json::from_value(Value::String(alg_name.to_owned()))
        .map_err(|_| malformed("an unknown alg"))?;
    if !allowed(&alg) {
        return Err(malformed("an algorithm that isn't accepted"));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let signing_input = format!("{header_part}.{payload_part}");

    let mut fitting = 0usize;
    for key in jwks.keys() {
        if let Some(kid) = kid
            && key.key_id().map(|id| id.as_str()) != Some(kid)
        {
            continue;
        }
        if alg.key_type().as_ref() != Some(key.key_type()) {
            continue;
        }
        if key.key_use().is_some_and(|u| !u.allows_signature()) {
            continue;
        }
        match key.signing_alg() {
            JsonWebKeyAlgorithm::Unspecified => {}
            JsonWebKeyAlgorithm::Algorithm(key_alg) if *key_alg == alg => {}
            _ => continue,
        }
        fitting += 1;
        if key
            .verify_signature(&alg, signing_input.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(payload);
        }
    }
    Err(if fitting == 0 {
        SignatureError::NoKey
    } else {
        SignatureError::Bad
    })
}

/// Checks the claims of a logout token whose signature has verified: issuer, audience, time,
/// event, subject or session id, no nonce. `now` is seconds since the Unix epoch.
pub fn check_claims(
    payload: &Value,
    issuer: &str,
    client_id: &str,
    now: i64,
) -> Result<LogoutClaims, SsoError> {
    let refuse = |why: &str| SsoError::Token(format!("logout token: {why}"));

    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("no iss"))?;
    if iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(refuse("the issuer isn't the provider's"));
    }
    if !string_list(payload.get("aud"))
        .iter()
        .any(|a| a == client_id)
    {
        return Err(refuse("the audience isn't this client"));
    }
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| refuse("no iat"))?;
    if iat > now + SKEW_SECS {
        return Err(refuse("issued in the future"));
    }
    if iat < now - MAX_AGE_SECS {
        return Err(refuse("issued too long ago"));
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| refuse("no exp"))?;
    if exp < now - SKEW_SECS {
        return Err(refuse("expired"));
    }
    if payload
        .get("jti")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(refuse("no jti"));
    }
    let event = payload
        .get("events")
        .and_then(Value::as_object)
        .and_then(|events| events.get(LOGOUT_EVENT));
    if !event.is_some_and(Value::is_object) {
        return Err(refuse("no backchannel-logout event"));
    }
    if payload.get("nonce").is_some() {
        return Err(refuse("it has a nonce, so it is an ID token"));
    }
    let subject = payload
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let session_id = payload
        .get("sid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if subject.is_none() && session_id.is_none() {
        return Err(refuse("it names neither a sub nor a sid"));
    }
    Ok(LogoutClaims {
        issuer: iss.to_owned(),
        subject,
        session_id,
    })
}

/// Validates a logout token in one go: signature against `jwks`, then the claims.
pub fn validate_logout_token(
    token: &str,
    jwks: &CoreJsonWebKeySet,
    issuer: &str,
    client_id: &str,
    now: i64,
) -> Result<LogoutClaims, SsoError> {
    let payload =
        verify_signature(token, jwks).map_err(|e| SsoError::Token(format!("logout token: {e}")))?;
    check_claims(&payload, issuer, client_id, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Es256Signer;
    use serde_json::json;

    const ISSUER: &str = "https://idp.example/realms/kemlock";
    const CLIENT: &str = "kemlock";
    const NOW: i64 = 1_800_000_000;

    fn jwks(signer: &Es256Signer) -> CoreJsonWebKeySet {
        serde_json::from_value(json!({"keys": [signer.jwk()]})).expect("a valid key set")
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER,
            "aud": CLIENT,
            "iat": NOW,
            "exp": NOW + 120,
            "jti": "j-1",
            "sub": "7f3a",
            "sid": "s-1",
            "events": { LOGOUT_EVENT: {} },
        })
    }

    fn check(payload: &Value) -> Result<LogoutClaims, SsoError> {
        check_claims(payload, ISSUER, CLIENT, NOW)
    }

    #[test]
    fn a_valid_token_names_its_subject_and_session() {
        let signer = Es256Signer::new("k1");
        let token = signer.sign(&claims());
        let got =
            validate_logout_token(&token, &jwks(&signer), ISSUER, CLIENT, NOW).expect("valid");
        assert_eq!(got.issuer, ISSUER);
        assert_eq!(got.subject.as_deref(), Some("7f3a"));
        assert_eq!(got.session_id.as_deref(), Some("s-1"));
    }

    #[test]
    fn a_session_id_alone_is_enough_and_so_is_a_subject_alone() {
        let mut only_sid = claims();
        only_sid.as_object_mut().expect("object").remove("sub");
        let got = check(&only_sid).expect("valid");
        assert_eq!(got.subject, None);
        assert_eq!(got.session_id.as_deref(), Some("s-1"));

        let mut only_sub = claims();
        only_sub.as_object_mut().expect("object").remove("sid");
        assert_eq!(
            check(&only_sub).expect("valid").subject.as_deref(),
            Some("7f3a")
        );
    }

    #[test]
    fn the_audience_may_be_a_list_that_holds_the_client() {
        let mut c = claims();
        c["aud"] = json!(["other", CLIENT]);
        assert!(check(&c).is_ok());
    }

    #[test]
    fn a_forged_or_foreign_signature_is_refused() {
        let signer = Es256Signer::new("k1");
        let other = Es256Signer::new("k1");
        let token = other.sign(&claims());
        // Same kid, different key: the signature doesn't verify.
        assert_eq!(
            verify_signature(&token, &jwks(&signer)),
            Err(SignatureError::Bad)
        );
        // A different kid: no key fits.
        let stranger = Es256Signer::new("k-other").sign(&claims());
        assert_eq!(
            verify_signature(&stranger, &jwks(&signer)),
            Err(SignatureError::NoKey)
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let signer = Es256Signer::new("k1");
        let token = signer.sign(&claims());
        let (header, _payload, signature) = split(&token).expect("three parts");
        let mut evil = claims();
        evil["sub"] = json!("someone-else");
        let forged = format!(
            "{header}.{}.{signature}",
            b64url::encode(evil.to_string().as_bytes())
        );
        assert_eq!(
            verify_signature(&forged, &jwks(&signer)),
            Err(SignatureError::Bad)
        );
    }

    #[test]
    fn unsigned_and_symmetric_tokens_are_refused() {
        let signer = Es256Signer::new("k1");
        for alg in ["none", "HS256", "nonsense"] {
            let header = b64url::encode(json!({"alg": alg, "kid": "k1"}).to_string().as_bytes());
            let payload = b64url::encode(claims().to_string().as_bytes());
            let token = format!("{header}.{payload}.AAAA");
            assert!(
                matches!(
                    verify_signature(&token, &jwks(&signer)),
                    Err(SignatureError::Malformed(_))
                ),
                "{alg}"
            );
        }
    }

    #[test]
    fn garbage_is_refused() {
        let signer = Es256Signer::new("k1");
        for bad in ["", "a.b", "a.b.c.d", "x.y.z", "....", "{}"] {
            assert!(verify_signature(bad, &jwks(&signer)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_key_set_without_a_fitting_key_gives_no_key() {
        let signer = Es256Signer::new("k1");
        let token = signer.sign(&claims());
        let empty: CoreJsonWebKeySet = serde_json::from_value(json!({"keys": []})).expect("empty");
        assert_eq!(verify_signature(&token, &empty), Err(SignatureError::NoKey));
    }

    #[test]
    fn the_issuer_and_audience_must_be_ours() {
        let mut c = claims();
        c["iss"] = json!("https://evil.example");
        assert!(check(&c).is_err());
        let mut c = claims();
        c["aud"] = json!("another-client");
        assert!(check(&c).is_err());
        let mut c = claims();
        c.as_object_mut().expect("object").remove("aud");
        assert!(check(&c).is_err());
        // A trailing slash on either side is the same issuer.
        let mut c = claims();
        c["iss"] = json!(format!("{ISSUER}/"));
        assert!(check(&c).is_ok());
    }

    #[test]
    fn a_stale_or_future_or_expired_token_is_refused() {
        let mut c = claims();
        c["iat"] = json!(NOW - 3600);
        assert!(check(&c).is_err(), "too old");
        let mut c = claims();
        c["iat"] = json!(NOW + 3600);
        assert!(check(&c).is_err(), "from the future");
        let mut c = claims();
        c["exp"] = json!(NOW - 300);
        assert!(check(&c).is_err(), "expired");
        // A little skew is fine.
        let mut c = claims();
        c["iat"] = json!(NOW + 30);
        assert!(check(&c).is_ok());
    }

    #[test]
    fn the_required_claims_must_be_there() {
        for missing in ["iat", "exp", "jti", "events"] {
            let mut c = claims();
            c.as_object_mut().expect("object").remove(missing);
            assert!(check(&c).is_err(), "{missing}");
        }
        let mut c = claims();
        c["jti"] = json!("");
        assert!(check(&c).is_err());
    }

    #[test]
    fn the_event_must_be_the_logout_event_with_an_object_value() {
        let mut c = claims();
        c["events"] = json!({"http://schemas.openid.net/event/other": {}});
        assert!(check(&c).is_err());
        let mut c = claims();
        c["events"] = json!({ LOGOUT_EVENT: "yes" });
        assert!(check(&c).is_err());
        let mut c = claims();
        c["events"] = json!("backchannel-logout");
        assert!(check(&c).is_err());
    }

    #[test]
    fn a_nonce_makes_it_an_id_token_and_is_refused() {
        let mut c = claims();
        c["nonce"] = json!("abc");
        assert!(check(&c).is_err());
    }

    #[test]
    fn a_token_naming_nobody_is_refused() {
        let mut c = claims();
        let object = c.as_object_mut().expect("object");
        object.remove("sub");
        object.remove("sid");
        assert!(check(&c).is_err());
        let mut c = claims();
        c["sub"] = json!("");
        c["sid"] = json!("");
        assert!(check(&c).is_err());
    }
}
