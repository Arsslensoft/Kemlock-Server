//! Access tokens: compact JWS signed with Ed25519 (`alg: EdDSA`).
//!
//! The claims are `sub` (account), `did` (device), `sid` (security stamp), `adm`, `iat`, `exp` and
//! `cnf.jkt`, the thumbprint of the device's DPoP key (RFC 9449 section 6). Tokens are checked
//! for signature and expiry here; whether `cnf.jkt` is the proof's key and whether the stamp is
//! still the account's is `kemlock_app::Authenticate`'s job.

use kemlock_app::b64url;
use kemlock_app::ports::{AccessClaims, CryptoError, TokenSigner};
use kemlock_crypto::ed25519::{self, SigningKey};
use kemlock_domain::{DeviceId, UserId};
use serde_json::{Value, json};
use std::fmt;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// The JWS protected header of every access token.
const HEADER: &str = r#"{"alg":"EdDSA","typ":"at+jwt"}"#;
/// How far in the future an `iat` may be before the token is refused.
const IAT_LEEWAY_SECS: i64 = 60;

struct Inner {
    key: SigningKey,
    public_key: [u8; 32],
}

/// Signs and checks access tokens. Cheap to clone.
#[derive(Clone)]
pub struct JwsTokenSigner {
    inner: Arc<Inner>,
}

impl fmt::Debug for JwsTokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsTokenSigner").finish_non_exhaustive()
    }
}

impl JwsTokenSigner {
    pub fn new(key: SigningKey) -> Self {
        let public_key = key.public_key();
        JwsTokenSigner {
            inner: Arc::new(Inner { key, public_key }),
        }
    }

    /// The public key tokens verify against.
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.public_key
    }
}

fn claim_uuid(claims: &Value, name: &str) -> Result<Uuid, CryptoError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(CryptoError::Invalid)
}

fn claim_time(claims: &Value, name: &str) -> Result<OffsetDateTime, CryptoError> {
    claims
        .get(name)
        .and_then(Value::as_i64)
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .ok_or(CryptoError::Invalid)
}

impl TokenSigner for JwsTokenSigner {
    fn sign(&self, claims: &AccessClaims) -> String {
        let payload = json!({
            "sub": claims.user.to_string(),
            "did": claims.device.to_string(),
            "sid": claims.security_stamp.to_string(),
            "adm": claims.admin,
            "atm": claims.auth_time.unix_timestamp(),
            "iat": claims.issued_at.unix_timestamp(),
            "exp": claims.expires_at.unix_timestamp(),
            "cnf": { "jkt": claims.jkt },
        });
        let signing_input = format!(
            "{}.{}",
            b64url::encode(HEADER.as_bytes()),
            b64url::encode(payload.to_string().as_bytes())
        );
        let signature = self.inner.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url::encode(&signature))
    }

    fn verify(&self, token: &str, now: OffsetDateTime) -> Result<AccessClaims, CryptoError> {
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CryptoError::Invalid);
        };
        // Only the header this server writes: no `alg` games.
        if b64url::decode(h).as_deref() != Some(HEADER.as_bytes()) {
            return Err(CryptoError::Invalid);
        }
        let signature = b64url::decode(s).ok_or(CryptoError::Invalid)?;
        let signing_input = format!("{h}.{p}");
        ed25519::verify(&self.inner.public_key, signing_input.as_bytes(), &signature)
            .map_err(|_| CryptoError::Invalid)?;

        let payload = b64url::decode(p).ok_or(CryptoError::Invalid)?;
        let claims: Value = serde_json::from_slice(&payload).map_err(|_| CryptoError::Invalid)?;
        let issued_at = claim_time(&claims, "iat")?;
        let auth_time = claim_time(&claims, "atm")?;
        let expires_at = claim_time(&claims, "exp")?;
        if expires_at <= now || issued_at.unix_timestamp() > now.unix_timestamp() + IAT_LEEWAY_SECS
        {
            return Err(CryptoError::Invalid);
        }
        let jkt = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(Value::as_str)
            .ok_or(CryptoError::Invalid)?
            .to_owned();
        Ok(AccessClaims {
            user: UserId(claim_uuid(&claims, "sub")?),
            device: DeviceId(claim_uuid(&claims, "did")?),
            jkt,
            security_stamp: claim_uuid(&claims, "sid")?,
            admin: claims
                .get("adm")
                .and_then(Value::as_bool)
                .ok_or(CryptoError::Invalid)?,
            auth_time,
            issued_at,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn signer() -> JwsTokenSigner {
        JwsTokenSigner::new(SigningKey::from_seed(&[1u8; 32]))
    }

    fn claims(now: OffsetDateTime) -> AccessClaims {
        AccessClaims {
            user: UserId::random(),
            device: DeviceId::random(),
            jkt: "thumbprint".to_owned(),
            security_stamp: Uuid::from_u128(5),
            admin: true,
            auth_time: now - Duration::minutes(40),
            issued_at: now,
            expires_at: now + Duration::minutes(10),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid time")
    }

    #[test]
    fn a_token_round_trips() {
        let c = claims(now());
        let token = signer().sign(&c);
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(signer().verify(&token, now()), Ok(c));
    }

    #[test]
    fn the_header_is_eddsa() {
        let token = signer().sign(&claims(now()));
        let header = b64url::decode(token.split('.').next().expect("a header")).expect("b64");
        assert_eq!(header, HEADER.as_bytes());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let token = signer().sign(&claims(now()));
        assert!(
            signer()
                .verify(&token, now() + Duration::minutes(9))
                .is_ok()
        );
        assert_eq!(
            signer().verify(&token, now() + Duration::minutes(10)),
            Err(CryptoError::Invalid)
        );
    }

    #[test]
    fn a_token_from_the_future_is_refused() {
        let token = signer().sign(&claims(now() + Duration::minutes(5)));
        assert_eq!(signer().verify(&token, now()), Err(CryptoError::Invalid));
    }

    #[test]
    fn another_servers_key_is_refused() {
        let token = signer().sign(&claims(now()));
        let other = JwsTokenSigner::new(SigningKey::from_seed(&[2u8; 32]));
        assert_eq!(other.verify(&token, now()), Err(CryptoError::Invalid));
    }

    #[test]
    fn tampering_with_the_payload_is_refused() {
        let c = claims(now());
        let token = signer().sign(&c);
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_claims = AccessClaims {
            admin: !c.admin,
            ..c
        };
        let forged = signer().sign(&forged_claims);
        let forged_payload = forged.split('.').nth(1).expect("a payload");
        parts[1] = forged_payload;
        assert_eq!(
            signer().verify(&parts.join("."), now()),
            Err(CryptoError::Invalid)
        );
    }

    #[test]
    fn other_headers_and_garbage_are_refused() {
        let s = signer();
        let token = s.sign(&claims(now()));
        let rest = token.split_once('.').expect("a dot").1;
        let none_header = b64url::encode(br#"{"alg":"none","typ":"at+jwt"}"#);
        for bad in [
            String::new(),
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            format!("{none_header}.{rest}"),
        ] {
            assert_eq!(s.verify(&bad, now()), Err(CryptoError::Invalid), "{bad}");
        }
    }

    #[test]
    fn the_token_carries_the_dpop_confirmation_claim() {
        let token = signer().sign(&claims(now()));
        let payload = b64url::decode(token.split('.').nth(1).expect("a payload")).expect("b64");
        let json: Value = serde_json::from_slice(&payload).expect("json");
        assert_eq!(json["cnf"]["jkt"], "thumbprint");
        assert_eq!(json["adm"], true);
    }
}
