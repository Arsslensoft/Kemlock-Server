//! The client side of DPoP: builds proofs with a software key. For this crate's tests, the
//! server's tests and tools; phones use their hardware keys.

use kemlock_app::b64url;
use kemlock_crypto::{ed25519, hash, p256};
use serde_json::{Map, Value, json};
use std::fmt;

enum Key {
    Es256(p256::SigningKey),
    EdDsa(ed25519::SigningKey),
}

/// A DPoP key and what it takes to sign proofs with it.
pub struct DpopSigner {
    key: Key,
}

impl fmt::Debug for DpopSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopSigner").finish_non_exhaustive()
    }
}

/// The claims of one proof.
#[derive(Clone, Copy, Debug)]
pub struct ProofClaims<'a> {
    pub method: &'a str,
    /// The request URL as the proof states it.
    pub htu: &'a str,
    pub iat: i64,
    pub jti: &'a str,
    /// The access token the request carries, for `ath`.
    pub access_token: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl DpopSigner {
    /// A new P-256 key, as phones have.
    pub fn es256() -> Self {
        DpopSigner {
            key: Key::Es256(p256::SigningKey::generate()),
        }
    }

    /// A new Ed25519 key.
    pub fn eddsa() -> Self {
        DpopSigner {
            key: Key::EdDsa(ed25519::SigningKey::generate()),
        }
    }

    pub fn alg(&self) -> &'static str {
        match self.key {
            Key::Es256(_) => "ES256",
            Key::EdDsa(_) => "EdDSA",
        }
    }

    /// The public key as a JWK.
    pub fn jwk(&self) -> Value {
        match &self.key {
            Key::Es256(key) => {
                let (x, y) = key.public_xy();
                json!({"kty":"EC","crv":"P-256","x":b64url::encode(&x),"y":b64url::encode(&y)})
            }
            Key::EdDsa(key) => {
                json!({"kty":"OKP","crv":"Ed25519","x":b64url::encode(&key.public_key())})
            }
        }
    }

    /// The RFC 7638 thumbprint of the public key.
    pub fn thumbprint(&self) -> String {
        let canonical = match &self.key {
            Key::Es256(key) => {
                let (x, y) = key.public_xy();
                format!(
                    r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                    b64url::encode(&x),
                    b64url::encode(&y)
                )
            }
            Key::EdDsa(key) => format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                b64url::encode(&key.public_key())
            ),
        };
        b64url::encode(&hash::sha256(canonical.as_bytes()))
    }

    /// A proof with the usual header and the given claims.
    pub fn proof(&self, claims: &ProofClaims<'_>) -> String {
        let header = json!({"typ":"dpop+jwt","alg":self.alg(),"jwk":self.jwk()});
        let mut body = Map::new();
        body.insert("htm".to_owned(), json!(claims.method));
        body.insert("htu".to_owned(), json!(claims.htu));
        body.insert("iat".to_owned(), json!(claims.iat));
        body.insert("jti".to_owned(), json!(claims.jti));
        if let Some(token) = claims.access_token {
            body.insert(
                "ath".to_owned(),
                json!(b64url::encode(&hash::sha256(token.as_bytes()))),
            );
        }
        if let Some(nonce) = claims.nonce {
            body.insert("nonce".to_owned(), json!(nonce));
        }
        self.sign_parts(&header, &Value::Object(body))
    }

    /// Signs any header and claims, for building proofs that break a rule.
    pub fn sign_parts(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            b64url::encode(header.to_string().as_bytes()),
            b64url::encode(claims.to_string().as_bytes())
        );
        let signature: [u8; 64] = match &self.key {
            Key::Es256(key) => key.sign(signing_input.as_bytes()),
            Key::EdDsa(key) => key.sign(signing_input.as_bytes()),
        };
        format!("{signing_input}.{}", b64url::encode(&signature))
    }
}
