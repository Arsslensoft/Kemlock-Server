//! RS256 tokens, signed with the key in `rsa_key.pem`.
//!
//! Vaultwarden signs every token it makes (access tokens, file-download links, registration and
//! two-step "remember" tokens) with one 2048-bit RSA key kept in `DATA_FOLDER/rsa_key.pem`, as
//! PKCS#1 text. This module reads that file as it is, so a server copied from Vaultwarden keeps its
//! key, and makes a new one (PKCS#8 text) when there is none.

use crate::pem;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    self, KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair,
};
use kemlock_app::b64url;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::path::Path;

/// The file Vaultwarden keeps its token key in.
pub const KEY_FILE: &str = "rsa_key.pem";

/// How far a token's `exp` and `nbf` may be off, as Vaultwarden allows: 30 seconds.
const LEEWAY_SECS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("can't read or write {path}: {message}")]
    Io { path: String, message: String },
    #[error("{0}")]
    Invalid(&'static str),
}

/// Why a token wasn't accepted. Clients only see a 401, so the text is for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("Token is invalid")]
    Invalid,
    #[error("Issuer is invalid")]
    Issuer,
    #[error("Token has expired")]
    Expired,
}

/// The token key: signs and checks RS256 tokens.
pub struct TokenKeys {
    pair: RsaKeyPair,
    public_key: Vec<u8>,
    /// The PEM text of the private key, which also seeds the unknown-email prelogin settings.
    pem: String,
}

impl std::fmt::Debug for TokenKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKeys").finish_non_exhaustive()
    }
}

impl TokenKeys {
    /// Reads `rsa_key.pem` from `folder`, or makes a 2048-bit key and writes it there.
    pub fn load_or_create(folder: &Path) -> Result<Self, KeyError> {
        let path = folder.join(KEY_FILE);
        let io = |e: std::io::Error| KeyError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::from_pem(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let keys = Self::generate()?;
                match write_new_private(&path, keys.pem.as_bytes()) {
                    Ok(()) => {
                        tracing::info!(path = %path.display(), "made the token key");
                        Ok(keys)
                    }
                    // Another start made the key between our read and our write: use theirs.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        Self::from_pem(&std::fs::read_to_string(&path).map_err(io)?)
                    }
                    Err(e) => Err(io(e)),
                }
            }
            Err(e) => Err(io(e)),
        }
    }

    /// A new 2048-bit key.
    pub fn generate() -> Result<Self, KeyError> {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048)
            .map_err(|_| KeyError::Invalid("couldn't make an RSA key"))?;
        let der: Pkcs8V1Der<'static> = pair
            .as_der()
            .map_err(|_| KeyError::Invalid("couldn't write the RSA key"))?;
        let pem = pem::pem_encode("PRIVATE KEY", der.as_ref());
        Self::from_pair(pair, pem)
    }

    /// Reads a key from PEM text: PKCS#1 (`RSA PRIVATE KEY`, Vaultwarden's) or PKCS#8
    /// (`PRIVATE KEY`).
    pub fn from_pem(text: &str) -> Result<Self, KeyError> {
        let (label, der) = pem::pem_decode(text).ok_or(KeyError::Invalid("not a PEM file"))?;
        let pair = match label.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            _ => return Err(KeyError::Invalid("not an RSA private key")),
        }
        .map_err(|_| KeyError::Invalid("the RSA key isn't valid"))?;
        Self::from_pair(pair, text.to_owned())
    }

    fn from_pair(pair: RsaKeyPair, pem: String) -> Result<Self, KeyError> {
        let public_key = pair.public_key().as_ref().to_vec();
        Ok(TokenKeys {
            pair,
            public_key,
            pem,
        })
    }

    /// The private key's PEM text.
    pub(crate) fn pem(&self) -> &str {
        &self.pem
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let mut out = vec![0u8; self.pair.public_modulus_len()];
        self.pair
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), message, &mut out)
            .map_err(|_| KeyError::Invalid("couldn't sign"))?;
        Ok(out)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, self.public_key.as_slice())
            .verify(message, signature)
            .is_ok()
    }

    /// A compact JWS over `claims`, header `{"typ":"JWT","alg":"RS256"}` as `jsonwebtoken` writes it.
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, KeyError> {
        let body = serde_json::to_vec(claims).map_err(|_| KeyError::Invalid("bad claims"))?;
        let input = format!(
            "{}.{}",
            b64url::encode(br#"{"typ":"JWT","alg":"RS256"}"#),
            b64url::encode(&body)
        );
        let signature = self.sign(input.as_bytes())?;
        Ok(format!("{input}.{}", b64url::encode(&signature)))
    }

    /// The claims of a token signed by this key, with `iss` equal to `issuer` and `exp` and `nbf`
    /// valid at `now` (Unix seconds), to within 30 seconds. Whitespace in the token is ignored.
    pub fn decode<T: DeserializeOwned>(
        &self,
        token: &str,
        issuer: &str,
        now: i64,
    ) -> Result<T, TokenError> {
        let token: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        let Some((input, signature)) = token.rsplit_once('.') else {
            return Err(TokenError::Invalid);
        };
        let Some((header, body)) = input.split_once('.') else {
            return Err(TokenError::Invalid);
        };
        if body.contains('.') {
            return Err(TokenError::Invalid);
        }
        let header: Value = b64url::decode(header)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(TokenError::Invalid)?;
        if header.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err(TokenError::Invalid);
        }
        let signature = b64url::decode(signature).ok_or(TokenError::Invalid)?;
        if !self.verify(input.as_bytes(), &signature) {
            return Err(TokenError::Invalid);
        }
        let claims: Value = b64url::decode(body)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(TokenError::Invalid)?;
        if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
            return Err(TokenError::Issuer);
        }
        let exp = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or(TokenError::Invalid)?;
        if exp < now - LEEWAY_SECS {
            return Err(TokenError::Expired);
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
            && nbf > now + LEEWAY_SECS
        {
            return Err(TokenError::Invalid);
        }
        serde_json::from_value(claims).map_err(|_| TokenError::Invalid)
    }
}

/// Writes a new file only the server's user can read; fails if the file exists.
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// The claims of an access token, as Vaultwarden's `LoginJwtClaims`. Vaultwarden leaves the
/// organization lists out of the token, so this does too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LoginClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The user id.
    pub sub: String,
    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    /// The user's security stamp: a changed stamp ends the session.
    pub sstamp: String,
    /// The device id.
    pub device: String,
    /// What kind of device, such as `Android` or `Linux`.
    pub devicetype: String,
    /// `web`, `cli`, `mobile` and so on; `undefined` when the client sent none.
    pub client_id: String,
    pub scope: Vec<String>,
    pub amr: Vec<String>,
    /// The identifier the app signs in with, so a change it makes can name it as its `ContextId`.
    /// Absent in tokens made before the server kept identifiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
}

/// A download link's claims: valid for one minute, for one attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct FileDownloadClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The cipher id.
    pub sub: String,
    pub file_id: String,
}

/// The token `register/send-verification-email` hands out and `register/finish` takes back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct RegisterVerifyClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The email address.
    pub sub: String,
    pub name: Option<String>,
    pub verified: bool,
}

/// The "remember this device" token a successful second step can hand back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct RememberClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The device id.
    pub sub: String,
    pub user_uuid: String,
    /// The account's two-step version when the token was made (`TwoFactorRepo::two_step_version`).
    /// A change to the account's methods moves it, which ends every token made before. Tokens
    /// from before the field existed read as 0.
    #[serde(default)]
    pub two_step_version: i64,
    /// The token's other fields sealed under `server.key` (see [`RememberClaims::bound`]). A token
    /// made without it, or with a proof that doesn't open, is no token: whoever holds `rsa_key.pem`
    /// (an old copy of it, say) can sign the claims but can't make the proof.
    #[serde(default)]
    pub proof: String,
}

/// What `proof` seals the claims under in `server.key`.
const REMEMBER_PURPOSE: &str = "bitwarden-remember-device";

impl RememberClaims {
    /// The text a proof covers: the device, the account, the two-step version and the expiry.
    fn bound_text(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}",
            self.sub, self.user_uuid, self.two_step_version, self.exp
        )
        .into_bytes()
    }

    /// The claims with their proof made under the server's own key, which the RSA signing key
    /// doesn't give.
    #[must_use]
    pub fn bound(mut self, seal: &kemlock_crypto::seal::ServerSeal) -> Self {
        self.proof = b64url::encode(&seal.seal(REMEMBER_PURPOSE, &self.bound_text()));
        self
    }

    /// Whether the proof opens under the server's key to these very claims.
    pub fn is_bound(&self, seal: &kemlock_crypto::seal::ServerSeal) -> bool {
        b64url::decode(&self.proof)
            .and_then(|sealed| seal.open(REMEMBER_PURPOSE, &sealed).ok())
            .is_some_and(|text| kemlock_crypto::hash::ct_eq(&text, &self.bound_text()))
    }
}

/// Making a 2048-bit key takes a moment, so the tests of every module share one.
#[cfg(test)]
pub(crate) fn shared_test_keys() -> &'static TokenKeys {
    use std::sync::OnceLock;
    static KEYS: OnceLock<TokenKeys> = OnceLock::new();
    KEYS.get_or_init(|| TokenKeys::generate().expect("a key is made"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(exp: i64) -> Value {
        json!({"nbf": 1_000, "exp": exp, "iss": "https://vault.test|login", "sub": "x"})
    }

    fn remember(exp: i64) -> RememberClaims {
        RememberClaims {
            nbf: 1_000,
            exp,
            iss: "https://vault.test|2faremember".to_owned(),
            sub: "device".to_owned(),
            user_uuid: "user".to_owned(),
            two_step_version: 3,
            proof: String::new(),
        }
    }

    #[test]
    fn a_remember_token_is_good_only_with_a_proof_made_under_the_servers_key() {
        use kemlock_crypto::seal::ServerSeal;
        let seal = ServerSeal::new(&[7; 32]);
        let bound = remember(5_000).bound(&seal);
        assert!(bound.is_bound(&seal));
        // No proof (a token signed with the RSA key alone), or one under another key.
        assert!(!remember(5_000).is_bound(&seal));
        assert!(!bound.is_bound(&ServerSeal::new(&[8; 32])));
        // A proof moved onto other claims doesn't fit them.
        for other in [
            RememberClaims { sub: "another".to_owned(), ..bound.clone() },
            RememberClaims { user_uuid: "someone".to_owned(), ..bound.clone() },
            RememberClaims { two_step_version: 4, ..bound.clone() },
            RememberClaims { exp: 9_999, ..bound.clone() },
        ] {
            assert!(!other.is_bound(&seal));
        }
        let junk = RememberClaims { proof: "not a proof".to_owned(), ..bound };
        assert!(!junk.is_bound(&seal));
    }

    #[test]
    fn a_signed_token_opens_with_the_same_key() {
        let keys = shared_test_keys();
        let token = keys.encode(&claims(5_000)).expect("signed");
        assert_eq!(token.split('.').count(), 3);
        let back: Value = keys
            .decode(&token, "https://vault.test|login", 2_000)
            .expect("decodes");
        assert_eq!(back["sub"], "x");
        assert!(
            keys.decode::<Value>(&format!(" {token}\n"), "https://vault.test|login", 2_000)
                .is_ok()
        );
    }

    #[test]
    fn the_header_is_what_jsonwebtoken_writes() {
        let token = shared_test_keys().encode(&claims(5_000)).expect("signed");
        let header = token.split('.').next().expect("a header");
        assert_eq!(
            b64url::decode(header).expect("base64url"),
            br#"{"typ":"JWT","alg":"RS256"}"#
        );
    }

    #[test]
    fn wrong_issuers_expired_and_early_tokens_are_refused() {
        let keys = shared_test_keys();
        let token = keys.encode(&claims(5_000)).expect("signed");
        assert_eq!(
            keys.decode::<Value>(&token, "https://other.test|login", 2_000),
            Err(TokenError::Issuer)
        );
        // 30 seconds of leeway either side.
        assert!(
            keys.decode::<Value>(&token, "https://vault.test|login", 5_030)
                .is_ok()
        );
        assert_eq!(
            keys.decode::<Value>(&token, "https://vault.test|login", 5_031),
            Err(TokenError::Expired)
        );
        assert_eq!(
            keys.decode::<Value>(&token, "https://vault.test|login", 969),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn tampered_and_foreign_tokens_are_refused() {
        let keys = shared_test_keys();
        let token = keys.encode(&claims(5_000)).expect("signed");
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_body = b64url::encode(claims(9_999_999).to_string().as_bytes());
        parts[1] = &forged_body;
        assert_eq!(
            keys.decode::<Value>(&parts.join("."), "https://vault.test|login", 2_000),
            Err(TokenError::Invalid)
        );
        let other = TokenKeys::generate().expect("another key");
        assert_eq!(
            other.decode::<Value>(&token, "https://vault.test|login", 2_000),
            Err(TokenError::Invalid)
        );
        for junk in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert_eq!(
                keys.decode::<Value>(junk, "https://vault.test|login", 2_000),
                Err(TokenError::Invalid),
                "{junk}"
            );
        }
        // An unsigned token ("alg":"none") is not accepted.
        let none = format!(
            "{}.{}.",
            b64url::encode(br#"{"alg":"none"}"#),
            b64url::encode(claims(5_000).to_string().as_bytes())
        );
        assert_eq!(
            keys.decode::<Value>(&none, "https://vault.test|login", 2_000),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn the_key_file_is_made_once_and_read_back() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let first = TokenKeys::load_or_create(dir.path()).expect("made");
        let text = std::fs::read_to_string(dir.path().join(KEY_FILE)).expect("written");
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----"));
        let token = first.encode(&claims(5_000)).expect("signed");
        let second = TokenKeys::load_or_create(dir.path()).expect("read back");
        assert!(
            second
                .decode::<Value>(&token, "https://vault.test|login", 2_000)
                .is_ok()
        );
        assert_eq!(second.pem(), first.pem());
    }

    #[test]
    fn junk_key_files_are_refused() {
        assert!(TokenKeys::from_pem("hello").is_err());
        assert!(
            TokenKeys::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
                .is_err()
        );
        assert!(
            TokenKeys::from_pem(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
            )
            .is_err()
        );
    }
}
