//! DPoP proofs (RFC 9449): a token is useless without the device key that signed the proof sent
//! with it.
//!
//! A proof is a compact JWS in the `DPoP` header. It must have `typ: dpop+jwt`, `alg` ES256 (the
//! phones' hardware keys) or EdDSA, and the public key as `jwk`. Its claims must carry `htm` (the
//! request method), `htu` (scheme, host and path, no query, compared with the configured
//! `DOMAIN`), `iat` within 60 s of now, a `jti` not seen in the last 5 minutes, `ath` (the hash
//! of the access token) on authenticated calls, and the server's current `nonce`.
//!
//! Server nonces are stateless: an HMAC of the 5-minute window under a server key. A proof with
//! no nonce or an old one gets `401 use_dpop_nonce` and the current nonce in `DPoP-Nonce`.
//!
//! Proof ids are remembered in a [`TimedSet`]: time buckets that expire whole, hashed entries and
//! a hard cap. At the cap a new proof is refused with [`DpopError::Overloaded`] (a 503), because
//! forgetting ids to make room would let any proof be replayed.
//!
//! Two sets, so the ones anybody can fill can't starve the ones only a signed-in device can: a
//! proof with no access token (a token endpoint, where nobody is authenticated yet and anyone
//! may make a key and get the nonce) goes in the open set, with a smaller cap; a proof that
//! carries a valid access token goes in the authenticated set. A full open set refuses only
//! sign-ins and refreshes, never a call that already holds a token.

use crate::replay::{Full, TimedSet};
use kemlock_app::b64url;
use kemlock_crypto::{ed25519, hash, p256};
use serde_json::{Map, Value};

/// How far a proof's `iat` may be from the server's clock.
pub const IAT_LEEWAY_SECS: i64 = 60;
/// How long a `jti` is remembered.
pub const JTI_TTL_SECS: i64 = 300;
/// How long one nonce is the current one.
pub const NONCE_WINDOW_SECS: i64 = 300;
/// The most proof ids remembered at once. A client making a proof needs a valid signature and the
/// current nonce, so this is far above what honest devices produce in five minutes.
pub const MAX_TRACKED_JTIS: usize = 100_000;
/// The most proof ids remembered at once from requests with no access token (sign-in and
/// refresh). Anyone may make these, so they have a set and a cap of their own: filling it
/// refuses new sign-ins, and nothing else. Honest devices make a few per sign-in.
pub const MAX_OPEN_JTIS: usize = 25_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopError {
    /// The proof is unusable; the text says which rule it broke.
    Invalid(&'static str),
    /// The proof lacks the server's current nonce: retry with the one in `DPoP-Nonce`.
    UseNonce,
    /// The server remembers as many proof ids as it will: try again shortly.
    Overloaded,
}

#[derive(Debug)]
pub struct DpopVerifier {
    /// `DOMAIN` without a trailing slash: scheme, host, optional port and path prefix.
    base: String,
    nonce_key: [u8; 32],
    /// Proof ids of requests that carried an access token.
    seen: TimedSet,
    /// Proof ids of requests that did not: token endpoints, open to anyone.
    seen_open: TimedSet,
}

enum PublicKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    EdDsa { x: [u8; 32] },
}

/// scheme://host[:port]/path of a URL, lower-cased where URLs are case-insensitive, with default
/// ports dropped and the query and fragment removed.
pub fn normalise_htu(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let mut out = format!("{}://{}", url.scheme(), url.host_str()?);
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(url.path());
    Some(out)
}

fn str_member<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

fn parse_jwk(jwk: &Map<String, Value>) -> Result<(PublicKey, String), DpopError> {
    if jwk.contains_key("d") {
        return Err(DpopError::Invalid("the jwk holds a private key"));
    }
    let coordinate = |name: &str| -> Option<[u8; 32]> {
        let bytes = b64url::decode(str_member(jwk, name)?)?;
        bytes.try_into().ok()
    };
    match (str_member(jwk, "kty"), str_member(jwk, "crv")) {
        (Some("EC"), Some("P-256")) => {
            let (Some(x), Some(y)) = (coordinate("x"), coordinate("y")) else {
                return Err(DpopError::Invalid("the jwk's coordinates are malformed"));
            };
            // RFC 7638: required members only, in lexicographic order, no whitespace.
            let thumbprint = format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64url::encode(&x),
                b64url::encode(&y)
            );
            Ok((PublicKey::Es256 { x, y }, jwk_thumbprint(&thumbprint)))
        }
        (Some("OKP"), Some("Ed25519")) => {
            let Some(x) = coordinate("x") else {
                return Err(DpopError::Invalid("the jwk's key is malformed"));
            };
            let thumbprint = format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                b64url::encode(&x)
            );
            Ok((PublicKey::EdDsa { x }, jwk_thumbprint(&thumbprint)))
        }
        _ => Err(DpopError::Invalid("the jwk's key type isn't supported")),
    }
}

/// RFC 7638: the base64url SHA-256 of the canonical JWK.
fn jwk_thumbprint(canonical: &str) -> String {
    b64url::encode(&hash::sha256(canonical.as_bytes()))
}

fn parse_part(part: &str) -> Result<Value, DpopError> {
    let bytes = b64url::decode(part).ok_or(DpopError::Invalid("the proof isn't base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| DpopError::Invalid("the proof isn't JSON"))
}

impl DpopVerifier {
    /// `domain` is the configured `DOMAIN`, such as `https://vault.example.org`.
    pub fn new(domain: &str, nonce_key: [u8; 32]) -> Result<Self, String> {
        DpopVerifier::with_capacities(domain, nonce_key, MAX_TRACKED_JTIS, MAX_OPEN_JTIS)
    }

    /// [`DpopVerifier::new`] with one cap on the remembered proof ids of each set.
    pub fn with_capacity(domain: &str, nonce_key: [u8; 32], cap: usize) -> Result<Self, String> {
        DpopVerifier::with_capacities(domain, nonce_key, cap, cap)
    }

    /// [`DpopVerifier::new`] with its own caps: `cap` for proofs that carry an access token and
    /// `open_cap` for those that don't.
    pub fn with_capacities(
        domain: &str,
        nonce_key: [u8; 32],
        cap: usize,
        open_cap: usize,
    ) -> Result<Self, String> {
        let base = domain.trim().trim_end_matches('/').to_owned();
        let normal = normalise_htu(&format!("{base}/"))
            .ok_or_else(|| format!("DOMAIN {domain:?} isn't an http(s) URL"))?;
        Ok(DpopVerifier {
            base: normal.trim_end_matches('/').to_owned(),
            nonce_key,
            seen: TimedSet::new(JTI_TTL_SECS, cap),
            seen_open: TimedSet::new(JTI_TTL_SECS, open_cap),
        })
    }

    /// How many proof ids are remembered, in both sets.
    pub fn tracked(&self) -> usize {
        self.seen.len() + self.seen_open.len()
    }

    /// How many of them came from requests with no access token.
    pub fn tracked_open(&self) -> usize {
        self.seen_open.len()
    }

    /// The nonce for one 5-minute window.
    pub fn nonce_for_window(&self, window: i64) -> String {
        let w = window.to_be_bytes();
        let mut data = b"kemlock/v1/dpop-nonce".to_vec();
        data.extend_from_slice(&w);
        let mac = hash::hmac_sha256(&self.nonce_key, &data);
        let mut out = w.to_vec();
        out.extend_from_slice(&mac[..16]);
        b64url::encode(&out)
    }

    /// The nonce to hand out now.
    pub fn current_nonce(&self, now: i64) -> String {
        self.nonce_for_window(now.div_euclid(NONCE_WINDOW_SECS))
    }

    fn nonce_ok(&self, nonce: &str, now: i64) -> bool {
        let window = now.div_euclid(NONCE_WINDOW_SECS);
        // The current nonce and the one before, so a nonce handed out just before a rotation
        // still works for a request that was already on its way.
        [window, window - 1]
            .iter()
            .any(|w| hash::ct_eq(nonce.as_bytes(), self.nonce_for_window(*w).as_bytes()))
    }

    /// Checks a proof for a request. Returns the thumbprint of the proof's key.
    ///
    /// `path` is the request path as received (no query); `access_token` is the token the request
    /// presents, which the proof's `ath` must hash, or `None` on a token endpoint.
    pub fn verify(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        now: i64,
        access_token: Option<&str>,
    ) -> Result<String, DpopError> {
        let mut parts = proof.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(DpopError::Invalid("the proof isn't a compact JWS"));
        };
        let header = parse_part(h)?;
        let claims = parse_part(p)?;
        let signature =
            b64url::decode(s).ok_or(DpopError::Invalid("the signature isn't base64url"))?;

        if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
            return Err(DpopError::Invalid("the proof's typ must be dpop+jwt"));
        }
        let jwk = header
            .get("jwk")
            .and_then(Value::as_object)
            .ok_or(DpopError::Invalid("the proof has no jwk"))?;
        let (key, thumbprint) = parse_jwk(jwk)?;
        let signing_input = format!("{h}.{p}");
        let verified = match (header.get("alg").and_then(Value::as_str), &key) {
            (Some("ES256"), PublicKey::Es256 { x, y }) => {
                p256::verify_es256(x, y, signing_input.as_bytes(), &signature).is_ok()
            }
            (Some("EdDSA"), PublicKey::EdDsa { x }) => {
                ed25519::verify(x, signing_input.as_bytes(), &signature).is_ok()
            }
            _ => return Err(DpopError::Invalid("the proof's alg doesn't fit its jwk")),
        };
        if !verified {
            return Err(DpopError::Invalid("the proof's signature is wrong"));
        }

        let claims = claims
            .as_object()
            .ok_or(DpopError::Invalid("the proof's claims aren't an object"))?;
        if str_member(claims, "htm") != Some(method) {
            return Err(DpopError::Invalid("htm doesn't match the request method"));
        }
        let expected = normalise_htu(&format!("{}{}", self.base, path));
        let claimed = str_member(claims, "htu").and_then(normalise_htu);
        if expected.is_none() || expected != claimed {
            return Err(DpopError::Invalid("htu doesn't match the request URL"));
        }
        let iat = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(DpopError::Invalid("iat is missing"))?;
        if now.abs_diff(iat) > IAT_LEEWAY_SECS.unsigned_abs() {
            return Err(DpopError::Invalid("iat is too far from the server's clock"));
        }
        let jti = str_member(claims, "jti")
            .filter(|j| !j.is_empty() && j.len() <= 256)
            .ok_or(DpopError::Invalid("jti is missing"))?;
        if let Some(token) = access_token {
            let expected_ath = b64url::encode(&hash::sha256(token.as_bytes()));
            let ath = str_member(claims, "ath").unwrap_or_default();
            if !hash::ct_eq(ath.as_bytes(), expected_ath.as_bytes()) {
                return Err(DpopError::Invalid("ath doesn't match the access token"));
            }
        }
        match str_member(claims, "nonce") {
            Some(nonce) if self.nonce_ok(nonce, now) => {}
            _ => return Err(DpopError::UseNonce),
        }

        // Last, so a proof that is retried with a new nonce isn't taken for a replay, and so
        // only proofs that passed every other check take room.
        let set = if access_token.is_some() {
            &self.seen
        } else {
            &self.seen_open
        };
        match set.insert(format!("{thumbprint}:{jti}").as_bytes(), now) {
            Ok(true) => Ok(thumbprint),
            Ok(false) => Err(DpopError::Invalid("the proof was already used")),
            Err(Full) => Err(DpopError::Overloaded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{DpopSigner, ProofClaims};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn verifier() -> DpopVerifier {
        DpopVerifier::new("https://vault.example.org", [3u8; 32]).expect("a valid domain")
    }

    fn claims<'a>(jti: &'a str, nonce: &'a str) -> ProofClaims<'a> {
        ProofClaims {
            method: "POST",
            htu: "https://vault.example.org/kem/v1/auth/token",
            iat: NOW,
            jti,
            access_token: None,
            nonce: Some(nonce),
        }
    }

    fn good(v: &DpopVerifier, signer: &DpopSigner, jti: &str) -> String {
        let nonce = v.current_nonce(NOW);
        signer.proof(&claims(jti, &nonce))
    }

    const PATH: &str = "/kem/v1/auth/token";

    #[test]
    fn a_valid_es256_proof_gives_the_keys_thumbprint() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let proof = good(&v, &signer, "j1");
        let jkt = v.verify(&proof, "POST", PATH, NOW, None).expect("valid");
        assert_eq!(jkt, signer.thumbprint());
    }

    #[test]
    fn a_valid_eddsa_proof_works_too() {
        let v = verifier();
        let signer = DpopSigner::eddsa();
        let proof = good(&v, &signer, "j1");
        let jkt = v.verify(&proof, "POST", PATH, NOW, None).expect("valid");
        assert_eq!(jkt, signer.thumbprint());
    }

    #[test]
    fn the_thumbprint_follows_rfc_7638() {
        // The RFC's own example: an RSA key. Ours are EC and OKP, so check the member order and
        // the absence of whitespace by shape.
        let signer = DpopSigner::es256();
        let jwk = signer.jwk();
        let expected = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().expect("x"),
            jwk["y"].as_str().expect("y")
        );
        let digest = hash::sha256(expected.as_bytes());
        assert_eq!(signer.thumbprint(), b64url::encode(&digest));
    }

    #[test]
    fn a_proof_is_single_use() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let proof = good(&v, &signer, "j1");
        assert!(v.verify(&proof, "POST", PATH, NOW, None).is_ok());
        assert_eq!(
            v.verify(&proof, "POST", PATH, NOW + 10, None),
            Err(DpopError::Invalid("the proof was already used"))
        );
    }

    #[test]
    fn a_jti_is_forgotten_after_five_minutes() {
        let v = verifier();
        let signer = DpopSigner::es256();
        assert!(
            v.verify(&good(&v, &signer, "j1"), "POST", PATH, NOW, None)
                .is_ok()
        );
        // The same jti in a new proof, 6 minutes later (new nonce window too).
        let later = NOW + 360;
        let nonce = v.current_nonce(later);
        let proof = signer.proof(&ProofClaims {
            iat: later,
            ..claims("j1", &nonce)
        });
        assert!(v.verify(&proof, "POST", PATH, later, None).is_ok());
    }

    #[test]
    fn at_the_cap_new_proofs_are_refused_and_replays_are_still_recognised() {
        let v = DpopVerifier::with_capacity("https://vault.example.org", [3u8; 32], 2)
            .expect("a valid domain");
        let signer = DpopSigner::es256();
        assert!(
            v.verify(&good(&v, &signer, "a"), "POST", PATH, NOW, None)
                .is_ok()
        );
        let b = good(&v, &signer, "b");
        assert!(v.verify(&b, "POST", PATH, NOW, None).is_ok());
        assert_eq!(v.tracked(), 2);

        // The set is full: a third proof is refused rather than making the set grow or forget.
        assert_eq!(
            v.verify(&good(&v, &signer, "c"), "POST", PATH, NOW, None),
            Err(DpopError::Overloaded)
        );
        assert_eq!(v.tracked(), 2, "a refused proof is not remembered");
        // Replays are still told from new proofs, so a replay never gets in through a full set.
        assert_eq!(
            v.verify(&b, "POST", PATH, NOW + 1, None),
            Err(DpopError::Invalid("the proof was already used"))
        );
        // A proof that fails any earlier check takes no room either.
        let stale = v.nonce_for_window(NOW.div_euclid(NONCE_WINDOW_SECS) - 2);
        let old = signer.proof(&claims("d", &stale));
        assert_eq!(
            v.verify(&old, "POST", PATH, NOW, None),
            Err(DpopError::UseNonce)
        );
        assert_eq!(v.tracked(), 2);

        // Time frees room: six minutes on, the old ids are gone.
        let later = NOW + 360;
        let nonce = v.current_nonce(later);
        let fresh = signer.proof(&ProofClaims {
            iat: later,
            ..claims("c", &nonce)
        });
        assert!(v.verify(&fresh, "POST", PATH, later, None).is_ok());
        assert_eq!(v.tracked(), 1);
    }

    #[test]
    fn a_full_open_set_refuses_sign_ins_and_never_a_call_with_a_token() {
        let v = DpopVerifier::with_capacities("https://vault.example.org", [3u8; 32], 5, 2)
            .expect("a valid domain");
        let stranger = DpopSigner::es256();
        assert!(
            v.verify(&good(&v, &stranger, "a"), "POST", PATH, NOW, None)
                .is_ok()
        );
        assert!(
            v.verify(&good(&v, &stranger, "b"), "POST", PATH, NOW, None)
                .is_ok()
        );
        // Anyone can make keys and ask a token endpoint: the open set is now full.
        assert_eq!(
            v.verify(&good(&v, &stranger, "c"), "POST", PATH, NOW, None),
            Err(DpopError::Overloaded)
        );
        assert_eq!(v.tracked_open(), 2);

        // A device that holds an access token is not held back by it.
        let device = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        for jti in ["x", "y", "z"] {
            let proof = device.proof(&ProofClaims {
                access_token: Some("tok"),
                ..claims(jti, &nonce)
            });
            assert!(
                v.verify(&proof, "POST", PATH, NOW, Some("tok")).is_ok(),
                "{jti}"
            );
        }
        assert_eq!(v.tracked_open(), 2, "they took no room in the open set");
        assert_eq!(v.tracked(), 5);
    }

    #[test]
    fn the_method_and_url_must_match() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let proof = good(&v, &signer, "j1");
        assert!(v.verify(&proof, "GET", PATH, NOW, None).is_err());
        assert!(
            v.verify(&proof, "POST", "/kem/v1/other", NOW, None)
                .is_err()
        );
    }

    #[test]
    fn the_url_is_compared_without_query_and_with_default_ports() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        let proof = signer.proof(&ProofClaims {
            htu: "HTTPS://Vault.Example.org:443/kem/v1/auth/token?x=1#frag",
            ..claims("j1", &nonce)
        });
        assert!(v.verify(&proof, "POST", PATH, NOW, None).is_ok());
    }

    #[test]
    fn a_domain_with_a_path_prefix_is_part_of_the_url() {
        let v = DpopVerifier::new("https://example.org/vault/", [3u8; 32]).expect("valid");
        let signer = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        let proof = signer.proof(&ProofClaims {
            htu: "https://example.org/vault/kem/v1/auth/token",
            ..claims("j1", &nonce)
        });
        assert!(v.verify(&proof, "POST", PATH, NOW, None).is_ok());
    }

    #[test]
    fn iat_must_be_within_a_minute() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        for (jti, iat, ok) in [
            ("a", NOW - 60, true),
            ("b", NOW + 60, true),
            ("c", NOW - 61, false),
            ("d", NOW + 61, false),
            // A difference that does not fit in an i64 is just as far away.
            ("e", i64::MIN, false),
            ("f", i64::MAX, false),
        ] {
            let proof = signer.proof(&ProofClaims {
                iat,
                ..claims(jti, &nonce)
            });
            assert_eq!(
                v.verify(&proof, "POST", PATH, NOW, None).is_ok(),
                ok,
                "iat {iat}"
            );
        }
    }

    #[test]
    fn ath_must_hash_the_access_token() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        let with_ath = |jti: &str, token: &str| {
            signer.proof(&ProofClaims {
                access_token: Some(token),
                ..claims(jti, &nonce)
            })
        };
        assert!(
            v.verify(&with_ath("a", "tok"), "POST", PATH, NOW, Some("tok"))
                .is_ok()
        );
        assert!(
            v.verify(&with_ath("b", "tok"), "POST", PATH, NOW, Some("other"))
                .is_err()
        );
        // A proof with no ath where a token is presented.
        assert!(
            v.verify(&good(&v, &signer, "c"), "POST", PATH, NOW, Some("tok"))
                .is_err()
        );
    }

    #[test]
    fn a_missing_or_old_nonce_asks_for_the_current_one() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let none = signer.proof(&ProofClaims {
            nonce: None,
            ..claims("a", "")
        });
        assert_eq!(
            v.verify(&none, "POST", PATH, NOW, None),
            Err(DpopError::UseNonce)
        );
        let stale = v.nonce_for_window(NOW.div_euclid(NONCE_WINDOW_SECS) - 2);
        let old = signer.proof(&claims("b", &stale));
        assert_eq!(
            v.verify(&old, "POST", PATH, NOW, None),
            Err(DpopError::UseNonce)
        );
        // The nonce retry isn't a replay: the first proof's jti was never recorded.
        let retried = good(&v, &signer, "a");
        assert!(v.verify(&retried, "POST", PATH, NOW, None).is_ok());
    }

    #[test]
    fn the_previous_nonce_is_still_accepted() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let previous = v.nonce_for_window(NOW.div_euclid(NONCE_WINDOW_SECS) - 1);
        let proof = signer.proof(&claims("a", &previous));
        assert!(v.verify(&proof, "POST", PATH, NOW, None).is_ok());
    }

    #[test]
    fn nonces_rotate_every_five_minutes_and_depend_on_the_key() {
        let v = verifier();
        let a = v.current_nonce(NOW);
        assert_eq!(a, v.current_nonce(NOW + 1));
        assert_ne!(a, v.current_nonce(NOW + NONCE_WINDOW_SECS));
        let other = DpopVerifier::new("https://vault.example.org", [4u8; 32]).expect("valid");
        assert_ne!(a, other.current_nonce(NOW));
    }

    #[test]
    fn a_tampered_proof_is_refused() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let proof = good(&v, &signer, "j1");
        let mut parts: Vec<String> = proof.split('.').map(str::to_owned).collect();
        parts[1] = b64url::encode(
            json!({"htm":"POST","htu":"https://vault.example.org/kem/v1/auth/token",
                   "iat":NOW,"jti":"j1","nonce":v.current_nonce(NOW),"extra":1})
            .to_string()
            .as_bytes(),
        );
        assert_eq!(
            v.verify(&parts.join("."), "POST", PATH, NOW, None),
            Err(DpopError::Invalid("the proof's signature is wrong"))
        );
    }

    #[test]
    fn structure_typ_alg_and_jwk_are_checked() {
        let v = verifier();
        let signer = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        let claims = json!({"htm":"POST","htu":"https://vault.example.org/kem/v1/auth/token",
                            "iat":NOW,"jti":"j","nonce":nonce});
        let jwk = signer.jwk();

        for garbage in ["", "a.b", "a.b.c.d", "!!!.!!!.!!!"] {
            assert!(
                v.verify(garbage, "POST", PATH, NOW, None).is_err(),
                "{garbage}"
            );
        }
        let wrong_typ = signer.sign_parts(&json!({"typ":"JWT","alg":"ES256","jwk":jwk}), &claims);
        assert!(v.verify(&wrong_typ, "POST", PATH, NOW, None).is_err());
        let wrong_alg =
            signer.sign_parts(&json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":jwk}), &claims);
        assert!(v.verify(&wrong_alg, "POST", PATH, NOW, None).is_err());
        let hs256 = signer.sign_parts(&json!({"typ":"dpop+jwt","alg":"HS256","jwk":jwk}), &claims);
        assert!(v.verify(&hs256, "POST", PATH, NOW, None).is_err());
        let no_jwk = signer.sign_parts(&json!({"typ":"dpop+jwt","alg":"ES256"}), &claims);
        assert!(v.verify(&no_jwk, "POST", PATH, NOW, None).is_err());
        let mut private = jwk.clone();
        private["d"] = json!("AAAA");
        let with_d = signer.sign_parts(
            &json!({"typ":"dpop+jwt","alg":"ES256","jwk":private}),
            &claims,
        );
        assert!(v.verify(&with_d, "POST", PATH, NOW, None).is_err());
    }

    #[test]
    fn a_proof_signed_by_another_key_than_its_jwk_is_refused() {
        let v = verifier();
        let claimed = DpopSigner::es256();
        let actual = DpopSigner::es256();
        let nonce = v.current_nonce(NOW);
        let claims = json!({"htm":"POST","htu":"https://vault.example.org/kem/v1/auth/token",
                            "iat":NOW,"jti":"j","nonce":nonce});
        // Signed with `actual`, but the header names `claimed`'s key.
        let forged = actual.sign_parts(
            &json!({"typ":"dpop+jwt","alg":"ES256","jwk":claimed.jwk()}),
            &claims,
        );
        assert!(v.verify(&forged, "POST", PATH, NOW, None).is_err());
    }

    #[test]
    fn the_domain_must_be_an_http_url() {
        assert!(DpopVerifier::new("not a url", [0; 32]).is_err());
        assert!(DpopVerifier::new("ftp://example.org", [0; 32]).is_err());
        assert!(DpopVerifier::new("http://localhost:8080", [0; 32]).is_ok());
    }
}
