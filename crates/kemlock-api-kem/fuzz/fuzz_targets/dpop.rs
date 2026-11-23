//! DPoP proofs (RFC 9449). The first byte picks what the rest is. Even: the text of a proof, which
//! never verifies but must be refused without a panic. Odd: a header and a claims object, JSON
//! separated by a newline, laid over a valid proof's and signed with the proof's own key, so the
//! checks behind the signature are reached too. A proof that is accepted is accepted only once.

#![no_main]

use kemlock_api_kem::dpop::{DpopVerifier, normalise_htu};
use kemlock_app::b64url;
use kemlock_crypto::ed25519::SigningKey;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const NOW: i64 = 1_800_000_000;
const DOMAIN: &str = "https://vault.example.org";
const PATH: &str = "/kem/v1/auth/token";

/// `base` with the members of the JSON object in `extra` laid over it, when there is one.
fn overlay(mut base: Value, extra: &[u8]) -> Value {
    if let (Value::Object(into), Ok(Value::Object(over))) =
        (&mut base, serde_json::from_slice::<Value>(extra))
    {
        into.extend(over);
    }
    base
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let verifier = DpopVerifier::new(DOMAIN, [7; 32]).expect("the domain is an https URL");

    if mode % 2 == 0 {
        if let Ok(text) = std::str::from_utf8(rest) {
            let _ = normalise_htu(text);
            let _ = verifier.verify(text, "POST", PATH, NOW, None);
            let _ = verifier.verify(text, "GET", "/kem/v1/sync", NOW, Some("an access token"));
        }
        return;
    }

    let key = SigningKey::from_seed(&[3; 32]);
    let split = rest.iter().position(|b| *b == b'\n');
    let (head, tail) = match split {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, &[][..]),
    };
    let header = overlay(
        json!({
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url::encode(&key.public_key()) },
        }),
        head,
    );
    let claims = overlay(
        json!({
            "htm": "POST",
            "htu": format!("{DOMAIN}{PATH}"),
            "iat": NOW,
            "jti": "proof-1",
            "nonce": verifier.current_nonce(NOW),
        }),
        tail,
    );
    let signing_input = format!(
        "{}.{}",
        b64url::encode(header.to_string().as_bytes()),
        b64url::encode(claims.to_string().as_bytes())
    );
    let proof = format!(
        "{signing_input}.{}",
        b64url::encode(&key.sign(signing_input.as_bytes()))
    );
    if verifier.verify(&proof, "POST", PATH, NOW, None).is_ok() {
        assert!(
            verifier.verify(&proof, "POST", PATH, NOW, None).is_err(),
            "a proof must be refused the second time"
        );
    }
});
