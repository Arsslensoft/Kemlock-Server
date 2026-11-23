//! Access tokens (compact JWS, EdDSA). The first byte picks what the rest is. Even: the text of a
//! token, which never verifies but must be refused without a panic. Odd: a claims object, laid
//! over valid claims and signed with the server's key, so the claim checks are reached. A token
//! that verifies has not expired.

#![no_main]

use kemlock_api_kem::JwsTokenSigner;
use kemlock_app::b64url;
use kemlock_app::ports::TokenSigner;
use kemlock_crypto::ed25519::SigningKey;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use time::OffsetDateTime;

const NOW: i64 = 1_800_000_000;
/// The header the server writes, and the only one it reads.
const HEADER: &str = r#"{"alg":"EdDSA","typ":"at+jwt"}"#;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let now = OffsetDateTime::from_unix_timestamp(NOW).expect("a valid time");
    let signer = JwsTokenSigner::new(SigningKey::from_seed(&[1; 32]));

    if mode % 2 == 0 {
        if let Ok(text) = std::str::from_utf8(rest) {
            let _ = signer.verify(text, now);
        }
        return;
    }

    let mut claims = json!({
        "sub": "00000000-0000-0000-0000-000000000001",
        "did": "00000000-0000-0000-0000-000000000002",
        "sid": "00000000-0000-0000-0000-000000000003",
        "adm": false,
        "atm": NOW,
        "iat": NOW,
        "exp": NOW + 600,
        "cnf": { "jkt": "thumbprint" },
    });
    if let (Value::Object(into), Ok(Value::Object(over))) =
        (&mut claims, serde_json::from_slice::<Value>(rest))
    {
        into.extend(over);
    }
    let signing_input = format!(
        "{}.{}",
        b64url::encode(HEADER.as_bytes()),
        b64url::encode(claims.to_string().as_bytes())
    );
    let key = SigningKey::from_seed(&[1; 32]);
    let token = format!(
        "{signing_input}.{}",
        b64url::encode(&key.sign(signing_input.as_bytes()))
    );
    if let Ok(accepted) = signer.verify(&token, now) {
        assert!(accepted.expires_at > now, "an expired token was accepted");
    }
});
