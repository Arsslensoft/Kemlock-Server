//! Registering a security key through the web vault's routes, as the Kemlock app's server test
//! does it (`mobile/test/vaultwarden_server/api_test.dart:332-381`, `_registerKey`).
//!
//! The "key" here is a credential of the right shape whose public key is the P-256 generator point:
//! a valid point on the curve, which is all registration checks of an attestation of format
//! `none`. Nothing here can sign, so these tests ask for the challenge and never answer it.

use crate::enc::{b64url, bytes_of, random_bytes};
use crate::http::Session;
use crate::util::{authority, hex_decode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The x coordinate of the P-256 generator point.
const GENERATOR_X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
/// The y coordinate of the P-256 generator point.
const GENERATOR_Y: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/// A security key registered on an account.
#[derive(Debug, Clone)]
pub struct Key {
    /// The credential id, base64url.
    pub credential_id: String,
    /// The relying party id the server challenges for: the host of its domain.
    pub rp_id: String,
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    assert!(text.len() < 24, "short texts only");
    out.push(0x60 | u8::try_from(text.len()).unwrap_or(0));
    out.extend_from_slice(text.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = bytes.len();
    if length < 24 {
        out.push(0x40 | u8::try_from(length).unwrap_or(0));
    } else if length < 256 {
        out.push(0x58);
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(length).unwrap_or(0).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// The attestation object, format `none`: user present, attested credential data, no AAGUID, a
/// counter of 0 (`api_test.dart:358-368`).
pub fn attestation_object(rp_id: &str, credential_id: &[u8]) -> Vec<u8> {
    let mut auth = Vec::new();
    auth.extend_from_slice(&bytes_of(Sha256::digest(rp_id.as_bytes())));
    auth.push(0x41);
    auth.extend_from_slice(&[0, 0, 0, 0]);
    auth.extend_from_slice(&[0u8; 16]);
    auth.extend_from_slice(
        &u16::try_from(credential_id.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    auth.extend_from_slice(credential_id);
    // A COSE key: EC2 (kty 2), ES256 (alg -7), P-256 (crv 1), x and y
    auth.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    auth.extend_from_slice(&hex_decode(GENERATOR_X));
    auth.extend_from_slice(&[0x22, 0x58, 0x20]);
    auth.extend_from_slice(&hex_decode(GENERATOR_Y));

    let mut out = vec![0xa3];
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    out.push(0xa0);
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, &auth);
    out
}

async fn send(session: &Session, method: &str, path: &str, body: &Value) -> Value {
    let reply = session.send(session.call(method, path).json(body)).await;
    reply.ok_json(path)
}

/// Registers a key on the account of `session` through
/// `get-webauthn`, `get-webauthn-challenge` and `PUT /api/two-factor/webauthn`. The server's own
/// origin is the session's base address, so its `DOMAIN` must be that address. A refusal panics
/// with the answer.
pub async fn register_key(session: &Session) -> Key {
    let base = session.http.base().to_owned();
    let host = authority(&base);
    let rp_id = host.split(':').next().unwrap_or_default().to_owned();
    let hash = &session.account.hash;

    let first = send(
        session,
        "POST",
        "/api/two-factor/get-webauthn",
        &json!({"masterPasswordHash": hash}),
    )
    .await;
    let verification = crate::util::key_of(&first, "userVerificationToken")
        .cloned()
        .unwrap_or(Value::Null);
    let created = send(
        session,
        "POST",
        "/api/two-factor/get-webauthn-challenge",
        &json!({"masterPasswordHash": hash, "userVerificationToken": verification}),
    )
    .await;
    let options = crate::util::key_of(&created, "options")
        .cloned()
        .unwrap_or_else(|| created.clone());
    let challenge = crate::util::key_of(&options, "challenge")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("get-webauthn-challenge: no challenge in {created}"))
        .to_owned();

    let credential = random_bytes(16);
    let client_data = json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": base,
        "crossOrigin": false,
    });
    let id = b64url(&credential);
    send(
        session,
        "PUT",
        "/api/two-factor/webauthn",
        &json!({
            "id": 1,
            "name": "Kemlock contract key",
            "masterPasswordHash": hash,
            "userVerificationToken": verification,
            "deviceResponse": {
                "id": id,
                "rawId": id,
                "type": "public-key",
                "extensions": {},
                "response": {
                    "AttestationObject": b64url(&attestation_object(&rp_id, &credential)),
                    "clientDataJson": b64url(client_data.to_string().as_bytes()),
                },
            },
        }),
    )
    .await;
    Key {
        credential_id: id,
        rp_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attestation_object_is_a_cbor_map_of_three() {
        let object = attestation_object("localhost", &[1, 2, 3]);
        assert_eq!(object[0], 0xa3);
        assert_eq!(&object[1..5], &[0x63, b'f', b'm', b't']);
        // The map's header, "fmt" and "none", "attStmt" and its empty map, "authData" and its
        // header of two bytes, then the authData: 32 + 1 + 4 + 16 + 2 + 3 + 77 = 135 bytes
        assert_eq!(object.len(), 1 + 4 + 5 + 8 + 1 + 9 + 2 + 135);
    }
}
