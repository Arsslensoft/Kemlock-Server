//! Test support: a software WebAuthn authenticator.
//!
//! [`SoftwareAuthenticator`] holds a P-256 key and makes what a browser sends back from
//! `navigator.credentials.create` (an attestation of format `none`) and `get` (a signed assertion),
//! as `PublicKeyCredential.toJSON()` would write them. It takes the options a server made, so a
//! test plays the whole ceremony against the real relying party in [`crate::WebAuthnRp`].
//!
//! Knobs make it misbehave: another origin or relying party id, no user verification, a counter
//! that does not move. The Bitwarden spelling of an answer (`AttestationObject`, `clientDataJson`)
//! is [`bitwarden_registration`] and [`bitwarden_assertion`].

use kemlock_app::b64url;
use kemlock_crypto::{hash, p256, rand};
use serde_json::{Value, json};

/// User present.
const FLAG_UP: u8 = 0x01;
/// User verified.
const FLAG_UV: u8 = 0x04;
/// Attested credential data follows.
const FLAG_AT: u8 = 0x40;

/// A security key or passkey made of software, for tests.
pub struct SoftwareAuthenticator {
    key: p256::SigningKey,
    credential_id: Vec<u8>,
    rp_id: String,
    origin: String,
    counter: u32,
    user_verified: bool,
    user_handle: Option<Vec<u8>>,
}

impl std::fmt::Debug for SoftwareAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareAuthenticator")
            .field("rp_id", &self.rp_id)
            .field("origin", &self.origin)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SoftwareAuthenticator {
    /// A new authenticator for the relying party `rp_id`, used from the page at `origin` (the
    /// scheme, host and port the browser reports, such as `https://vault.example.org`).
    pub fn new(rp_id: &str, origin: &str) -> Self {
        SoftwareAuthenticator {
            key: p256::SigningKey::generate(),
            credential_id: rand::bytes::<32>().to_vec(),
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            counter: 0,
            user_verified: true,
            user_handle: None,
        }
    }

    /// The credential id the authenticator makes.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Whether answers claim the person was verified (a PIN, a fingerprint). On by default.
    pub fn set_user_verified(&mut self, verified: bool) {
        self.user_verified = verified;
    }

    /// The signature counter the next answer will move on from.
    pub fn set_counter(&mut self, counter: u32) {
        self.counter = counter;
    }

    /// The origin answers claim, for a page of another site.
    pub fn set_origin(&mut self, origin: &str) {
        self.origin = origin.to_owned();
    }

    /// The relying party id answers are made for.
    pub fn set_rp_id(&mut self, rp_id: &str) {
        self.rp_id = rp_id.to_owned();
    }

    /// The options' `publicKey` object, whether or not the caller wrapped it.
    fn public_key(options: &Value) -> &Value {
        options.get("publicKey").unwrap_or(options)
    }

    fn client_data(&self, kind: &str, options: &Value) -> Vec<u8> {
        json!({
            "type": kind,
            "challenge": Self::public_key(options)["challenge"],
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut flags = FLAG_UP;
        if self.user_verified {
            flags |= FLAG_UV;
        }
        if attested {
            flags |= FLAG_AT;
        }
        flags
    }

    /// The registration answer for creation options: an attestation of format `none` carrying the
    /// credential's public key. Remembers the user handle the options name.
    pub fn create(&mut self, options: &Value) -> Value {
        let public_key = Self::public_key(options);
        self.user_handle = public_key["user"]["id"].as_str().and_then(b64url::decode);
        let client_data = self.client_data("webauthn.create", options);

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&hash::sha256(self.rp_id.as_bytes()));
        auth_data.push(self.flags(true));
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        auth_data.extend_from_slice(&self.credential_id);
        // A COSE key: EC2 (kty 2), ES256 (alg -7), P-256 (crv 1), x and y.
        let (x, y) = self.key.public_xy();
        auth_data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        auth_data.extend_from_slice(&x);
        auth_data.extend_from_slice(&[0x22, 0x58, 0x20]);
        auth_data.extend_from_slice(&y);

        let mut attestation = vec![0xa3];
        cbor_text(&mut attestation, "fmt");
        cbor_text(&mut attestation, "none");
        cbor_text(&mut attestation, "attStmt");
        attestation.push(0xa0);
        cbor_text(&mut attestation, "authData");
        cbor_bytes(&mut attestation, &auth_data);

        let id = b64url::encode(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "attestationObject": b64url::encode(&attestation),
                "clientDataJSON": b64url::encode(&client_data),
            },
            "clientExtensionResults": {},
        })
    }

    /// The sign-in answer for request options: a signature over the authenticator data and the
    /// client data, with the counter moved on by one.
    pub fn get(&mut self, options: &Value) -> Value {
        self.counter = self.counter.wrapping_add(1);
        let client_data = self.client_data("webauthn.get", options);

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&hash::sha256(self.rp_id.as_bytes()));
        auth_data.push(self.flags(false));
        auth_data.extend_from_slice(&self.counter.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&hash::sha256(&client_data));
        let signature = der_signature(&self.key.sign(&signed));

        let id = b64url::encode(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url::encode(&auth_data),
                "clientDataJSON": b64url::encode(&client_data),
                "signature": b64url::encode(&signature),
                "userHandle": self.user_handle.as_deref().map(b64url::encode),
            },
            "clientExtensionResults": {},
        })
    }
}

/// A registration answer in the spelling Bitwarden's clients send as `deviceResponse`:
/// `AttestationObject` and `clientDataJson`, with `extensions` for the extension results.
pub fn bitwarden_registration(answer: &Value) -> Value {
    json!({
        "id": answer["id"],
        "rawId": answer["rawId"],
        "type": answer["type"],
        "extensions": {},
        "response": {
            "AttestationObject": answer["response"]["attestationObject"],
            "clientDataJson": answer["response"]["clientDataJSON"],
        },
    })
}

/// A sign-in answer in the spelling the Bitwarden clients send as the `twoFactorToken` of provider
/// 7 (`clientDataJson`, no user handle, `extensions.appid`), as the text the client sends.
pub fn bitwarden_assertion(answer: &Value) -> String {
    json!({
        "id": answer["id"],
        "rawId": answer["rawId"],
        "type": answer["type"],
        "extensions": {"appid": false},
        "response": {
            "authenticatorData": answer["response"]["authenticatorData"],
            "clientDataJson": answer["response"]["clientDataJSON"],
            "signature": answer["response"]["signature"],
        },
    })
    .to_string()
}

/// A short CBOR text string.
fn cbor_text(out: &mut Vec<u8>, text: &str) {
    out.push(0x60 | u8::try_from(text.len()).unwrap_or(0));
    out.extend_from_slice(text.as_bytes());
}

/// A CBOR byte string of up to 65,535 bytes.
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = bytes.len();
    if length < 24 {
        out.push(0x40 | u8::try_from(length).unwrap_or(0));
    } else if length < 256 {
        out.push(0x58);
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// An unsigned big-endian integer as a DER INTEGER: leading zeros cut, one zero added back when the
/// top bit is set.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[first..];
    let mut out = vec![0x02];
    if trimmed[0] & 0x80 != 0 {
        out.push(u8::try_from(trimmed.len() + 1).unwrap_or(0));
        out.push(0);
    } else {
        out.push(u8::try_from(trimmed.len()).unwrap_or(0));
    }
    out.extend_from_slice(trimmed);
    out
}

/// An ECDSA signature `r ‖ s` as the DER `SEQUENCE` WebAuthn carries.
fn der_signature(signature: &[u8; 64]) -> Vec<u8> {
    let r = der_integer(&signature[..32]);
    let s = der_integer(&signature[32..]);
    let mut out = vec![0x30, u8::try_from(r.len() + s.len()).unwrap_or(0)];
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_der_with_the_sign_bit_kept_clear() {
        assert_eq!(der_integer(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
        assert_eq!(der_integer(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(der_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(
            der_integer(&[0, 0xff, 0x01]),
            vec![0x02, 0x03, 0x00, 0xff, 0x01]
        );
        assert_eq!(der_integer(&[0, 0, 0]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn a_signature_is_a_der_sequence_of_two_integers() {
        let mut raw = [0u8; 64];
        raw[31] = 5;
        raw[63] = 0x90;
        assert_eq!(
            der_signature(&raw),
            vec![0x30, 0x07, 0x02, 0x01, 0x05, 0x02, 0x02, 0x00, 0x90]
        );
    }

    #[test]
    fn cbor_lengths_cross_the_one_byte_boundary() {
        let mut out = Vec::new();
        cbor_bytes(&mut out, &[7; 23]);
        assert_eq!(&out[..1], &[0x40 | 23]);
        let mut out = Vec::new();
        cbor_bytes(&mut out, &[7; 24]);
        assert_eq!(&out[..2], &[0x58, 24]);
        let mut out = Vec::new();
        cbor_bytes(&mut out, &[7; 300]);
        assert_eq!(&out[..3], &[0x59, 0x01, 0x2c]);
    }

    #[test]
    fn an_answer_names_the_credential_in_both_spellings_of_the_id() {
        let mut authenticator = SoftwareAuthenticator::new("kemlock.test", "https://kemlock.test");
        let options = json!({"challenge": "AAAA", "user": {"id": "AQID"}});
        let answer = authenticator.create(&options);
        assert_eq!(answer["id"], answer["rawId"]);
        assert_eq!(
            b64url::decode(answer["id"].as_str().expect("an id")),
            Some(authenticator.credential_id().to_vec())
        );
        let signed = authenticator.get(&json!({"publicKey": {"challenge": "BBBB"}}));
        assert_eq!(
            signed["response"]["userHandle"],
            json!(b64url::encode(&[1, 2, 3]))
        );
    }
}
