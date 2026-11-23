//! The signed envelope every signed federation object travels in.
//!
//! `{0: body (bytes), 1: signature (bytes)}` as deterministic CBOR. The signature is `sig1` over
//! the body's exact bytes under a context label, so a verifier never re-encodes anything: what was
//! signed is what is in the envelope.

use crate::cbor::Value;
use crate::crypto;
use crate::error::{FedError, Result};
use kemlock_crypto::sig1;

/// A body and the signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signed {
    /// Signs `body` under `context`.
    pub fn sign(key: &sig1::SigningKey, context: &str, body: Vec<u8>) -> Result<Signed> {
        let signature = crypto::sign(key, context, &body)?;
        Ok(Signed { body, signature })
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Bytes(self.body.clone())),
            (1, Value::Bytes(self.signature.clone())),
        ])
        .encode()
    }

    /// Parses an envelope, checking the signature's length but not the signature.
    pub fn decode(bytes: &[u8]) -> Result<Signed> {
        let value = Value::decode(bytes)?;
        let fields = value.as_fields()?;
        fields.only(&[0, 1])?;
        let signature = fields.bytes(1)?;
        if signature.len() != sig1::SIGNATURE_LEN {
            return Err(FedError::Malformed("a signature has the wrong length"));
        }
        Ok(Signed {
            body: fields.bytes(0)?.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// Verifies the signature under `key` and `context`.
    pub fn verify(&self, key: &sig1::PublicKey, context: &str) -> Result<()> {
        crypto::verify(key, context, &self.body, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> (sig1::SigningKey, sig1::PublicKey) {
        let key = sig1::SigningKey::from_bytes(&[4; 64]);
        let public = crypto::sign_public(&key).expect("public key");
        (key, public)
    }

    #[test]
    fn signs_encodes_decodes_and_verifies() {
        let (key, public) = key();
        let signed = Signed::sign(&key, "ctx", b"body".to_vec()).expect("sign");
        let again = Signed::decode(&signed.encode()).expect("decode");
        assert_eq!(again, signed);
        again.verify(&public, "ctx").expect("verify");
        assert!(again.verify(&public, "other").is_err());
    }

    #[test]
    fn a_changed_body_or_signature_fails() {
        let (key, public) = key();
        let signed = Signed::sign(&key, "ctx", b"body".to_vec()).expect("sign");
        let mut body = signed.clone();
        body.body[0] ^= 1;
        assert!(body.verify(&public, "ctx").is_err());
        let mut sig = signed;
        sig.signature[100] ^= 1;
        assert!(sig.verify(&public, "ctx").is_err());
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        let (key, _) = key();
        let signed = Signed::sign(&key, "ctx", b"body".to_vec()).expect("sign");
        let mut trailing = signed.encode();
        trailing.push(0);
        assert!(Signed::decode(&trailing).is_err());
        let short = Value::map(vec![(0, Value::bytes(b"x")), (1, Value::bytes(&[0; 10]))]).encode();
        assert!(Signed::decode(&short).is_err());
        let extra = Value::map(vec![
            (0, Value::bytes(b"x")),
            (1, Value::Bytes(signed.signature.clone())),
            (2, Value::Uint(1)),
        ])
        .encode();
        assert!(Signed::decode(&extra).is_err());
        assert!(Signed::decode(&[]).is_err());
    }
}
