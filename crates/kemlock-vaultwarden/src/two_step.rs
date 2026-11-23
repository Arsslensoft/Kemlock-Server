//! Vaultwarden's two-step setups (the `twofactor` table) as what Kemlock Server keeps.
//!
//! A move keeps every setup, so nobody re-enrols. An authenticator app (type 0) is a base32
//! secret, handled where it is stored. The rest are JSON in `data`:
//!
//! - email (1): `{"email", "last_token", "token_sent", "attempts"}`, kept as it is, so the
//!   address the codes go to stays;
//! - Duo (2): `{"host", "ik", "sk"}` for an account that saved its own integration, or an empty
//!   `data` for one that uses the server's, which come from `config.json` or the environment;
//! - YubiKey (3): `{"keys": [<12-character ids>], "nfc"}`;
//! - WebAuthn (7): a list of registrations `{"id", "name", "migrated", "credential"}`, where
//!   `credential` is webauthn-rs's `Passkey` (`{"cred": <Credential>}`);
//! - U2F (4): the registrations Vaultwarden made before WebAuthn, `{"id", "name", "reg": {"keyHandle",
//!   "pubKey", ...}, "counter", "compromised", "migrated"}`. Vaultwarden turns them into WebAuthn
//!   registrations itself when it starts, and does the same here: a P-256 key whose credential id is
//!   the key handle.
//!
//! WebAuthn and U2F registrations both become Kemlock's security keys, credentials in the form
//! `kemlock-identity`'s relying party keeps them: the JSON of webauthn-rs-core's `Credential`.
//! This module reads and writes that JSON by hand, so the crate needs no WebAuthn library; the
//! tests of `kemlock-api-bw` sign in with a software authenticator to show it is read.

use kemlock_domain::Passkey;
use serde_json::{Map, Value, json};

/// An account may have this many security keys, in slots 1 to 5.
const MAX_KEYS: usize = 5;

/// A security key carried over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedKey {
    /// The slot, 1 to 5: Vaultwarden's id when that is one of them and free, else the lowest free.
    pub slot: u8,
    pub name: String,
    pub credential_id: Vec<u8>,
    /// The JSON of the credential.
    pub credential: Vec<u8>,
}

/// The security keys of an account: its WebAuthn registrations (`webauthn`, the `data` of the
/// type 7 row) and then its U2F ones (`u2f`, type 4), without a key twice (Vaultwarden keeps a
/// U2F registration it migrated beside the WebAuthn one it made of it) and at most five.
pub fn security_keys(webauthn: Option<&str>, u2f: Option<&str>) -> Vec<MappedKey> {
    let mut found: Vec<Candidate> = Vec::new();
    let from_webauthn = entries(webauthn)
        .into_iter()
        .filter_map(|e| webauthn_key(&e));
    let from_u2f = entries(u2f).into_iter().filter_map(|e| u2f_key(&e));
    for candidate in from_webauthn.chain(from_u2f) {
        if found
            .iter()
            .any(|c| c.credential_id == candidate.credential_id)
        {
            continue;
        }
        if found.len() == MAX_KEYS {
            break;
        }
        found.push(candidate);
    }

    // A slot goes to the key that asks for it, when it is one of 1 to 5 and nobody had it first;
    // the others take the lowest free ones.
    let mut slots: Vec<Option<u8>> = vec![None; found.len()];
    let mut taken = [false; MAX_KEYS + 1];
    for (index, candidate) in found.iter().enumerate() {
        if let Some(wanted) = candidate
            .wanted
            .and_then(|w| u8::try_from(w).ok())
            .filter(|w| (1..=5).contains(w) && !taken[usize::from(*w)])
        {
            taken[usize::from(wanted)] = true;
            slots[index] = Some(wanted);
        }
    }
    let mut keys = Vec::with_capacity(found.len());
    for (candidate, slot) in found.into_iter().zip(slots) {
        let slot = slot.unwrap_or_else(|| {
            let free = (1..=5u8).find(|s| !taken[usize::from(*s)]).unwrap_or(5);
            taken[usize::from(free)] = true;
            free
        });
        keys.push(MappedKey {
            slot,
            name: Passkey::clean_name(&candidate.name).unwrap_or_else(|| "Security key".to_owned()),
            credential_id: candidate.credential_id,
            credential: candidate.credential.to_string().into_bytes(),
        });
    }
    keys
}

/// An email setup's `data`, when it is one: an object whose `email` is text. Kept as written.
pub fn email_data(data: &str) -> Option<String> {
    let value: Value = serde_json::from_str(data).ok()?;
    value.get("email")?.as_str()?;
    Some(value.to_string())
}

/// A YubiKey setup's `data` as `{"keys": [...], "nfc": bool}`, when it is one. Either spelling of
/// the names is read.
pub fn yubikey_data(data: &str) -> Option<String> {
    let value: Value = serde_json::from_str(data).ok()?;
    let keys = value
        .get("keys")
        .or_else(|| value.get("Keys"))?
        .as_array()?;
    let keys: Vec<&str> = keys.iter().filter_map(Value::as_str).collect();
    if keys.is_empty() {
        return None;
    }
    let nfc = value
        .get("nfc")
        .or_else(|| value.get("Nfc"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(json!({"keys": keys, "nfc": nfc}).to_string())
}

/// A Duo setup's `data`: the account's own integration as `{"host", "ik", "sk"}`, or `{}` for an
/// account that uses the server's (Vaultwarden keeps an empty string for those).
pub fn duo_data(data: &str) -> String {
    let own = serde_json::from_str::<Value>(data).ok().and_then(|value| {
        let part = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
        };
        Some(json!({"host": part("host")?, "ik": part("ik")?, "sk": part("sk")?}))
    });
    own.unwrap_or_else(|| json!({})).to_string()
}

// ---------------------------------------------------------------------------------------------
// Security keys.

struct Candidate {
    wanted: Option<i64>,
    name: String,
    credential_id: Vec<u8>,
    credential: Value,
}

fn entries(text: Option<&str>) -> Vec<Value> {
    match text.and_then(|t| serde_json::from_str::<Value>(t).ok()) {
        Some(Value::Array(list)) => list,
        _ => Vec::new(),
    }
}

fn name_of(entry: &Value) -> String {
    entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// A WebAuthn registration of Vaultwarden's.
fn webauthn_key(entry: &Value) -> Option<Candidate> {
    let (credential_id, credential) = credential_of(entry.get("credential")?)?;
    Some(Candidate {
        wanted: entry.get("id").and_then(Value::as_i64),
        name: name_of(entry),
        credential_id,
        credential,
    })
}

/// A U2F registration of Vaultwarden's, made a WebAuthn credential as Vaultwarden does: ES256
/// on P-256, the key handle as the credential id, no user verification, the counter kept.
fn u2f_key(entry: &Value) -> Option<Candidate> {
    let reg = entry.get("reg")?;
    let handle = bytes_of(reg.get("keyHandle").or_else(|| reg.get("key_handle"))?)?;
    let public = bytes_of(reg.get("pubKey").or_else(|| reg.get("pub_key"))?)?;
    // An uncompressed P-256 point: 0x04, x, y.
    if handle.is_empty() || public.len() != 65 {
        return None;
    }
    let counter = entry.get("counter").and_then(Value::as_u64).unwrap_or(0);
    let credential = json!({
        "cred_id": encode(&handle),
        "cred": {
            "type_": "ES256",
            "key": {"EC_EC2": {
                "curve": "SECP256R1",
                "x": encode(&public[1..33]),
                "y": encode(&public[33..65]),
            }},
        },
        "counter": counter,
        "transports": null,
        "user_verified": false,
        "backup_eligible": false,
        "backup_state": false,
        "registration_policy": "discouraged",
        "extensions": {},
        "attestation": {"data": "None", "metadata": "None"},
        "attestation_format": "none",
    });
    Some(Candidate {
        wanted: entry.get("id").and_then(Value::as_i64),
        name: name_of(entry),
        credential_id: handle,
        credential,
    })
}

/// The credential a stored `Passkey` holds, its id in the canonical spelling and every member the
/// relying party reads present. A `Passkey` wraps the credential in `cred`; the credential of an
/// older Vaultwarden (webauthn-rs 0.3, with `verified`) lies bare.
fn credential_of(stored: &Value) -> Option<(Vec<u8>, Value)> {
    let inner = match stored.get("cred") {
        Some(wrapped) if wrapped.get("cred_id").is_some() => wrapped,
        _ => stored,
    };
    let mut object: Map<String, Value> = inner.as_object()?.clone();
    let id = bytes_of(object.get("cred_id")?)?;
    if id.is_empty() || !object.get("cred")?.is_object() {
        return None;
    }
    object.insert("cred_id".to_owned(), Value::String(encode(&id)));
    if !object.contains_key("user_verified") {
        let verified = object
            .remove("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        object.insert("user_verified".to_owned(), Value::Bool(verified));
    }
    for (name, default) in [
        ("counter", json!(0)),
        ("transports", Value::Null),
        ("backup_eligible", json!(false)),
        ("backup_state", json!(false)),
        ("registration_policy", json!("discouraged")),
        ("extensions", json!({})),
        ("attestation", json!({"data": "None", "metadata": "None"})),
        ("attestation_format", json!("none")),
    ] {
        object.entry(name.to_owned()).or_insert(default);
    }
    Some((id, Value::Object(object)))
}

/// Bytes written as base64 text (either alphabet, padded or not) or as an array of numbers.
fn bytes_of(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(text) => decode(text),
        Value::Array(items) => items
            .iter()
            .map(|i| i.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        _ => None,
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// Base64 in either alphabet, with or without padding.
fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.trim().bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(id: &[u8], counter: u32) -> Value {
        json!({"cred": {
            "cred_id": encode(id),
            "cred": {"type_": "ES256", "key": {"EC_EC2": {"curve": "SECP256R1", "x": "eA", "y": "eQ"}}},
            "counter": counter,
            "transports": null,
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": false,
            "registration_policy": "discouraged",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }})
    }

    fn registration(id: i64, name: &str, credential: Value) -> Value {
        json!({"id": id, "name": name, "migrated": false, "credential": credential})
    }

    #[test]
    fn base64_is_read_in_both_alphabets_and_written_as_url_safe() {
        assert_eq!(decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(decode("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("not base64!"), None);
        for data in [&b""[..], b"a", b"ab", b"abc", b"abcd"] {
            assert_eq!(decode(&encode(data)), Some(data.to_vec()));
        }
    }

    #[test]
    fn a_webauthn_registration_keeps_its_credential_and_its_slot() {
        let data = Value::Array(vec![
            registration(2, "Blue key", passkey(b"id-one", 7)),
            registration(1, "", passkey(b"id-two", 0)),
        ])
        .to_string();
        let keys = security_keys(Some(&data), None);
        assert_eq!(keys.len(), 2);
        assert_eq!((keys[0].slot, keys[0].name.as_str()), (2, "Blue key"));
        assert_eq!((keys[1].slot, keys[1].name.as_str()), (1, "Security key"));
        assert_eq!(keys[0].credential_id, b"id-one");
        let credential: Value = serde_json::from_slice(&keys[0].credential).expect("JSON");
        assert_eq!(credential["counter"], 7);
        assert_eq!(credential["cred_id"], encode(b"id-one"));
        assert_eq!(credential["cred"]["key"]["EC_EC2"]["curve"], "SECP256R1");
        assert_eq!(credential["backup_eligible"], true);
    }

    #[test]
    fn a_slot_that_is_taken_or_out_of_range_gets_the_lowest_free_one() {
        let data = Value::Array(vec![
            registration(3, "A", passkey(b"a", 0)),
            registration(3, "B", passkey(b"b", 0)),
            registration(9, "C", passkey(b"c", 0)),
            registration(1, "D", passkey(b"d", 0)),
        ])
        .to_string();
        let slots: Vec<u8> = security_keys(Some(&data), None)
            .iter()
            .map(|k| k.slot)
            .collect();
        assert_eq!(slots, vec![3, 2, 4, 1]);
    }

    #[test]
    fn a_credential_of_an_older_vaultwarden_is_brought_up_to_date() {
        let old = json!({
            "cred_id": [1, 2, 3],
            "cred": {"type_": "ES256", "key": {"EC_EC2": {"curve": "SECP256R1", "x": "eA", "y": "eQ"}}},
            "counter": 4,
            "verified": true,
            "registration_policy": "required"
        });
        let data = Value::Array(vec![registration(1, "Old", old)]).to_string();
        let keys = security_keys(Some(&data), None);
        assert_eq!(keys.len(), 1);
        let credential: Value = serde_json::from_slice(&keys[0].credential).expect("JSON");
        assert_eq!(credential["cred_id"], encode(&[1, 2, 3]));
        assert_eq!(credential["user_verified"], true);
        assert!(credential.get("verified").is_none());
        assert_eq!(credential["registration_policy"], "required");
        assert_eq!(credential["backup_state"], false);
        assert_eq!(credential["attestation_format"], "none");
    }

    #[test]
    fn a_u2f_registration_becomes_a_p256_credential_with_the_key_handle_as_its_id() {
        let mut public = vec![4u8];
        public.extend([0x11; 32]);
        public.extend([0x22; 32]);
        let data = json!([{
            "id": 5, "name": "Old key",
            "reg": {"keyHandle": [9, 8, 7], "pubKey": public, "attestationCert": null, "deviceName": null},
            "counter": 12, "compromised": false, "migrated": null
        }])
        .to_string();
        let keys = security_keys(None, Some(&data));
        assert_eq!(keys.len(), 1);
        assert_eq!(
            (keys[0].slot, keys[0].credential_id.as_slice()),
            (5, &[9u8, 8, 7][..])
        );
        let credential: Value = serde_json::from_slice(&keys[0].credential).expect("JSON");
        assert_eq!(credential["counter"], 12);
        assert_eq!(credential["user_verified"], false);
        assert_eq!(
            credential["cred"]["key"]["EC_EC2"]["x"],
            encode(&[0x11; 32])
        );
        assert_eq!(
            credential["cred"]["key"]["EC_EC2"]["y"],
            encode(&[0x22; 32])
        );
    }

    #[test]
    fn a_u2f_registration_vaultwarden_already_migrated_is_not_a_second_key() {
        let mut public = vec![4u8];
        public.extend([0x11; 32]);
        public.extend([0x22; 32]);
        let u2f = json!([{
            "id": 1, "name": "Key",
            "reg": {"keyHandle": [9, 8, 7], "pubKey": public},
            "counter": 12, "compromised": false, "migrated": true
        }])
        .to_string();
        let webauthn = Value::Array(vec![registration(
            1,
            "Key",
            json!({"cred": {
                "cred_id": encode(&[9, 8, 7]),
                "cred": {"type_": "ES256", "key": {"EC_EC2": {"curve": "SECP256R1", "x": "eA", "y": "eQ"}}},
                "counter": 12
            }}),
        )])
        .to_string();
        assert_eq!(security_keys(Some(&webauthn), Some(&u2f)).len(), 1);
    }

    #[test]
    fn at_most_five_keys_and_nothing_from_damaged_data() {
        let many: Vec<Value> = (1..=7u8)
            .map(|n| registration(i64::from(n), "K", passkey(&[n], 0)))
            .collect();
        let data = Value::Array(many).to_string();
        assert_eq!(security_keys(Some(&data), None).len(), 5);
        assert!(security_keys(Some("not json"), Some("{}")).is_empty());
        assert!(security_keys(Some("[{\"id\": 1}]"), Some("[{\"reg\": {}}]")).is_empty());
        assert!(security_keys(None, None).is_empty());
    }

    #[test]
    fn email_yubikey_and_duo_data_are_kept_or_normalised() {
        let email = r#"{"email":"a@b.example","last_token":null,"token_sent":5,"attempts":0}"#;
        assert_eq!(
            serde_json::from_str::<Value>(&email_data(email).expect("kept")).expect("JSON"),
            serde_json::from_str::<Value>(email).expect("JSON")
        );
        assert_eq!(email_data("{}"), None);
        assert_eq!(email_data("nope"), None);

        assert_eq!(
            yubikey_data(r#"{"Keys":["cccccccccccc"],"Nfc":true}"#).as_deref(),
            Some(r#"{"keys":["cccccccccccc"],"nfc":true}"#)
        );
        assert_eq!(yubikey_data(r#"{"keys":[],"nfc":true}"#), None);

        let own = r#"{"host":"api-1.duosecurity.com","ik":"DI1","sk":"s"}"#;
        assert_eq!(
            serde_json::from_str::<Value>(&duo_data(own)).expect("JSON"),
            serde_json::from_str::<Value>(own).expect("JSON")
        );
        assert_eq!(duo_data(""), "{}");
        assert_eq!(duo_data(r#"{"host":"x","ik":"","sk":"s"}"#), "{}");
    }
}
