//! Entry points for the `cargo-fuzz` targets in `fuzz/`, built only with the `fuzzing` feature.
//!
//! The cipher code is private to the crate, because nothing else should call it; the fuzz targets
//! are a separate crate in their own workspace, so they come in through these functions. Each one
//! takes untrusted bytes, must never panic, and checks the property its comment names.

use crate::cipher::{
    CipherData, StoredCipher, cipher_json, lcase_keys, shows_ssh_keys, update_from_data,
    validate_import,
};
use serde_json::{Value, json};
use time::OffsetDateTime;

const CIPHER_ID: &str = "00000000-0000-0000-0000-000000000000";

/// A cipher request body (`POST /api/ciphers`, one element of an import): parsed, checked as an
/// import, applied to a new cipher and rendered. A request that was applied can always be served
/// back, because the type it was applied under is one `cipher_json` knows.
pub fn cipher_request(bytes: &[u8]) {
    let Ok(request) = serde_json::from_slice::<CipherData>(bytes) else {
        return;
    };
    let _ = validate_import(std::slice::from_ref(&request));
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut cipher = StoredCipher::new(CIPHER_ID.to_owned(), request.r#type, now);
    if update_from_data(&mut cipher, request, now, true, true).is_ok() {
        assert!(
            cipher_json(&cipher, &[]).is_ok(),
            "a cipher that was accepted must be served"
        );
    }
}

/// A stored cipher, as the item's ciphertext holds it, rendered for a sync; and the key
/// lower-casing that every typed object goes through.
pub fn stored_cipher(bytes: &[u8]) {
    if let Ok(cipher) = serde_json::from_slice::<StoredCipher>(bytes) {
        let urls: Vec<String> = cipher.attachments.iter().map(|_| String::new()).collect();
        let _ = cipher_json(&cipher, &urls);
    }
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        let _ = lcase_keys(value);
    }
}

/// Bitwarden `EncString`s (`2.iv|data|mac`) as text in every field a client fills with one: the
/// server must keep them byte for byte, whatever they hold, and never panic on one.
pub fn enc_string(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let body = json!({
        "encryptedFor": CIPHER_ID,
        "type": 1,
        "name": text,
        "notes": text,
        "key": text,
        "fields": [{ "name": text, "value": text, "type": 0 }],
        "passwordHistory": [{ "password": text, "lastUsedDate": text }],
        "login": {
            "username": text,
            "password": text,
            "totp": text,
            "uris": [{ "uri": text, "match": null }],
        },
    });
    let Ok(request) = serde_json::from_value::<CipherData>(body) else {
        return;
    };
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut cipher = StoredCipher::new(CIPHER_ID.to_owned(), 1, now);
    if update_from_data(&mut cipher, request, now, false, true).is_ok() {
        let shown = cipher_json(&cipher, &[]).expect("a login is a known cipher type");
        assert_eq!(
            shown["name"].as_str(),
            Some(text.as_str()),
            "an encrypted name is served as it was sent"
        );
        assert_eq!(
            shown["key"].as_str(),
            Some(text.as_str()),
            "an encrypted key is served as it was sent"
        );
    }
}

/// The `Bitwarden-Client-Version` header that decides whether SSH keys are shown.
pub fn client_version(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = shows_ssh_keys(Some(text));
    }
}
