//! Contract test: the answers of Vaultwarden 1.37.5 recorded in the Kemlock app's fixtures
//! (`account-pbkdf2.json`, `account-argon2id.json`, copied byte for byte) are replayed against
//! the router, and the answers must have the same keys, types and casing, and the same values
//! for everything the client wrote.

mod common;

use common::{HASH, Harness};
use serde_json::{Value, json};

fn keys_of(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .unwrap_or_else(|| panic!("an object, not {v}"))
        .keys()
        .cloned()
        .collect();
    keys.sort_unstable();
    keys
}

/// The JSON type of a value, so "null where Vaultwarden has null" is checked too.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

async fn replay(fixture: &str) {
    let recorded: Value = serde_json::from_str(fixture).expect("a fixture");
    let email = recorded["email"].as_str().expect("an email");
    let token = &recorded["token"];
    let kdf = token["Kdf"].as_i64().expect("a kdf") as i32;
    let h = Harness::new().await;
    h.account_with(
        email,
        HASH,
        token["Key"].as_str().expect("a key"),
        kdf,
        token["KdfIterations"].as_i64().expect("iterations") as i32,
        token["KdfMemory"].as_i64().map(|m| m as i32),
        token["KdfParallelism"].as_i64().map(|m| m as i32),
    )
    .await;

    // Prelogin: the whole body.
    let (_, prelogin) = h
        .json(
            "POST",
            "/identity/accounts/prelogin",
            None,
            Some(json!({"email": email})),
        )
        .await;
    assert_eq!(prelogin, recorded["prelogin"]);

    // Token: every key the recording has, with the same type, and the same nested keys.
    let answer = h.login(email, HASH).await;
    for key in keys_of(token) {
        assert_eq!(
            kind(&answer[&key]),
            kind(&token[&key]),
            "token key {key}: {}",
            answer[&key]
        );
    }
    assert_eq!(answer["Kdf"], token["Kdf"]);
    assert_eq!(answer["KdfIterations"], token["KdfIterations"]);
    assert_eq!(answer["KdfMemory"], token["KdfMemory"]);
    assert_eq!(answer["KdfParallelism"], token["KdfParallelism"]);
    assert_eq!(answer["Key"], token["Key"]);
    assert_eq!(
        keys_of(&answer["UserDecryptionOptions"]),
        keys_of(&token["UserDecryptionOptions"])
    );
    assert_eq!(
        keys_of(&answer["UserDecryptionOptions"]["MasterPasswordUnlock"]),
        keys_of(&token["UserDecryptionOptions"]["MasterPasswordUnlock"])
    );
    assert_eq!(
        answer["UserDecryptionOptions"]["MasterPasswordUnlock"]["Kdf"],
        token["UserDecryptionOptions"]["MasterPasswordUnlock"]["Kdf"]
    );
    assert_eq!(
        answer["UserDecryptionOptions"]["MasterPasswordUnlock"]["Salt"],
        token["UserDecryptionOptions"]["MasterPasswordUnlock"]["Salt"]
    );
    assert_eq!(
        keys_of(&answer["AccountKeys"]),
        keys_of(&token["AccountKeys"])
    );
    assert_eq!(
        keys_of(&answer["AccountKeys"]["publicKeyEncryptionKeyPair"]),
        keys_of(&token["AccountKeys"]["publicKeyEncryptionKeyPair"])
    );
    let access = answer["access_token"].as_str().expect("a token").to_owned();

    // The recorded folder and ciphers, written the way the Kemlock app writes them.
    let sync_recorded = &recorded["sync"];
    let (_, me) = h
        .json("GET", "/api/accounts/profile", Some(&access), None)
        .await;
    let user_id = me["id"].as_str().expect("an id").to_owned();
    let folder_recorded = &sync_recorded["folders"][0];
    let (_, folder) = h
        .json(
            "POST",
            "/api/folders",
            Some(&access),
            Some(json!({"name": folder_recorded["name"]})),
        )
        .await;
    assert_eq!(keys_of(&folder), keys_of(folder_recorded));
    for key in keys_of(folder_recorded) {
        assert_eq!(
            kind(&folder[&key]),
            kind(&folder_recorded[&key]),
            "folder key {key}"
        );
    }
    assert_eq!(folder["name"], folder_recorded["name"]);

    for recorded_cipher in sync_recorded["ciphers"].as_array().expect("ciphers") {
        let typed = match recorded_cipher["type"].as_i64() {
            Some(1) => "login",
            _ => "secureNote",
        };
        let mut request = json!({
            "encryptedFor": user_id,
            "type": recorded_cipher["type"],
            "folderId": folder["id"],
            "name": recorded_cipher["name"],
            "notes": recorded_cipher["notes"],
            "key": recorded_cipher["key"],
            "favorite": recorded_cipher["favorite"],
            "reprompt": recorded_cipher["reprompt"],
            "fields": recorded_cipher["fields"],
            "passwordHistory": recorded_cipher["passwordHistory"],
            "lastKnownRevisionDate": null,
        });
        request[typed] = recorded_cipher[typed].clone();
        let (status, written) = h
            .json("POST", "/api/ciphers", Some(&access), Some(request))
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{written}");
        assert_eq!(keys_of(&written), keys_of(recorded_cipher), "cipher keys");
        for key in keys_of(recorded_cipher) {
            // Dates and ids differ, and so does the folder; everything else has the same type.
            assert_eq!(
                kind(&written[&key]),
                kind(&recorded_cipher[&key]),
                "cipher key {key}"
            );
        }
        // What the client wrote comes back as written.
        for key in [
            "name",
            "notes",
            "key",
            "favorite",
            "reprompt",
            "fields",
            "passwordHistory",
            "type",
        ] {
            assert_eq!(written[key], recorded_cipher[key], "{key}");
        }
        assert_eq!(written[typed], recorded_cipher[typed], "the {typed} object");
        assert_eq!(written["folderId"], folder["id"]);
        assert_eq!(written["permissions"], recorded_cipher["permissions"]);
    }

    // The profile, and the whole sync, have the recorded keys.
    let recorded_profile = &sync_recorded["profile"];
    assert_eq!(keys_of(&me), keys_of(recorded_profile));
    for key in keys_of(recorded_profile) {
        assert_eq!(
            kind(&me[&key]),
            kind(&recorded_profile[&key]),
            "profile key {key}"
        );
    }
    assert_eq!(me["key"], recorded_profile["key"]);
    assert_eq!(
        keys_of(&me["accountKeys"]),
        keys_of(&recorded_profile["accountKeys"])
    );
    let (_, sync) = h
        .json("GET", "/api/sync?excludeDomains=true", Some(&access), None)
        .await;
    assert_eq!(
        sync["ciphers"].as_array().map(Vec::len),
        sync_recorded["ciphers"].as_array().map(Vec::len)
    );
    for key in ["profile", "folders", "ciphers"] {
        assert_eq!(kind(&sync[key]), kind(&sync_recorded[key]), "{key}");
    }
}

#[tokio::test]
async fn a_pbkdf2_account_replays_like_vaultwarden() {
    replay(include_str!("fixtures/account-pbkdf2.json")).await;
}

#[tokio::test]
async fn an_argon2id_account_replays_like_vaultwarden() {
    replay(include_str!("fixtures/account-argon2id.json")).await;
}
