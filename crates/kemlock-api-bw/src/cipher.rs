// Ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/db/models/cipher.rs (Cipher::to_json), src/api/core/ciphers.rs (update_cipher_from_data),
//   src/util.rs (lcase_first, process_json_key, get_display_size).
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! Ciphers as Vaultwarden keeps and shows them.
//!
//! A cipher is stored as one JSON document, a [`StoredCipher`], in the ciphertext of a `bw` item.
//! It holds what Vaultwarden keeps in its `ciphers`, `folders_ciphers`, `favorites` and `archives`
//! rows: the encrypted fields as the client sent them (the typed object, `fields` and
//! `passwordHistory` untouched, unknown keys included), plus the dates, the folder, the favourite
//! flag and the attachments. [`cipher_json`] then makes `cipherDetails` exactly as Vaultwarden's
//! `Cipher::to_json` does, repairs and all, so what a client reads back is what it would read from
//! Vaultwarden.

use crate::dates::{format_date, parse_date, validate_and_format_date};
use crate::error::{BwError, BwResult};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use time::OffsetDateTime;

/// The item kind of a folder; ciphers use `login`, `secure-note` and so on.
pub(crate) const FOLDER_KIND: &str = "bw-folder";

/// Vaultwarden's `MAX_NOTE_SIZE` default: encrypted notes up to 10,000 characters.
pub(crate) const MAX_NOTE_SIZE: usize = 10_000;

/// Kinds of the items that hold ciphers, from Bitwarden's cipher type.
pub(crate) fn kind_for_type(cipher_type: i32) -> &'static str {
    match cipher_type {
        1 => "login",
        2 => "secure-note",
        3 => "card",
        4 => "identity",
        5 => "ssh-key",
        6 => "bank-account",
        7 => "drivers-license",
        8 => "passport",
        _ => "cipher",
    }
}

/// The key of the typed object for a cipher type.
pub(crate) fn type_key(cipher_type: i32) -> Option<&'static str> {
    match cipher_type {
        1 => Some("login"),
        2 => Some("secureNote"),
        3 => Some("card"),
        4 => Some("identity"),
        5 => Some("sshKey"),
        6 => Some("bankAccount"),
        7 => Some("driversLicense"),
        8 => Some("passport"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredAttachment {
    pub id: String,
    /// The file name, encrypted by the client.
    pub file_name: String,
    /// Bytes of the encrypted file.
    pub size: i64,
    pub key: Option<String>,
}

/// One cipher as stored in an item's ciphertext.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredCipher {
    pub id: String,
    pub r#type: i32,
    pub creation_date: String,
    /// Moves when the cipher is created, updated, trashed or restored, and not when it is only
    /// moved to a folder, starred, archived or given an attachment, as in Vaultwarden.
    pub revision_date: String,
    pub deleted_date: Option<String>,
    pub reprompt: i32,
    pub key: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<Value>,
    pub password_history: Option<Value>,
    /// The typed object (`login`, `secureNote`, …) as the client sent it.
    pub data: Value,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub archived_date: Option<String>,
    #[serde(default)]
    pub attachments: Vec<StoredAttachment>,
}

impl StoredCipher {
    pub(crate) fn new(id: String, cipher_type: i32, now: OffsetDateTime) -> Self {
        let now = format_date(now);
        StoredCipher {
            id,
            r#type: cipher_type,
            creation_date: now.clone(),
            revision_date: now,
            deleted_date: None,
            reprompt: 0,
            key: None,
            name: String::new(),
            notes: None,
            fields: None,
            password_history: None,
            data: Value::Null,
            folder_id: None,
            favorite: false,
            archived_date: None,
            attachments: Vec::new(),
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        kind_for_type(self.r#type)
    }
}

fn nonempty_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|s| !s.is_empty()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Attachments2Data {
    pub file_name: String,
    pub key: String,
}

/// A cipher request, as Vaultwarden's `CipherData`. Unknown keys are ignored, as there.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct CipherData {
    pub id: Option<String>,
    #[serde(default, deserialize_with = "nonempty_str")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    pub organization_id: Option<String>,
    pub key: Option<String>,
    /// Required: a body without it doesn't parse, and one that isn't the user's id is a 422.
    pub encrypted_for: String,
    pub encrypted_by_key_id: Option<String>,
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<Value>,
    pub login: Option<Value>,
    pub secure_note: Option<Value>,
    pub card: Option<Value>,
    pub identity: Option<Value>,
    pub ssh_key: Option<Value>,
    pub bank_account: Option<Value>,
    pub drivers_license: Option<Value>,
    pub passport: Option<Value>,
    pub favorite: Option<bool>,
    pub reprompt: Option<i32>,
    pub password_history: Option<Value>,
    pub attachments: Option<Value>,
    pub attachments2: Option<HashMap<String, Attachments2Data>>,
    pub last_known_revision_date: Option<String>,
    pub archived_date: Option<String>,
}

/// The message of a refused stale write.
pub(crate) const OUT_OF_DATE: &str =
    "The client copy of this cipher is out of date. Resync the client and try again.";

fn note_too_long() -> BwError {
    BwError::msg(format!(
        "The field Notes exceeds the maximum encrypted value length of {MAX_NOTE_SIZE} characters."
    ))
}

/// Removes the `response` key the web client's JavaScript adds, from every object of an array.
fn clean_array(mut value: Value) -> Value {
    if let Some(items) = value.as_array_mut() {
        for item in items.iter_mut().filter_map(Value::as_object_mut) {
            item.remove("response");
        }
    }
    value
}

/// `update_cipher_from_data`: copies a request into `cipher` and moves its revision date to `now`.
///
/// `check_stale` is off for an import. `folder_valid` says the request's `folderId`, if any, is one
/// of the user's folders; the caller looks it up. Organization checks are the caller's too.
pub(crate) fn update_from_data(
    cipher: &mut StoredCipher,
    data: CipherData,
    now: OffsetDateTime,
    check_stale: bool,
    folder_valid: bool,
) -> BwResult<()> {
    if check_stale && let Some(sent) = &data.last_known_revision_date {
        match parse_date(sent) {
            None => tracing::warn!("couldn't parse a lastKnownRevisionDate"),
            Some(sent) => {
                if let Some(stored) = parse_date(&cipher.revision_date)
                    && (stored - sent).whole_seconds() > 1
                {
                    return Err(BwError::msg(OUT_OF_DATE));
                }
            }
        }
    }

    if data.notes.as_ref().is_some_and(|n| n.len() > MAX_NOTE_SIZE) {
        return Err(note_too_long());
    }

    if !folder_valid {
        return Err(BwError::msg("Invalid folder"));
    }

    // Key rotation renames and re-keys attachments; a missing one was removed from another client.
    if let Some(updates) = &data.attachments2 {
        for (id, update) in updates {
            if let Some(saved) = cipher.attachments.iter_mut().find(|a| &a.id == id) {
                saved.key = Some(update.key.clone());
                saved.file_name = update.file_name.clone();
            }
        }
    }

    let type_data = match data.r#type {
        1 => data.login,
        2 => data.secure_note,
        3 => data.card,
        4 => data.identity,
        5 => data.ssh_key,
        6 => data.bank_account,
        7 => data.drivers_license,
        8 => data.passport,
        _ => return Err(BwError::msg("Invalid type")),
    };
    let mut type_data = type_data.ok_or_else(|| BwError::msg("Data missing"))?;
    if let Some(object) = type_data.as_object_mut() {
        object.remove("response");
        if let Some(uris) = object.get_mut("uris")
            && uris.is_array()
        {
            *uris = clean_array(uris.take());
        }
    }

    cipher.key = data.key;
    cipher.name = data.name;
    cipher.notes = data.notes;
    cipher.fields = data.fields.map(clean_array);
    cipher.data = type_data;
    cipher.password_history = data.password_history;
    cipher.reprompt = data.reprompt.filter(|r| *r == 0 || *r == 1).unwrap_or(0);
    cipher.folder_id = data.folder_id;
    if let Some(favorite) = data.favorite {
        cipher.favorite = favorite;
    }
    match data.archived_date {
        Some(sent) => match parse_date(&sent) {
            Some(at) => cipher.archived_date = Some(format_date(at)),
            None => tracing::warn!("couldn't parse an archivedDate"),
        },
        None => cipher.archived_date = None,
    }
    cipher.revision_date = format_date(now);
    Ok(())
}

/// Vaultwarden's import check: nothing is imported unless every cipher passes. A failure is a 400
/// whose body names each bad cipher's field.
pub(crate) fn validate_import(ciphers: &[CipherData]) -> BwResult<()> {
    let mut errors = Map::new();
    let note_msg = format!(
        "The field Notes exceeds the maximum encrypted value length of {MAX_NOTE_SIZE} characters."
    );
    for (index, cipher) in ciphers.iter().enumerate() {
        if cipher
            .notes
            .as_ref()
            .is_some_and(|n| n.len() > MAX_NOTE_SIZE)
        {
            errors.insert(format!("Ciphers[{index}].Notes"), json!([&note_msg]));
        }
        if let Some(Value::Array(history)) = &cipher.password_history {
            for entry in history {
                if let Value::Object(entry) = entry
                    && entry.get("password").is_some_and(|p| !p.is_string())
                {
                    errors.insert(
                        format!("Ciphers[{index}].Notes"),
                        json!(["The password history contains a `null` value. Only strings are allowed."]),
                    );
                    break;
                }
            }
        }
    }
    if errors.is_empty() {
        return Ok(());
    }
    Err(BwError::Json(json!({
        "message": "The model state is invalid.",
        "validationErrors": errors,
        "object": "error",
    })))
}

fn lcase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
    }
}

/// `ssn` is the one key that is lower-cased whole.
fn process_json_key(key: &str) -> String {
    if key.to_lowercase() == "ssn" {
        "ssn".to_owned()
    } else {
        lcase_first(key)
    }
}

/// Lower-cases the first letter of every key, deeply (Vaultwarden's `LowerCase` and
/// `convert_json_key_lcase_first`). Two keys that differ only in that letter become one.
pub(crate) fn lcase_keys(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(lcase_keys).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (process_json_key(&k), lcase_keys(v)))
                .collect(),
        ),
        other => other,
    }
}

/// `fields`: a list of objects, or nothing; a `type` that isn't a number becomes the number it
/// spells or the hidden type 1, which can't disclose anything.
fn fields_json(fields: Option<&Value>) -> Vec<Value> {
    let Some(Value::Array(items)) = fields else {
        return Vec::new();
    };
    if !items.iter().all(|i| i.is_object() || i.is_array()) {
        return Vec::new();
    }
    items
        .iter()
        .cloned()
        .map(|item| {
            let mut item = lcase_keys(item);
            if let Value::Object(field) = &mut item {
                let fixed = match field.get("type") {
                    Some(t) if t.is_number() => None,
                    Some(t) => Some(t.as_str().unwrap_or("1").parse::<u8>().unwrap_or(1)),
                    None => Some(1),
                };
                if let Some(number) = fixed {
                    field.insert("type".to_owned(), json!(number));
                }
            }
            item
        })
        .collect()
}

/// `passwordHistory`: entries with a string `password` only, each with a valid `lastUsedDate`.
fn password_history_json(history: Option<&Value>) -> Vec<Value> {
    let Some(Value::Array(items)) = history else {
        return Vec::new();
    };
    if !items.iter().all(|i| i.is_object() || i.is_array()) {
        return Vec::new();
    }
    items
        .iter()
        .cloned()
        .map(lcase_keys)
        .filter_map(|entry| match entry {
            Value::Object(mut map) if map.get("password").is_some_and(Value::is_string) => {
                let used = match map.get("lastUsedDate").and_then(Value::as_str) {
                    Some(text) => validate_and_format_date(text),
                    None => "1970-01-01T00:00:00.000000Z".to_owned(),
                };
                map.insert("lastUsedDate".to_owned(), json!(used));
                Some(Value::Object(map))
            }
            _ => None,
        })
        .collect()
}

/// The typed object as a client reads it, with Vaultwarden's repairs.
fn type_data_json(cipher_type: i32, raw: &Value) -> Value {
    let mut data = if raw.is_object() || raw.is_array() {
        lcase_keys(raw.clone())
    } else {
        Value::Object(Map::new())
    };

    if cipher_type == 1
        && let Value::Object(login) = &mut data
    {
        // Upstream always has `uri`: the first URI's, for clients that read only that one. The
        // `uris` slot is created as null when the login had none, as `type_data["uris"]` does.
        login.insert("uri".to_owned(), Value::Null);
        let mut first = None;
        let slot = login.entry("uris").or_insert(Value::Null);
        if let Some(uris) = slot.as_array_mut()
            && !uris.is_empty()
        {
            // A `match` is a number or null, never text.
            for uri in uris.iter_mut() {
                if let Value::Object(uri) = uri
                    && let Some(text) = uri.get("match").and_then(Value::as_str)
                {
                    let parsed = text.parse::<u8>().map_or(Value::Null, |n| json!(n));
                    uri.insert("match".to_owned(), parsed);
                }
            }
            first = Some(uris[0]["uri"].clone());
        }
        if let Some(first) = first {
            login.insert("uri".to_owned(), first);
        }
        if let Some(text) = login.get("passwordRevisionDate").and_then(Value::as_str) {
            let fixed = validate_and_format_date(text);
            login.insert("passwordRevisionDate".to_owned(), json!(fixed));
        }
    }

    // A secure note's `type` is a number, or the note breaks mobile clients.
    if cipher_type == 2 {
        let ok =
            matches!(&data, Value::Object(note) if note.get("type").is_some_and(Value::is_number));
        if !ok {
            data = json!({"type": 0});
        }
    }

    // An SSH key needs all three parts; a client crashes on one with a part missing.
    if cipher_type == 5 {
        let has = |key: &str| data[key].as_str().is_some_and(|s| !s.is_empty());
        if !(has("keyFingerprint") && has("privateKey") && has("publicKey")) {
            tracing::warn!("an ssh key is missing a mandatory part");
            data = Value::Null;
        }
    }
    data
}

/// Vaultwarden's `get_display_size`: `17.00 bytes`, `1.50 KB`.
pub(crate) fn display_size(size: i64) -> String {
    const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];
    let mut size = size as f64;
    let mut unit = 0;
    while size > 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.2} {}", UNITS[unit])
}

/// One attachment as clients read it; `url` is the link a download needs.
pub(crate) fn attachment_json(attachment: &StoredAttachment, url: &str) -> Value {
    json!({
        "id": attachment.id,
        "url": url,
        "fileName": attachment.file_name,
        "size": attachment.size.to_string(),
        "sizeName": display_size(attachment.size),
        "key": attachment.key,
        "object": "attachment",
    })
}

/// `cipherDetails`. `urls` are the download links of the cipher's attachments, in order.
pub(crate) fn cipher_json(cipher: &StoredCipher, urls: &[String]) -> BwResult<Value> {
    let key = type_key(cipher.r#type).ok_or_else(|| {
        BwError::msg(format!(
            "Cipher {} has an invalid type {}",
            cipher.id, cipher.r#type
        ))
    })?;
    let attachments = if cipher.attachments.is_empty() {
        Value::Null
    } else {
        Value::Array(
            cipher
                .attachments
                .iter()
                .zip(urls)
                .map(|(attachment, url)| attachment_json(attachment, url))
                .collect(),
        )
    };
    let mut object = json!({
        "object": "cipherDetails",
        "id": cipher.id,
        "type": cipher.r#type,
        "creationDate": cipher.creation_date,
        "revisionDate": cipher.revision_date,
        "deletedDate": cipher.deleted_date,
        "reprompt": cipher.reprompt,
        "organizationId": null,
        "key": cipher.key,
        "attachments": attachments,
        // Always true in Vaultwarden: it shows or hides the TOTP counter together with premium.
        "organizationUseTotp": true,
        "collectionIds": [],
        "name": cipher.name,
        "notes": cipher.notes,
        "fields": fields_json(cipher.fields.as_ref()),
        "passwordHistory": password_history_json(cipher.password_history.as_ref()),
        // Every typed object is null but the one that matches `type`.
        "login": null,
        "secureNote": null,
        "card": null,
        "identity": null,
        "sshKey": null,
        "bankAccount": null,
        "driversLicense": null,
        "passport": null,
        "folderId": cipher.folder_id,
        "favorite": cipher.favorite,
        "archivedDate": cipher.archived_date,
        "edit": true,
        "viewPassword": true,
        "permissions": { "delete": true, "restore": true },
    });
    object[key] = type_data_json(cipher.r#type, &cipher.data);
    Ok(object)
}

/// Whether a `Bitwarden-Client-Version` is at least 2024.12.0, which is when `/api/sync` may show
/// SSH keys. A missing or malformed header is no; so is a pre-release, which a semver range of
/// `>=2024.12.0` never matches.
pub(crate) fn shows_ssh_keys(header: Option<&str>) -> bool {
    let Some(version) = header else {
        return false;
    };
    // semver: three numbers without leading zeros, then optionally `-pre` and `+build`.
    let core = version.split('+').next().unwrap_or_default();
    if core.contains('-') {
        return false;
    }
    let mut numbers = Vec::with_capacity(3);
    for part in core.split('.') {
        let valid = !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'));
        match part.parse::<u64>() {
            Ok(n) if valid => numbers.push(n),
            _ => return false,
        }
    }
    numbers.len() == 3 && (numbers[0], numbers[1], numbers[2]) >= (2024, 12, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-21 10:00:00.123456 UTC);
    const USER: &str = "a0c1a4ab-929b-4d7c-940e-502a460d3b58";

    fn request(extra: Value) -> CipherData {
        let mut body = json!({
            "encryptedFor": USER,
            "type": 1,
            "name": "2.name",
            "notes": null,
            "login": {"username": "2.u", "password": "2.p", "uris": []},
        });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                body.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(body).expect("a valid request")
    }

    fn stored(data: CipherData) -> StoredCipher {
        let mut cipher = StoredCipher::new("c1".to_owned(), data.r#type, NOW);
        update_from_data(&mut cipher, data, NOW, false, true).expect("applies");
        cipher
    }

    #[test]
    fn a_new_cipher_shows_every_key_vaultwarden_shows() {
        let out = cipher_json(&stored(request(json!({}))), &[]).expect("json");
        let mut keys: Vec<&str> = out
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "archivedDate",
                "attachments",
                "bankAccount",
                "card",
                "collectionIds",
                "creationDate",
                "deletedDate",
                "driversLicense",
                "edit",
                "favorite",
                "fields",
                "folderId",
                "id",
                "identity",
                "key",
                "login",
                "name",
                "notes",
                "object",
                "organizationId",
                "organizationUseTotp",
                "passport",
                "passwordHistory",
                "permissions",
                "reprompt",
                "revisionDate",
                "secureNote",
                "sshKey",
                "type",
                "viewPassword"
            ]
        );
        assert_eq!(out["object"], "cipherDetails");
        assert_eq!(out["creationDate"], "2026-11-21T10:00:00.123456Z");
        assert_eq!(out["attachments"], Value::Null);
        assert_eq!(out["permissions"], json!({"delete": true, "restore": true}));
        assert_eq!(out["secureNote"], Value::Null);
    }

    #[test]
    fn a_login_shows_uri_and_keeps_unknown_keys() {
        let data = request(json!({
            "login": {
                "Username": "2.u",
                "uris": [{"uri": "2.first", "match": "3", "uriChecksum": "2.sum", "extra": 1},
                         {"uri": "2.second", "match": null}],
                "fido2Credentials": [{"credentialId": "2.id", "counter": "0"}],
                "passwordRevisionDate": "2026-01-02T03:04:05Z",
                "somethingNew": {"Inner": true}
            }
        }));
        let out = cipher_json(&stored(data), &[]).expect("json");
        let login = &out["login"];
        assert_eq!(
            login["username"], "2.u",
            "the first letter of a key is lower-cased"
        );
        assert_eq!(login["uri"], "2.first");
        assert_eq!(
            login["uris"][0]["match"], 3,
            "a textual match becomes a number"
        );
        assert_eq!(login["uris"][0]["extra"], 1);
        assert_eq!(login["uris"][1]["match"], Value::Null);
        assert_eq!(login["fido2Credentials"][0]["counter"], "0");
        assert_eq!(login["somethingNew"]["inner"], true);
        assert_eq!(login["passwordRevisionDate"], "2026-01-02T03:04:05.000000Z");
    }

    #[test]
    fn a_login_without_uris_gets_null_uri_and_null_uris() {
        let data = request(json!({"login": {"username": "2.u"}}));
        let out = cipher_json(&stored(data), &[]).expect("json");
        assert_eq!(out["login"]["uri"], Value::Null);
        assert_eq!(out["login"]["uris"], Value::Null);
    }

    #[test]
    fn fields_are_repaired_the_way_vaultwarden_repairs_them() {
        let data = request(json!({
            "fields": [
                {"name": "n1", "value": "v1", "type": 0},
                {"name": "n2", "value": "v2", "type": "2"},
                {"name": "n3", "value": "v3", "type": "text"},
                {"name": "n4", "value": "v4"},
                {"name": "n5", "response": {"x": 1}, "type": 1}
            ]
        }));
        let out = cipher_json(&stored(data), &[]).expect("json");
        let types: Vec<&Value> = out["fields"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|f| &f["type"])
            .collect();
        assert_eq!(types, [0, 2, 1, 1, 1]);
        assert!(out["fields"][4].get("response").is_none());
    }

    #[test]
    fn password_history_keeps_only_entries_with_a_text_password() {
        let data = request(json!({
            "passwordHistory": [
                {"password": "2.a", "lastUsedDate": "2026-01-01T00:00:00Z"},
                {"password": null, "lastUsedDate": "2026-01-01T00:00:00Z"},
                {"password": "2.b"},
                {"password": "2.c", "lastUsedDate": "nonsense"}
            ]
        }));
        let out = cipher_json(&stored(data), &[]).expect("json");
        let history = out["passwordHistory"].as_array().expect("an array");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0]["lastUsedDate"], "2026-01-01T00:00:00.000000Z");
        assert_eq!(history[1]["lastUsedDate"], "1970-01-01T00:00:00.000000Z");
        assert_eq!(history[2]["lastUsedDate"], "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn secure_notes_and_ssh_keys_are_repaired() {
        let note = request(json!({"type": 2, "secureNote": {"type": "x"}}));
        let out = cipher_json(&stored(note), &[]).expect("json");
        assert_eq!(out["secureNote"], json!({"type": 0}));

        let good = json!({"privateKey": "2.k", "publicKey": "2.p", "keyFingerprint": "2.f"});
        let ssh = request(json!({"type": 5, "sshKey": good}));
        let out = cipher_json(&stored(ssh), &[]).expect("json");
        assert_eq!(out["sshKey"]["privateKey"], "2.k");

        let bad = request(json!({"type": 5, "sshKey": {"privateKey": "2.k", "publicKey": ""}}));
        let out = cipher_json(&stored(bad), &[]).expect("json");
        assert_eq!(out["sshKey"], Value::Null);
    }

    #[test]
    fn requests_are_checked_the_way_vaultwarden_checks_them() {
        let mut c = StoredCipher::new("c1".to_owned(), 1, NOW);
        let apply = |c: &mut StoredCipher, d: CipherData| update_from_data(c, d, NOW, true, true);

        assert_eq!(
            apply(&mut c, request(json!({"type": 9}))),
            Err(BwError::msg("Invalid type"))
        );
        assert_eq!(
            apply(&mut c, request(json!({"login": null}))),
            Err(BwError::msg("Data missing"))
        );
        let long_note = "n".repeat(MAX_NOTE_SIZE + 1);
        assert_eq!(
            apply(&mut c, request(json!({"notes": long_note}))),
            Err(note_too_long())
        );
        assert_eq!(
            update_from_data(&mut c, request(json!({})), NOW, true, false),
            Err(BwError::msg("Invalid folder"))
        );
        assert!(apply(&mut c, request(json!({"type": 1}))).is_ok());
    }

    #[test]
    fn a_stale_write_is_refused_but_an_unparsable_date_is_ignored() {
        let mut c = stored(request(json!({})));
        let later = datetime!(2026-11-21 10:05:00 UTC);
        let apply = |c: &mut StoredCipher, sent: &str, at: OffsetDateTime| {
            update_from_data(
                c,
                request(json!({"lastKnownRevisionDate": sent})),
                at,
                true,
                true,
            )
        };
        // The stored time is 10:00:00.123456. A client copy under 2 s older passes; 2 s older does not.
        assert!(apply(&mut c, "2026-11-21T09:59:59.500000Z", later).is_ok());
        let mut c = stored(request(json!({})));
        assert_eq!(
            apply(&mut c, "2026-11-21T09:59:58Z", later),
            Err(BwError::msg(OUT_OF_DATE))
        );
        // A client copy newer than the stored one is fine, and the mobile apps' null date too.
        assert!(apply(&mut c, "2026-11-21T10:30:00Z", later).is_ok());
        assert!(apply(&mut c, "0001-01-01T00:00:00", later).is_ok());
        // No check on an import.
        let mut c = stored(request(json!({})));
        assert!(
            update_from_data(
                &mut c,
                request(json!({"lastKnownRevisionDate": "2000-01-01T00:00:00Z"})),
                later,
                false,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn an_update_replaces_what_it_names_and_keeps_the_rest() {
        let mut c = stored(request(
            json!({"favorite": true, "folderId": "f1", "notes": "2.n"}),
        ));
        let later = datetime!(2026-11-22 00:00:00 UTC);
        // `favorite` absent keeps the flag; `folderId`, `notes` and `archivedDate` absent clear them.
        update_from_data(&mut c, request(json!({"folderId": ""})), later, true, true).expect("ok");
        assert!(c.favorite);
        assert_eq!(c.folder_id, None);
        assert_eq!(c.notes, None);
        assert_eq!(c.revision_date, "2026-11-22T00:00:00.000000Z");
        assert_eq!(c.creation_date, "2026-11-21T10:00:00.123456Z");
        update_from_data(
            &mut c,
            request(json!({"favorite": false, "archivedDate": "2026-11-22T01:00:00Z"})),
            later,
            true,
            true,
        )
        .expect("ok");
        assert!(!c.favorite);
        assert_eq!(
            c.archived_date.as_deref(),
            Some("2026-11-22T01:00:00.000000Z")
        );
    }

    #[test]
    fn rotation_re_keys_attachments_that_still_exist() {
        let mut c = stored(request(json!({})));
        c.attachments.push(StoredAttachment {
            id: "att1".to_owned(),
            file_name: "2.old".to_owned(),
            size: 17,
            key: Some("2.oldkey".to_owned()),
        });
        let data = request(json!({"attachments2": {
            "att1": {"fileName": "2.new", "key": "2.newkey"},
            "gone": {"fileName": "2.x", "key": "2.y"}
        }}));
        update_from_data(&mut c, data, NOW, true, true).expect("ok");
        assert_eq!(c.attachments[0].file_name, "2.new");
        assert_eq!(c.attachments[0].key.as_deref(), Some("2.newkey"));
        assert_eq!(c.attachments.len(), 1);
    }

    #[test]
    fn attachments_show_their_size_and_link() {
        let mut c = stored(request(json!({})));
        c.attachments.push(StoredAttachment {
            id: "att1".to_owned(),
            file_name: "2.f".to_owned(),
            size: 17,
            key: None,
        });
        let urls = ["https://v.test/attachments/c1/att1?token=t".to_owned()];
        let out = cipher_json(&c, &urls).expect("json");
        let attachment = &out["attachments"][0];
        assert_eq!(attachment["size"], "17");
        assert_eq!(attachment["sizeName"], "17.00 bytes");
        assert_eq!(attachment["url"], urls[0]);
        assert_eq!(attachment["object"], "attachment");
        assert_eq!(attachment["key"], Value::Null);
        assert_eq!(display_size(1500), "1.46 KB");
        assert_eq!(display_size(3 * 1024 * 1024), "3.00 MB");
        assert_eq!(display_size(1024), "1024.00 bytes");
    }

    #[test]
    fn an_import_names_every_bad_cipher() {
        let fine = request(json!({}));
        let long = request(json!({"notes": "n".repeat(MAX_NOTE_SIZE + 1)}));
        let nulled = request(json!({"passwordHistory": [{"password": null}]}));
        assert!(validate_import(&[fine]).is_ok());
        let Err(BwError::Json(body)) = validate_import(&[long, nulled]) else {
            panic!("a refusal");
        };
        assert_eq!(body["message"], "The model state is invalid.");
        assert_eq!(body["object"], "error");
        assert!(body["validationErrors"]["Ciphers[0].Notes"].is_array());
        assert!(body["validationErrors"]["Ciphers[1].Notes"].is_array());
    }

    #[test]
    fn a_body_without_encrypted_for_does_not_parse() {
        let body = json!({"type": 1, "name": "2.n", "login": {}});
        assert!(serde_json::from_value::<CipherData>(body).is_err());
    }

    #[test]
    fn ssh_keys_need_a_client_version_of_2024_12_0() {
        for yes in ["2024.12.0", "2025.12.0", "2026.6.1", "2024.12.0+build"] {
            assert!(shows_ssh_keys(Some(yes)), "{yes}");
        }
        for no in [
            "2024.11.9",
            "2024.12",
            "1.1.0",
            "",
            "x.y.z",
            "2024.12.0-beta",
            "2024.012.0",
            "3.0.0",
        ] {
            assert!(!shows_ssh_keys(Some(no)), "{no}");
        }
        assert!(!shows_ssh_keys(None));
    }

    #[test]
    fn keys_differing_in_their_first_letter_become_one() {
        let out =
            lcase_keys(json!({"Name": 1, "name": 2, "SSN": 3, "Inner": {"Deep": [{"Key": 1}]}}));
        assert_eq!(out["ssn"], 3);
        assert_eq!(out["inner"]["deep"][0]["key"], 1);
        assert_eq!(out.as_object().map(Map::len), Some(3));
    }
}
