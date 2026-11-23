// Ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/db/models/cipher.rs (Cipher::to_json), src/util.rs (lcase_first, process_json_key).
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! The JSON Vaultwarden 1.37.5 returns for a cipher, built the way its `Cipher::to_json`
//! (`src/db/models/cipher.rs`) builds it, so the Bitwarden API can serve the same bytes.
//!
//! Vaultwarden builds a cipher's JSON per request, and parts of it depend on who asks. This module
//! splits it the same way:
//!
//! - [`base_json`] is everything that doesn't depend on the viewer: the cipher's own columns, its
//!   cleaned `fields`, `passwordHistory` and type data, and `collectionIds`. It is what Vaultwarden
//!   returns for an organization listing, and it is what a Kemlock `bw` item stores. `attachments`
//!   is `null` in it, because each attachment's `url` carries a token that is made per request.
//! - [`apply_viewer`] adds what Vaultwarden adds for a user's sync: `folderId`, `favorite`,
//!   `archivedDate`, `edit`, `viewPassword` and `permissions`.
//! - [`attachment_json`] is one entry of `attachments`.
//!
//! Object keys come out in alphabetical order, as Vaultwarden's do (`serde_json` without
//! `preserve_order`). Clients treat objects as unordered either way.

use crate::vwtime::{display_size, format_date, validate_and_format_date};
use serde_json::{Map, Value, json};
use time::PrimitiveDateTime;

/// The columns of a `ciphers` row that go into its JSON.
#[derive(Clone, Debug)]
pub struct CipherParts<'a> {
    pub id: &'a str,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
    pub deleted_at: Option<PrimitiveDateTime>,
    pub organization_uuid: Option<&'a str>,
    pub key: Option<&'a str>,
    pub atype: i64,
    pub name: &'a str,
    pub notes: Option<&'a str>,
    pub fields: Option<&'a str>,
    pub data: &'a str,
    pub password_history: Option<&'a str>,
    pub reprompt: Option<i64>,
}

/// What a user's sync adds to a cipher.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewerState {
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub archived_at: Option<PrimitiveDateTime>,
    /// The viewer may not edit the cipher.
    pub read_only: bool,
    /// The viewer may not see its passwords.
    pub hide_passwords: bool,
}

fn lcase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
    }
}

// The `ssn` key of an identity is the one key Vaultwarden keeps entirely lower-case.
fn process_json_key(key: &str) -> String {
    if key.to_lowercase() == "ssn" {
        "ssn".to_owned()
    } else {
        lcase_first(key)
    }
}

/// Vaultwarden's `convert_json_key_lcase_first`: lower-cases the first letter of every key, at
/// every depth.
pub fn lcase_keys(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(lcase_keys).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, inner) in map {
                out.insert(process_json_key(&key), lcase_keys(inner));
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// `serde_json::from_str::<LowerCase<Value>>`: a JSON object with lower-cased keys; anything
/// else is an error.
fn parse_lower_object(text: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(object @ Value::Object(_)) => Some(lcase_keys(object)),
        _ => None,
    }
}

/// `serde_json::from_str::<Vec<LowerCase<Value>>>`: a JSON array of objects; one element that
/// isn't an object makes the whole value an error.
fn parse_lower_objects(text: &str) -> Option<Vec<Value>> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) if items.iter().all(Value::is_object) => {
            Some(items.into_iter().map(lcase_keys).collect())
        }
        _ => None,
    }
}

fn clean_fields(text: Option<&str>) -> Vec<Value> {
    let Some(mut fields) = text.and_then(parse_lower_objects) else {
        return Vec::new();
    };
    for field in &mut fields {
        // The type must be a number; strings break some clients. A string becomes its number,
        // and anything else becomes 1, the hidden type, so nothing is shown by accident.
        let kind = match field.get("type") {
            Some(t) if t.is_number() => None,
            Some(t) if t.is_string() => Some(t.as_str().unwrap_or("1").parse::<u8>().unwrap_or(1)),
            _ => Some(1),
        };
        if let (Some(kind), Value::Object(map)) = (kind, &mut *field) {
            map.insert("type".to_owned(), json!(kind));
        }
    }
    fields
}

fn clean_password_history(text: Option<&str>) -> Vec<Value> {
    let Some(items) = text.and_then(parse_lower_objects) else {
        return Vec::new();
    };
    items
        .into_iter()
        // An entry whose password isn't a string breaks newer clients.
        .filter(|entry| entry.get("password").is_some_and(Value::is_string))
        .map(|mut entry| {
            let last_used = match entry.get("lastUsedDate").and_then(Value::as_str) {
                Some(date) => validate_and_format_date(date),
                None => "1970-01-01T00:00:00.000000Z".to_owned(),
            };
            if let Value::Object(map) = &mut entry {
                map.insert("lastUsedDate".to_owned(), json!(last_used));
            }
            entry
        })
        .collect()
}

/// The key under which a cipher type's data sits, or `None` for a type Vaultwarden rejects.
pub fn type_key(atype: i64) -> Option<&'static str> {
    match atype {
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

/// A name for a cipher type that is a valid Kemlock item kind (`[a-z0-9_-]`).
pub fn kind_name(atype: i64) -> Option<&'static str> {
    match atype {
        1 => Some("login"),
        2 => Some("secure-note"),
        3 => Some("card"),
        4 => Some("identity"),
        5 => Some("ssh-key"),
        6 => Some("bank-account"),
        7 => Some("drivers-license"),
        8 => Some("passport"),
        _ => None,
    }
}

fn clean_type_data(parts: &CipherParts<'_>) -> Value {
    // Mobile clients crash on a missing object, so a bad one becomes `{}`.
    let mut data = parse_lower_object(parts.data).unwrap_or_else(|| Value::Object(Map::new()));

    if parts.atype == 1
        && let Value::Object(map) = &mut data
    {
        // Several mobile clients still read `uri`, the first of `uris`; upstream always has it.
        map.insert("uri".to_owned(), Value::Null);
        // Vaultwarden indexes `uris` mutably, which adds a null one when it is missing.
        let slot = map.entry("uris".to_owned()).or_insert(Value::Null);
        let mut first_uri = None;
        if let Some(uris) = slot.as_array_mut()
            && !uris.is_empty()
        {
            for uri in uris.iter_mut() {
                // `match` is a number or null; a string becomes its number, or null.
                if uri.get("match").is_some_and(Value::is_string) {
                    let number = uri
                        .get("match")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .parse::<u8>();
                    let value = match number {
                        Ok(n) => json!(n),
                        Err(_) => Value::Null,
                    };
                    if let Value::Object(entry) = uri {
                        entry.insert("match".to_owned(), value);
                    }
                }
            }
            first_uri = Some(uris[0].get("uri").cloned().unwrap_or(Value::Null));
        }
        if let Some(first) = first_uri {
            map.insert("uri".to_owned(), first);
        }
        let revision = map
            .get("passwordRevisionDate")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(revision) = revision {
            map.insert(
                "passwordRevisionDate".to_owned(),
                json!(validate_and_format_date(&revision)),
            );
        }
    }

    // A secure note needs a numeric `type`; without one the native clients break.
    if parts.atype == 2 && !data.get("type").is_some_and(Value::is_number) {
        data = json!({ "type": 0 });
    }

    // An SSH key with a missing part breaks the mobile client; the only fix is `null`.
    if parts.atype == 5 {
        let empty = |key: &str| {
            data.get(key)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        };
        if empty("keyFingerprint") || empty("privateKey") || empty("publicKey") {
            data = Value::Null;
        }
    }
    data
}

/// The viewer-independent JSON of a cipher, or `None` for a cipher type Vaultwarden doesn't
/// serve (it answers a sync containing one with an error).
///
/// `collection_ids` are the collections the cipher is in; the caller sorts them.
pub fn base_json(parts: &CipherParts<'_>, collection_ids: &[String]) -> Option<Value> {
    let key = type_key(parts.atype)?;
    let reprompt = parts.reprompt.filter(|r| *r == 0 || *r == 1).unwrap_or(0);
    let mut object = json!({
        "object": "cipherDetails",
        "id": parts.id,
        "type": parts.atype,
        "creationDate": format_date(parts.created_at),
        "revisionDate": format_date(parts.updated_at),
        "deletedDate": parts.deleted_at.map_or(Value::Null, |d| Value::String(format_date(d))),
        "reprompt": reprompt,
        "organizationId": parts.organization_uuid,
        "key": parts.key,
        // Attachment URLs carry a token made per request; the server fills this in.
        "attachments": Value::Null,
        // Vaultwarden sets UseTotp on every organization, and this shows the TOTP counter.
        "organizationUseTotp": true,
        "collectionIds": collection_ids,
        "name": parts.name,
        "notes": parts.notes,
        "fields": clean_fields(parts.fields),
        "passwordHistory": clean_password_history(parts.password_history),
        // Every type is `null` except the one that matches.
        "login": null,
        "secureNote": null,
        "card": null,
        "identity": null,
        "sshKey": null,
        "bankAccount": null,
        "driversLicense": null,
        "passport": null,
    });
    object[key] = clean_type_data(parts);
    Some(object)
}

/// Adds what a user's sync adds to a cipher's JSON.
pub fn apply_viewer(json: &mut Value, viewer: &ViewerState) {
    if let Value::Object(map) = json {
        map.insert("folderId".to_owned(), json!(viewer.folder_id));
        map.insert("favorite".to_owned(), json!(viewer.favorite));
        map.insert(
            "archivedDate".to_owned(),
            viewer
                .archived_at
                .map_or(Value::Null, |d| Value::String(format_date(d))),
        );
        // True unless an organization's collection or group says read-only or hide-passwords.
        map.insert("edit".to_owned(), json!(!viewer.read_only));
        map.insert("viewPassword".to_owned(), json!(!viewer.hide_passwords));
        // The key clients have read since v2025.6.0.
        map.insert(
            "permissions".to_owned(),
            json!({ "delete": !viewer.read_only, "restore": !viewer.read_only }),
        );
    }
}

/// One entry of a cipher's `attachments`, as Vaultwarden's `Attachment::to_json` builds it. `url`
/// is the per-request download URL.
pub fn attachment_json(
    id: &str,
    url: &str,
    file_name: &str,
    size: i64,
    key: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "url": url,
        "fileName": file_name,
        "size": size.to_string(),
        "sizeName": display_size(size),
        "key": key,
        "object": "attachment",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vwtime::parse_db_time;

    fn t(text: &str) -> PrimitiveDateTime {
        parse_db_time(text).expect("a time")
    }

    fn parts(atype: i64, data: &str) -> CipherParts<'_> {
        CipherParts {
            id: "0b2a8e83-2a3b-4d6e-8a54-0d5fd1b1d6a1",
            created_at: t("2024-05-01 10:00:00.123456"),
            updated_at: t("2024-05-02 11:30:00"),
            deleted_at: None,
            organization_uuid: None,
            key: None,
            atype,
            name: "2.name|iv|mac",
            notes: None,
            fields: None,
            data,
            password_history: None,
            reprompt: None,
        }
    }

    #[test]
    fn keys_are_lowercased_at_every_depth_except_ssn() {
        let value: Value =
            serde_json::from_str(r#"{"FirstName":"a","SSN":"b","Uris":[{"Uri":"u","Match":1}]}"#)
                .expect("json");
        assert_eq!(
            lcase_keys(value),
            json!({"firstName":"a","ssn":"b","uris":[{"uri":"u","match":1}]})
        );
    }

    #[test]
    fn a_login_is_cleaned_like_vaultwarden_cleans_it() {
        let mut p = parts(
            1,
            r#"{"Username":"u","Password":"p","Totp":null,
                "PasswordRevisionDate":"2024-01-01T00:00:00Z",
                "Uris":[{"Uri":"https://a.example","Match":"1"},{"Uri":"https://b.example","Match":"x"}]}"#,
        );
        p.fields =
            Some(r#"[{"Type":"1","Name":"n","Value":"v"},{"Name":"x"},{"Type":0,"Name":"y"}]"#);
        p.password_history = Some(
            r#"[{"Password":"old","LastUsedDate":"2023-01-01T00:00:00Z"},
                {"Password":null,"LastUsedDate":"x"},{"Password":"older"}]"#,
        );
        p.reprompt = Some(1);
        p.notes = Some("2.notes|iv|mac");
        let json = base_json(&p, &["c1".to_owned()]).expect("a login");
        assert_eq!(
            json,
            json!({
                "object": "cipherDetails",
                "id": "0b2a8e83-2a3b-4d6e-8a54-0d5fd1b1d6a1",
                "type": 1,
                "creationDate": "2024-05-01T10:00:00.123456Z",
                "revisionDate": "2024-05-02T11:30:00.000000Z",
                "deletedDate": null,
                "reprompt": 1,
                "organizationId": null,
                "key": null,
                "attachments": null,
                "organizationUseTotp": true,
                "collectionIds": ["c1"],
                "name": "2.name|iv|mac",
                "notes": "2.notes|iv|mac",
                "fields": [
                    {"type": 1, "name": "n", "value": "v"},
                    {"type": 1, "name": "x"},
                    {"type": 0, "name": "y"}
                ],
                "passwordHistory": [
                    {"password": "old", "lastUsedDate": "2023-01-01T00:00:00.000000Z"},
                    {"password": "older", "lastUsedDate": "1970-01-01T00:00:00.000000Z"}
                ],
                "login": {
                    "username": "u",
                    "password": "p",
                    "totp": null,
                    "passwordRevisionDate": "2024-01-01T00:00:00.000000Z",
                    "uri": "https://a.example",
                    "uris": [
                        {"uri": "https://a.example", "match": 1},
                        {"uri": "https://b.example", "match": null}
                    ]
                },
                "secureNote": null,
                "card": null,
                "identity": null,
                "sshKey": null,
                "bankAccount": null,
                "driversLicense": null,
                "passport": null
            })
        );
    }

    #[test]
    fn a_login_without_uris_gets_null_uri_and_uris() {
        let json = base_json(&parts(1, r#"{"Username":"u"}"#), &[]).expect("a login");
        assert_eq!(json["login"]["uri"], Value::Null);
        assert_eq!(json["login"]["uris"], Value::Null);
        assert_eq!(json["login"]["username"], "u");
        assert_eq!(json["collectionIds"], json!([]));
    }

    #[test]
    fn broken_data_becomes_what_clients_can_open() {
        // Not an object: an empty one.
        let json = base_json(&parts(3, "[1,2]"), &[]).expect("a card");
        assert_eq!(json["card"], json!({}));
        // A secure note without a numeric type.
        let json = base_json(&parts(2, r#"{"Type":"0"}"#), &[]).expect("a note");
        assert_eq!(json["secureNote"], json!({"type": 0}));
        let json = base_json(&parts(2, r#"{"Type":1}"#), &[]).expect("a note");
        assert_eq!(json["secureNote"], json!({"type": 1}));
        // An SSH key missing a part is null; a whole one is kept.
        let json = base_json(&parts(5, r#"{"PrivateKey":"k","PublicKey":"p"}"#), &[]).expect("ssh");
        assert_eq!(json["sshKey"], Value::Null);
        let whole = r#"{"PrivateKey":"k","PublicKey":"p","KeyFingerprint":"f"}"#;
        let json = base_json(&parts(5, whole), &[]).expect("ssh");
        assert_eq!(
            json["sshKey"],
            json!({"privateKey":"k","publicKey":"p","keyFingerprint":"f"})
        );
        // Fields that aren't all objects are dropped as a whole.
        let mut p = parts(2, r#"{"Type":0}"#);
        p.fields = Some(r#"[{"Name":"a"}, "oops"]"#);
        assert_eq!(base_json(&p, &[]).expect("a note")["fields"], json!([]));
    }

    #[test]
    fn unknown_types_are_not_served() {
        assert!(base_json(&parts(9, "{}"), &[]).is_none());
        assert!(base_json(&parts(0, "{}"), &[]).is_none());
        assert_eq!(kind_name(5), Some("ssh-key"));
        assert_eq!(kind_name(9), None);
    }

    #[test]
    fn organization_and_trash_columns_are_carried() {
        let mut p = parts(2, r#"{"Type":0}"#);
        p.organization_uuid = Some("org-1");
        p.deleted_at = Some(t("2024-06-01 00:00:00"));
        p.reprompt = Some(7);
        p.key = Some("2.key|iv|mac");
        let json = base_json(&p, &["c2".to_owned(), "c9".to_owned()]).expect("a note");
        assert_eq!(json["organizationId"], "org-1");
        assert_eq!(json["deletedDate"], "2024-06-01T00:00:00.000000Z");
        assert_eq!(json["reprompt"], 0, "only 0 and 1 are valid");
        assert_eq!(json["key"], "2.key|iv|mac");
        assert_eq!(json["collectionIds"], json!(["c2", "c9"]));
    }

    #[test]
    fn the_viewer_adds_folder_favorite_archive_and_permissions() {
        let mut json = base_json(&parts(2, r#"{"Type":0}"#), &[]).expect("a note");
        let viewer = ViewerState {
            folder_id: Some("f1".to_owned()),
            favorite: true,
            archived_at: Some(t("2025-01-02 03:04:05")),
            read_only: false,
            hide_passwords: true,
        };
        apply_viewer(&mut json, &viewer);
        assert_eq!(json["folderId"], "f1");
        assert_eq!(json["favorite"], true);
        assert_eq!(json["archivedDate"], "2025-01-02T03:04:05.000000Z");
        assert_eq!(json["edit"], true);
        assert_eq!(json["viewPassword"], false);
        assert_eq!(
            json["permissions"],
            json!({"delete": true, "restore": true})
        );

        let mut again = base_json(&parts(2, r#"{"Type":0}"#), &[]).expect("a note");
        apply_viewer(&mut again, &ViewerState::default());
        assert_eq!(again["folderId"], Value::Null);
        assert_eq!(again["archivedDate"], Value::Null);
        assert_eq!(again["favorite"], false);
    }

    #[test]
    fn attachments_print_like_vaultwarden_prints_them() {
        assert_eq!(
            attachment_json(
                "a1",
                "https://vw/attachments/c/a1?token=t",
                "2.f|i|m",
                1536,
                Some("2.k|i|m")
            ),
            json!({
                "id": "a1",
                "url": "https://vw/attachments/c/a1?token=t",
                "fileName": "2.f|i|m",
                "size": "1536",
                "sizeName": "1.50 KB",
                "key": "2.k|i|m",
                "object": "attachment"
            })
        );
    }
}
