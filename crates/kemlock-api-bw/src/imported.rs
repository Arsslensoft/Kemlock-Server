//! Ciphers that came from Vaultwarden.
//!
//! The move from Vaultwarden (`kemlock-vaultwarden`) stores each cipher as the JSON Vaultwarden
//! itself would return for it, `cipherDetails` with its repairs already made, so what an app reads
//! back is what it read before, byte for byte. Two things in that JSON are made per request and
//! are not stored: each attachment's download `url` (it carries a token that lives a minute) and,
//! for a cipher an organization owns, what each member sees of it (`folderId`, `favorite`,
//! `archivedDate`, `edit`, `viewPassword`, `permissions`). [`imported_json`] adds them with
//! `kemlock_vaultwarden::cipher_json::{attachment_json, apply_viewer}`.
//!
//! The stored form lists attachments as `{"id", "fileName", "size", "key"}`, the same shape as the
//! Bitwarden API's own [`StoredCipher`] documents, which is what an imported cipher turns into the
//! first time an app changes it ([`stored_from_details`]).

use crate::cipher::{StoredAttachment, StoredCipher, type_key};
use crate::error::BwResult;
use kemlock_vaultwarden::cipher_json::{ViewerState, apply_viewer, attachment_json};
use serde_json::Value;

/// Whether an item's document is Vaultwarden's cipher JSON, as the move stores it, rather than one
/// of the Bitwarden API's own.
pub fn is_imported(doc: &Value) -> bool {
    doc.get("object").and_then(Value::as_str) == Some("cipherDetails")
}

/// The cipher JSON to answer with: the stored document with each attachment's entry made by
/// `attachment_json` (`url_for` gives the download link of an attachment id) and, when `viewer` is
/// given, what that user sees of the cipher added.
pub fn imported_json(
    doc: &Value,
    viewer: Option<&ViewerState>,
    url_for: impl Fn(&str) -> BwResult<String>,
) -> BwResult<Value> {
    let mut json = doc.clone();
    let entries = doc
        .get("attachments")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty());
    json["attachments"] = match entries {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for entry in list {
                let id = entry.get("id").and_then(Value::as_str).unwrap_or_default();
                let url = url_for(id)?;
                out.push(attachment_json(
                    id,
                    &url,
                    entry
                        .get("fileName")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    entry.get("size").and_then(Value::as_i64).unwrap_or(0),
                    entry.get("key").and_then(Value::as_str),
                ));
            }
            Value::Array(out)
        }
        None => Value::Null,
    };
    if let Some(viewer) = viewer {
        apply_viewer(&mut json, viewer);
    }
    Ok(json)
}

/// An imported cipher as the Bitwarden API's own document, so it can be changed like any other.
pub(crate) fn stored_from_details(doc: &Value) -> Option<StoredCipher> {
    let cipher_type = i32::try_from(doc.get("type")?.as_i64()?).ok()?;
    let data_key = type_key(cipher_type)?;
    let text = |key: &str| doc.get(key).and_then(Value::as_str).map(str::to_owned);
    let list = |key: &str| doc.get(key).filter(|v| !v.is_null()).cloned();
    let attachments = doc
        .get("attachments")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    Some(StoredAttachment {
                        id: entry.get("id")?.as_str()?.to_owned(),
                        file_name: entry.get("fileName")?.as_str()?.to_owned(),
                        size: entry.get("size")?.as_i64()?,
                        key: entry.get("key").and_then(Value::as_str).map(str::to_owned),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(StoredCipher {
        id: text("id")?,
        r#type: cipher_type,
        creation_date: text("creationDate")?,
        revision_date: text("revisionDate")?,
        deleted_date: text("deletedDate"),
        reprompt: doc
            .get("reprompt")
            .and_then(Value::as_i64)
            .and_then(|r| i32::try_from(r).ok())
            .unwrap_or(0),
        key: text("key"),
        name: text("name")?,
        notes: text("notes"),
        fields: list("fields"),
        password_history: list("passwordHistory"),
        data: doc.get(data_key).cloned().unwrap_or(Value::Null),
        folder_id: text("folderId"),
        favorite: doc
            .get("favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        archived_date: text("archivedDate"),
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> Value {
        json!({
            "object": "cipherDetails",
            "id": "c1",
            "type": 1,
            "creationDate": "2024-05-01T10:00:00.123456Z",
            "revisionDate": "2024-05-02T11:30:00.000000Z",
            "deletedDate": null,
            "reprompt": 1,
            "organizationId": null,
            "key": "2.k",
            "attachments": [{"id": "a1", "fileName": "2.f", "size": 5, "key": null}],
            "name": "2.name",
            "notes": null,
            "fields": [],
            "passwordHistory": [],
            "login": {"username": "2.u", "uris": null, "uri": null},
            "folderId": "f1",
            "favorite": true,
            "archivedDate": null,
        })
    }

    #[test]
    fn only_cipher_details_are_imported_documents() {
        assert!(is_imported(&doc()));
        assert!(!is_imported(&json!({"id": "c1", "type": 1})));
    }

    #[test]
    fn attachments_get_their_links_and_nothing_else_changes() {
        let served = imported_json(&doc(), None, |id| Ok(format!("https://vault.test/{id}")))
            .expect("serves");
        assert_eq!(served["attachments"][0]["url"], "https://vault.test/a1");
        assert_eq!(served["attachments"][0]["size"], "5");
        assert_eq!(served["attachments"][0]["sizeName"], "5.00 bytes");
        assert_eq!(served["attachments"][0]["object"], "attachment");
        assert_eq!(served["folderId"], "f1");
        assert_eq!(served["name"], "2.name");

        let mut bare = doc();
        bare["attachments"] = Value::Null;
        let served = imported_json(&bare, None, |_| Ok(String::new())).expect("serves");
        assert!(served["attachments"].is_null());
    }

    #[test]
    fn a_viewer_adds_the_per_user_parts() {
        let viewer = ViewerState {
            folder_id: Some("f2".to_owned()),
            favorite: false,
            archived_at: None,
            read_only: true,
            hide_passwords: true,
        };
        let served = imported_json(&doc(), Some(&viewer), |_| Ok(String::new())).expect("serves");
        assert_eq!(served["folderId"], "f2");
        assert_eq!(served["favorite"], false);
        assert_eq!(served["edit"], false);
        assert_eq!(served["viewPassword"], false);
        assert_eq!(
            served["permissions"],
            json!({"delete": false, "restore": false})
        );
    }

    #[test]
    fn an_imported_cipher_becomes_a_stored_one() {
        let cipher = stored_from_details(&doc()).expect("converts");
        assert_eq!(cipher.id, "c1");
        assert_eq!(cipher.r#type, 1);
        assert_eq!(cipher.reprompt, 1);
        assert_eq!(cipher.folder_id.as_deref(), Some("f1"));
        assert!(cipher.favorite);
        assert_eq!(cipher.data["username"], "2.u");
        assert_eq!(cipher.attachments.len(), 1);
        assert_eq!(cipher.attachments[0].id, "a1");
        assert_eq!(cipher.attachments[0].size, 5);
        assert_eq!(cipher.attachments[0].key, None);
        assert_eq!(cipher.name, "2.name");
    }

    #[test]
    fn a_document_without_its_basics_is_not_converted() {
        assert!(stored_from_details(&json!({"object": "cipherDetails"})).is_none());
        let mut odd = doc();
        odd["type"] = json!(99);
        assert!(stored_from_details(&odd).is_none());
    }
}
