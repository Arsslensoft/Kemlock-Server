// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/enpass/enpass-json-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Enpass JSON: `{"folders": [...], "items": [...]}`.
//!
//! Items with a `login.` or `password.` template, or any other template (but not `identity.`)
//! holding a filled password field, are logins; `creditcard.` items are cards; everything else is
//! a note whose fields are kept as custom fields. An item that ends up with nothing to sign in
//! with is a note. Folders form a tree, flattened to `parent/child` paths. Trashed items are left
//! out and listed.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::builder::Builder;
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::model::{
    Card, CustomField, FieldKind, Format, ImportBatch, Login, Meta, Note, SkipReason,
};
use crate::util::{
    card_brand, card_number, clean_name, clean_notes, decode_text, is_blank, is_noteworthy_login,
    jarr, jint, jstr, kvp, make_uris, nonblank, scalar_text, set_card_expiration,
};

/// Folders deeper than this are not followed.
const MAX_TREE_DEPTH: usize = 64;

/// The text of a string or scalar member; empty when there is none.
fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(scalar_text).unwrap_or_default()
}

fn sensitive_kind(field: &Value) -> FieldKind {
    if jint(field, "sensitive") == Some(1) {
        FieldKind::Hidden
    } else {
        FieldKind::Text
    }
}

/// Each titled folder with its `a/b/c` path, parents first. A folder with no title is dropped with
/// everything below it; a parent that is not in the export makes a folder a root; a loop is not
/// followed.
fn folder_paths(folders: &[Value], max: usize) -> Vec<(String, String)> {
    let mut by_uuid: HashMap<&str, usize> = HashMap::new();
    for (i, folder) in folders.iter().enumerate() {
        by_uuid.insert(jstr(folder, "uuid").unwrap_or(""), i);
    }
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, folder) in folders.iter().enumerate() {
        let parent = jstr(folder, "parent_uuid").unwrap_or("");
        if !parent.is_empty() && by_uuid.contains_key(parent) {
            children.entry(parent).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    let mut out = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let mut stack: Vec<(usize, String, usize)> = roots
        .into_iter()
        .rev()
        .map(|i| (i, String::new(), 0))
        .collect();
    while let Some((i, prefix, depth)) = stack.pop() {
        if out.len() >= max || depth > MAX_TREE_DEPTH || !seen.insert(i) {
            continue;
        }
        let Some(folder) = folders.get(i) else {
            continue;
        };
        let title = jstr(folder, "title").unwrap_or("").trim();
        if title.is_empty() {
            continue;
        }
        let path = if is_blank(&prefix) {
            title.to_string()
        } else {
            format!("{prefix}/{title}")
        };
        let uuid = jstr(folder, "uuid").unwrap_or("");
        out.push((uuid.to_string(), path.clone()));
        if let Some(kids) = children.get(uuid) {
            for kid in kids.iter().rev() {
                stack.push((*kid, path.clone(), depth + 1));
            }
        }
    }
    out
}

/// `androidapp://<package>` from what Enpass keeps for an Android app: with the scheme added when
/// missing, an `android://` left in the middle removed, and a base64 hash up to `==@` dropped.
fn clean_android(value: &str) -> String {
    let with_scheme = if value.starts_with("androidapp://") {
        value.to_string()
    } else {
        format!("androidapp://{value}")
    };
    strip_android_hash(&with_scheme.replacen("android://", "", 1))
}

/// Removes `[A-Za-z0-9-_+/]*==@` after each `androidapp://`, in one pass (Bitwarden bounds the
/// regular expression for the same reason).
fn strip_android_hash(s: &str) -> String {
    const PREFIX: &str = "androidapp://";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(PREFIX) {
        out.push_str(&rest[..at]);
        out.push_str(PREFIX);
        let after = &rest[at + PREFIX.len()..];
        let run = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/')))
            .unwrap_or(after.len());
        rest = after[run..].strip_prefix("==@").unwrap_or(after);
    }
    out.push_str(rest);
    out
}

#[derive(Default)]
struct LoginParts {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    urls: Vec<String>,
    fields: Vec<CustomField>,
    notes: Option<String>,
}

fn read_login(fields: &[Value]) -> LoginParts {
    let mut p = LoginParts::default();
    for field in fields {
        let value = text(field, "value");
        let kind = jstr(field, "type").unwrap_or("");
        if is_blank(&value) || kind == "section" {
            continue;
        }
        if (kind == "username" || kind == "email") && p.username.as_deref().is_none_or(is_blank) {
            p.username = Some(value);
        } else if kind == "password" && p.password.as_deref().is_none_or(is_blank) {
            p.password = Some(value);
        } else if kind == "totp" && p.totp.as_deref().is_none_or(is_blank) {
            p.totp = Some(value);
        } else if kind == "url" {
            p.urls.push(value);
        } else if kind == ".Android#" {
            p.urls.push(clean_android(&value));
        } else {
            let label = text(field, "label");
            kvp(
                &mut p.fields,
                &mut p.notes,
                &label,
                &value,
                sensitive_kind(field),
            );
        }
    }
    p
}

fn read_card(fields: &[Value]) -> (Card, Option<String>) {
    let mut card = Card::default();
    let mut notes = None;
    for field in fields {
        let value = text(field, "value");
        let kind = jstr(field, "type").unwrap_or("");
        if is_blank(&value) || kind == "section" || kind == "ccType" {
            continue;
        }
        match kind {
            "ccName" if card.cardholder.is_none() => card.cardholder = Some(value),
            "ccNumber" if card.number.is_none() => {
                card.number = card_number(&value);
                card.brand = card.number.as_deref().and_then(card_brand);
            }
            "ccCvc" if card.code.is_none() => card.code = Some(value),
            "ccPin" if card.pin.is_none() => card.pin = Some(value),
            "ccExpiry" if card.exp_year.is_none() => {
                if !set_card_expiration(&mut card, &value) {
                    let label = text(field, "label");
                    kvp(
                        &mut card.fields,
                        &mut notes,
                        &label,
                        &value,
                        sensitive_kind(field),
                    );
                }
            }
            _ => {
                let label = text(field, "label");
                kvp(
                    &mut card.fields,
                    &mut notes,
                    &label,
                    &value,
                    sensitive_kind(field),
                );
            }
        }
    }
    (card, notes)
}

/// The item's own note, then what its fields spilled into the note.
fn join_notes(own: Option<String>, spill: Option<String>) -> Option<String> {
    let own = own
        .map(|n| n.trim_end().to_string())
        .filter(|n| !is_blank(n));
    match (own, spill) {
        (Some(n), Some(s)) => Some(format!("{n}\n{s}")),
        (Some(n), None) => Some(n),
        (None, s) => s,
    }
}

fn read_item(item: &Value, b: &mut Builder<'_>, folders: &HashMap<String, usize>) {
    let title = jstr(item, "title");
    if jint(item, "trashed").unwrap_or(0) > 0 {
        b.skip(title, SkipReason::Trashed, None);
        return;
    }
    let mut meta = Meta::default();
    if let Some(first) = jarr(item, "folders").first().and_then(Value::as_str)
        && let Some(ix) = folders.get(first)
    {
        meta.folder = Some(*ix);
    }
    meta.favorite = jint(item, "favorite").unwrap_or(0) > 0;
    meta.created_ms = jint(item, "createdAt").map(|s| s.saturating_mul(1000));
    meta.modified_ms = jint(item, "updated_at").map(|s| s.saturating_mul(1000));
    meta.source_id = jstr(item, "uuid").map(str::to_string);

    let name = clean_name(title);
    let own_note = nonblank(item.get("note").and_then(Value::as_str));
    let fields = jarr(item, "fields");
    let template = jstr(item, "template_type");

    enum Shape {
        Login,
        Card,
        Note,
    }
    let shape = match template {
        Some(t) if !fields.is_empty() => {
            if t.starts_with("login.") || t.starts_with("password.") {
                Shape::Login
            } else if t.starts_with("creditcard.") {
                Shape::Card
            } else if !t.contains("identity.")
                && fields
                    .iter()
                    .any(|f| jstr(f, "type") == Some("password") && !is_blank(&text(f, "value")))
            {
                Shape::Login
            } else {
                Shape::Note
            }
        }
        _ => Shape::Login,
    };

    match shape {
        Shape::Card => {
            let (mut card, spill) = read_card(fields);
            card.name = name;
            card.notes = clean_notes(join_notes(own_note, spill));
            card.meta = meta;
            b.card(card);
        }
        Shape::Note => {
            let mut note_fields = Vec::new();
            let mut spill = None;
            for field in fields {
                let value = text(field, "value");
                if is_blank(&value) || jstr(field, "type") == Some("section") {
                    continue;
                }
                let label = text(field, "label");
                kvp(
                    &mut note_fields,
                    &mut spill,
                    &label,
                    &value,
                    sensitive_kind(field),
                );
            }
            b.note(Note {
                name,
                text: clean_notes(join_notes(own_note, spill)),
                fields: note_fields,
                meta,
            });
        }
        Shape::Login => {
            let parts = read_login(fields);
            let login = Login {
                name: name.clone(),
                uris: make_uris(parts.urls.iter().map(String::as_str)),
                username: parts.username,
                password: parts.password,
                totp: parts.totp,
                notes: clean_notes(join_notes(own_note, parts.notes)),
                fields: parts.fields,
                meta: meta.clone(),
                ..Login::default()
            };
            if is_noteworthy_login(&login) && login.totp.is_none() {
                b.note(Note {
                    name,
                    text: login.notes,
                    fields: login.fields,
                    meta,
                });
            } else {
                b.login(login);
            }
        }
    }
}

/// Reads an Enpass JSON export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    ctx.limits.check_input(bytes)?;
    let source = decode_text(bytes);
    let root: Value = serde_json::from_str(&source).map_err(|_| ImportError::Unsupported)?;
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ImportError::Unsupported)?;

    let mut b = Builder::new(Format::EnpassJson, ctx.limits);
    let mut folders: HashMap<String, usize> = HashMap::new();
    for (uuid, path) in folder_paths(jarr(&root, "folders"), ctx.limits.max_entries) {
        if let Some(ix) = b.folder(&path) {
            folders.insert(uuid, ix);
        }
    }
    for (i, item) in items.iter().enumerate() {
        if !item.is_object() {
            b.skip(None, SkipReason::Malformed, None);
            continue;
        }
        if b.full() {
            b.note_unread(items.len() - i);
            break;
        }
        read_item(item, &mut b, &folders);
    }
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const EXPORT: &str = include_str!("../tests/fixtures/enpass/export.json");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    fn field<'a>(fields: &'a [CustomField], name: &str) -> Option<&'a CustomField> {
        fields.iter().find(|f| f.name == name)
    }

    #[test]
    fn reads_the_export() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.format, Format::EnpassJson);
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.notes.len(), 2);
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::Trashed);
        assert_eq!(batch.skipped[0].name.as_deref(), Some("Old account"));
    }

    #[test]
    fn folders_are_flattened_and_untitled_ones_drop_their_children() {
        let batch = read(EXPORT).expect("batch");
        let paths: Vec<&str> = batch.folders.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["Personal", "Personal/Banking"]);
        assert_eq!(batch.folders[1].parent, Some(0));
    }

    #[test]
    fn a_login_keeps_its_websites_code_fields_and_dates() {
        let batch = read(EXPORT).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example");
        assert_eq!(login.username.as_deref(), Some("ada@example.com"));
        assert_eq!(login.password.as_deref(), Some("pw1"));
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let uris: Vec<&str> = login.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(uris, ["https://example.com", "http://example.org"]);
        assert_eq!(login.notes.as_deref(), Some("Some note"));
        let recovery = field(&login.fields, "Recovery").expect("field");
        assert_eq!(recovery.value, "abc");
        assert_eq!(recovery.kind, FieldKind::Hidden);
        assert_eq!(
            field(&login.fields, "PIN").map(|f| f.kind),
            Some(FieldKind::Hidden)
        );
        assert_eq!(login.fields.len(), 2);
        assert!(login.meta.favorite);
        assert_eq!(login.meta.folder, Some(1));
        assert_eq!(login.meta.created_ms, Some(1_600_000_000_000));
        assert_eq!(login.meta.modified_ms, Some(1_600_000_100_000));
        assert_eq!(login.meta.source_id.as_deref(), Some("i1"));
    }

    #[test]
    fn an_android_address_loses_its_hash() {
        let batch = read(EXPORT).expect("batch");
        let app = &batch.logins[1];
        assert_eq!(app.name, "App");
        assert_eq!(app.uris.len(), 1);
        assert_eq!(app.uris[0].uri, "androidapp://com.example.app/");
        assert_eq!(
            clean_android("androidapp://aGFzaA==@com.x"),
            "androidapp://com.x"
        );
        assert_eq!(clean_android("com.y"), "androidapp://com.y");
        assert_eq!(
            strip_android_hash("androidapp://androidapp://ab==@c"),
            "androidapp://androidapp://c"
        );
        assert_eq!(
            strip_android_hash("x androidapp://ab==@c androidapp://d"),
            "x androidapp://c androidapp://d"
        );
    }

    #[test]
    fn a_card_is_read_from_its_typed_fields() {
        let batch = read(EXPORT).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.name, "Visa");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert_eq!(card.pin.as_deref(), Some("9999"));
        assert_eq!(card.fields.len(), 1);
        assert_eq!(card.fields[0].name, "Bank");
    }

    #[test]
    fn items_without_a_sign_in_are_notes() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.notes[0].name, "Plain note");
        assert_eq!(batch.notes[0].text.as_deref(), Some("Just text"));
        assert_eq!(batch.notes[1].name, "Me");
        assert_eq!(batch.notes[1].fields[0].name, "First name");
        assert_eq!(batch.notes[1].fields[0].value, "Ada");
    }

    #[test]
    fn a_folder_loop_does_not_hang() {
        let text = r#"{"folders":[
            {"uuid":"x","title":"A","parent_uuid":""},
            {"uuid":"x","title":"B","parent_uuid":"x"},
            {"uuid":"y","title":"C","parent_uuid":"z"},
            {"uuid":"z","title":"D","parent_uuid":"y"}],
          "items":[{"title":"t","template_type":"login.default","fields":[{"type":"username","value":"u"}]}]}"#;
        let batch = read(text).expect("batch");
        assert!(batch.folders.len() <= 2);
        assert_eq!(batch.logins.len(), 1);
    }

    #[test]
    fn entries_over_the_limit_are_counted() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let batch = parse(EXPORT.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 2);
        // The four items after the second were not read.
        assert_eq!(
            batch.skipped.iter().map(|s| s.count).sum::<usize>(),
            batch.skipped_count()
        );
        assert!(batch.skipped_count() >= 3);
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("[1,2]").err(), Some(ImportError::Unsupported));
        assert_eq!(
            read("{\"folders\":[]}").err(),
            Some(ImportError::Unsupported)
        );
        assert_eq!(read("{\"items\":[]}").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_items_do_not_panic() {
        for text in [
            r#"{"items":[1,null,"x",{"fields":5},{"title":5,"template_type":3,"fields":[null,1,{}]}]}"#,
            r#"{"items":[{"template_type":"creditcard.default","fields":[{"type":"ccExpiry","value":"13/99"}]}]}"#,
            r#"{"items":[{"folders":[1],"favorite":"x","createdAt":9223372036854775807}]}"#,
        ] {
            let _ = read(text);
        }
    }
}
