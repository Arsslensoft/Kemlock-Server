// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/keeper/keeper-json-importer.ts,
//   libs/importer/src/importers/keeper/keeper-importer.ts and
//   libs/importer/src/importers/keeper/types/keeper-json-types.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Keeper JSON: `{"records": [...], "shared_folders": [...]}`.
//!
//! A record's `$type` picks the kind: `bankCard` is a card, `driverLicense`, `ssnCard` and
//! `passport` are identities with one document, `sshKeys` is an SSH key (a note when it has no
//! private key), and anything else is a login (a note when it has nothing to sign in with).
//! `custom_fields` keys look like `$type:name:N`; the type says how the value is read, and what the
//! kind doesn't take becomes a custom field. A one-time code on a login is its `totp`, on anything
//! else a code of its own. A record's `shared_folder` is a shared folder (a space); its `folder` is
//! a folder. `references` copy a field of another record by `uid`.
//!
//! The SSH key is taken as exported (no conversion to OpenSSH format) and its passphrase, the
//! record's password, is kept as a hidden field. Custom fields are read in the order serde_json
//! keeps an object's keys.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::builder::Builder;
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::model::{
    Card, Code, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity, ImportBatch,
    Login, Meta, Note, SharedKind, SkipReason, SshKey, UriRule,
};
use crate::util::{
    add_field, as_int, card_brand, card_number, clean_name, clean_notes, decode_text, is_blank,
    is_noteworthy_login, jarr, jint, jstr, make_uris, nonblank, parse_iso_ms, parse_month,
    parse_year, scalar_text, ymd_from_ms,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
}

/// What a `references` entry points at: the record with this `uid`, and the field to copy.
struct Reference {
    id: String,
    field: String,
}

/// One record while it is read: Bitwarden's `CipherView`, with the pieces of every kind.
struct Draft {
    kind: Kind,
    name: Option<String>,
    notes: Option<String>,
    username: Option<String>,
    password: Option<String>,
    uris: Vec<UriRule>,
    totp: Option<String>,
    codes: Vec<String>,
    fields: Vec<CustomField>,
    card: Card,
    identity: Identity,
    ssh: SshKey,
    folder: Option<String>,
    spaces: Vec<String>,
    modified_ms: Option<i64>,
    uid: Option<String>,
    references: Vec<Reference>,
}

fn nb(s: &str) -> Option<String> {
    nonblank(Some(s))
}

/// `key.replace(/:?:\d$/, "")`: a trailing `:N` or `::N`, where Keeper numbers repeated fields.
fn strip_instance(key: &str) -> &str {
    let bytes = key.as_bytes();
    let n = bytes.len();
    if n >= 2 && bytes[n - 1].is_ascii_digit() && bytes[n - 2] == b':' {
        let cut = if n >= 3 && bytes[n - 3] == b':' {
            n - 3
        } else {
            n - 2
        };
        &key[..cut]
    } else {
        key
    }
}

/// `$<type>:<name>:<suffix>` as `(type, name)`; a key without `$` is a name only.
fn parse_field_key(key: &str) -> (String, String) {
    if is_blank(key) {
        return (String::new(), String::new());
    }
    let (kind, mut name) = if let Some(rest) = key.strip_prefix('$') {
        match rest.find(':') {
            Some(pos) => (
                rest[..pos].trim().to_string(),
                rest[pos + 1..].trim().to_string(),
            ),
            None => (rest.trim().to_string(), String::new()),
        }
    } else {
        (String::new(), key.to_string())
    };
    let bytes = name.as_bytes();
    let n = bytes.len();
    if n >= 2 && bytes[n - 2] == b':' && bytes[n - 1].is_ascii_digit() {
        name.truncate(n - 2);
    }
    (kind, name)
}

/// JavaScript's `value.toString()` for what a custom field holds.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Keeper's `convertToFieldValue`: a string as it is, anything else as JSON.
fn field_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Whether JavaScript would call the value falsy (`addField` skips those).
fn falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::String(s) => s.is_empty(),
        Value::Number(n) => n.as_f64() == Some(0.0),
        _ => false,
    }
}

/// Keeper's `addField` for a JSON value.
fn add_value(fields: &mut Vec<CustomField>, name: &str, v: &Value, kind: FieldKind) {
    if !falsy(v) {
        add_field(fields, name, &field_value(v), kind);
    }
}

/// `makeArray`: an array as it is, null as nothing, anything else as one element.
fn make_array(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(items) => items.iter().collect(),
        Value::Null => Vec::new(),
        other => vec![other],
    }
}

/// `findCustomField`: the value at a `/` path, each part matching a key with its `:N` suffix
/// removed; empty when anything on the way is missing.
fn find_custom(custom: &Map<String, Value>, path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let mut map = custom;
    for (i, part) in parts.iter().enumerate() {
        let Some((_, value)) = map
            .iter()
            .find(|(key, _)| strip_instance(key.as_str()) == *part)
        else {
            return String::new();
        };
        if value.is_null() {
            return String::new();
        }
        if i + 1 == parts.len() {
            return js_string(value);
        }
        match value {
            Value::Object(next) => map = next,
            _ => return String::new(),
        }
    }
    String::new()
}

/// `deleteTopLevelCustomField`.
fn delete_top(custom: &mut Map<String, Value>, name: &str) {
    let key = custom
        .keys()
        .find(|key| strip_instance(key.as_str()) == name)
        .cloned();
    if let Some(key) = key {
        custom.remove(key.as_str());
    }
}

/// A date Keeper keeps as epoch milliseconds, as `yyyy-mm-dd`.
fn ms_text(s: &str) -> Option<String> {
    s.trim().parse::<i64>().ok().and_then(ymd_from_ms)
}

/// The text of a member that may be a string or a number.
fn member(v: &Value, key: &str) -> String {
    scalar_text(&v[key]).unwrap_or_default()
}

/// How a `date` custom field is shown: `yyyy-mm-dd` for epoch milliseconds or an ISO time; empty
/// when it is neither.
fn date_text(v: &Value) -> String {
    let ms = match v {
        Value::Number(_) => as_int(v),
        Value::String(s) => s.trim().parse::<i64>().ok().or_else(|| parse_iso_ms(s)),
        _ => None,
    };
    ms.and_then(ymd_from_ms).unwrap_or_default()
}

impl Draft {
    fn new() -> Draft {
        Draft {
            kind: Kind::Login,
            name: None,
            notes: None,
            username: None,
            password: None,
            uris: Vec::new(),
            totp: None,
            codes: Vec::new(),
            fields: Vec::new(),
            card: Card::default(),
            identity: Identity::default(),
            ssh: SshKey::default(),
            folder: None,
            spaces: Vec::new(),
            modified_ms: None,
            uid: None,
            references: Vec::new(),
        }
    }

    /// `copyLoginPropertiesAsCustomFields`: the login's own fields move to custom fields.
    fn copy_login_properties(&mut self) {
        if let Some(username) = self.username.take()
            && !is_blank(&username)
        {
            add_field(&mut self.fields, "Username", &username, FieldKind::Text);
        }
        if let Some(password) = self.password.take()
            && !is_blank(&password)
        {
            add_field(&mut self.fields, "Password", &password, FieldKind::Hidden);
        }
        for uri in std::mem::take(&mut self.uris) {
            add_field(&mut self.fields, "URL", &uri.uri, FieldKind::Text);
        }
    }

    /// A passphrase, kept as a hidden field before the password would be copied as "Password".
    fn keep_passphrase(&mut self) {
        if let Some(passphrase) = self.password.take()
            && !is_blank(&passphrase)
        {
            add_field(
                &mut self.fields,
                "Passphrase",
                &passphrase,
                FieldKind::Hidden,
            );
        }
    }

    /// `importIdentityName`.
    fn import_name(&mut self, custom: &mut Map<String, Value>) {
        self.identity.given_name = nb(&find_custom(custom, "$name/first"));
        self.identity.middle_name = nb(&find_custom(custom, "$name/middle"));
        self.identity.family_name = nb(&find_custom(custom, "$name/last"));
        delete_top(custom, "$name");
    }

    /// A date held as epoch milliseconds at `$key`, removed from the custom fields when it reads.
    fn take_date(custom: &mut Map<String, Value>, key: &str) -> Option<String> {
        let date = ms_text(&find_custom(custom, key))?;
        delete_top(custom, key);
        Some(date)
    }
}

fn import_bank_card(d: &mut Draft, custom: &mut Map<String, Value>) {
    d.kind = Kind::Card;
    d.card.cardholder = nb(&find_custom(custom, "$text:cardholderName"));
    d.card.number = card_number(&find_custom(custom, "$paymentCard/cardNumber"));
    d.card.brand = d.card.number.as_deref().and_then(card_brand);
    d.card.code = nb(&find_custom(custom, "$paymentCard/cardSecurityCode"));
    let expiry = find_custom(custom, "$paymentCard/cardExpirationDate");
    if !expiry.is_empty() {
        let parts: Vec<&str> = expiry.split('/').collect();
        if parts.len() == 2
            && let (Some(month), Some(year)) = (parse_month(parts[0]), parse_year(parts[1]))
        {
            d.card.exp_month = Some(month);
            d.card.exp_year = Some(year);
        } else {
            add_field(&mut d.fields, "Expiration date", &expiry, FieldKind::Text);
        }
    }
    d.card.pin = nb(&find_custom(custom, "$pinCode"));
    d.copy_login_properties();
    delete_top(custom, "$paymentCard");
    delete_top(custom, "$text:cardholderName");
    delete_top(custom, "$pinCode");
}

/// An identity with one document: the number at `number_key`, the dates Keeper gives.
fn import_document(
    d: &mut Draft,
    custom: &mut Map<String, Value>,
    kind: DocumentKind,
    number_key: &str,
    with_issue_date: bool,
) {
    d.kind = Kind::Identity;
    let mut document = IdDocument {
        kind,
        number: nb(&find_custom(custom, number_key)),
        ..IdDocument::default()
    };
    d.import_name(custom);
    if kind != DocumentKind::TaxNumber {
        if let Some(date) = Draft::take_date(custom, "$birthDate") {
            d.identity.birth_date = Some(date);
        }
        if let Some(date) = Draft::take_date(custom, "$expirationDate") {
            document.expires_on = Some(date);
        }
        if with_issue_date && let Some(date) = Draft::take_date(custom, "$date:dateIssued") {
            document.issued_on = Some(date);
        }
    }
    if document.number.is_some() || document.expires_on.is_some() || document.issued_on.is_some() {
        d.identity.documents.push(document);
    }
    d.copy_login_properties();
    delete_top(custom, number_key);
}

fn import_ssh_keys(d: &mut Draft, custom: &mut Map<String, Value>) {
    let private_key = find_custom(custom, "$keyPair/privateKey");
    if is_blank(&private_key) {
        // Without a key there is nothing to keep as one: a note, with the passphrase kept.
        d.kind = Kind::Note;
        d.keep_passphrase();
        d.copy_login_properties();
        return;
    }
    d.kind = Kind::SshKey;
    d.ssh.private_key = private_key;
    d.ssh.public_key = nb(&find_custom(custom, "$keyPair/publicKey"));
    d.keep_passphrase();
    d.copy_login_properties();
    add_field(
        &mut d.fields,
        "Hostname",
        &find_custom(custom, "$host/hostName"),
        FieldKind::Text,
    );
    add_field(
        &mut d.fields,
        "Port",
        &find_custom(custom, "$host/port"),
        FieldKind::Text,
    );
    delete_top(custom, "$keyPair");
    delete_top(custom, "$host");
}

/// Types that carry an array of values of their own: codes and websites.
fn import_array_field(kind: &str, value: &Value, d: &mut Draft) -> bool {
    match kind {
        "oneTimeCode" => {
            let codes: Vec<String> = make_array(value)
                .into_iter()
                .map(js_string)
                .filter(|code| !is_blank(code))
                .collect();
            for code in codes {
                if d.kind == Kind::Login {
                    if d.totp.is_none() {
                        d.totp = Some(code);
                    } else {
                        add_field(&mut d.fields, "TOTP", &code, FieldKind::Hidden);
                    }
                } else {
                    d.codes.push(code);
                }
            }
            true
        }
        "url" => {
            let urls: Vec<String> = make_array(value)
                .into_iter()
                .filter_map(scalar_text)
                .collect();
            let uris = make_uris(urls.iter().map(String::as_str));
            if d.kind == Kind::Login {
                d.uris.extend(uris);
            } else {
                for uri in uris {
                    add_field(&mut d.fields, "URL", &uri.uri, FieldKind::Text);
                }
            }
            true
        }
        _ => false,
    }
}

/// Types whose value is an object that expands into several fields.
fn import_expanding_field(kind: &str, value: &Value, d: &mut Draft) -> bool {
    match kind {
        "host" => {
            add_value(
                &mut d.fields,
                "Hostname",
                &value["hostName"],
                FieldKind::Text,
            );
            add_value(&mut d.fields, "Port", &value["port"], FieldKind::Text);
        }
        "keyPair" => {
            add_value(
                &mut d.fields,
                "Public key",
                &value["publicKey"],
                FieldKind::Text,
            );
            add_value(
                &mut d.fields,
                "Private key",
                &value["privateKey"],
                FieldKind::Hidden,
            );
        }
        "securityQuestion" => {
            for entry in make_array(value) {
                add_value(
                    &mut d.fields,
                    "Security question",
                    &entry["question"],
                    FieldKind::Text,
                );
                add_value(
                    &mut d.fields,
                    "Security question answer",
                    &entry["answer"],
                    FieldKind::Hidden,
                );
            }
        }
        // An implementation detail of Keeper.
        "appFiller" => {}
        _ => return false,
    }
    true
}

fn import_single_field(kind: &str, name: &str, value: &Value, d: &mut Draft) {
    let mut text = field_value(value);
    let mut shown = FieldKind::Text;
    match kind {
        "date" | "birthDate" | "expirationDate" => text = date_text(value),
        "name" => {
            text = ["first", "middle", "last"]
                .iter()
                .map(|part| member(value, part))
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string();
        }
        "address" => {
            text = ["street1", "street2", "city", "state", "zip", "country"]
                .iter()
                .map(|part| member(value, part))
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
                .trim()
                .to_string();
        }
        "phone" => {
            let mut parts = Vec::new();
            let region = member(value, "region");
            if !region.is_empty() {
                parts.push(format!("({region})"));
            }
            let number = member(value, "number");
            if !number.is_empty() {
                parts.push(number);
            }
            let ext = member(value, "ext");
            if !ext.is_empty() {
                parts.push(format!("ext. {ext}"));
            }
            let phone_type = member(value, "type");
            if !phone_type.is_empty() {
                parts.push(format!("({phone_type})"));
            }
            text = parts.join(" ").trim().to_string();
        }
        "bankAccount" => {
            let mut parts = Vec::new();
            let other = member(value, "otherType");
            let account_type = if other.is_empty() {
                member(value, "accountType")
            } else {
                other
            };
            if !account_type.is_empty() {
                parts.push(format!("Type: {account_type}"));
            }
            let number = member(value, "accountNumber");
            if !number.is_empty() {
                parts.push(format!("Account Number: {number}"));
            }
            let routing = member(value, "routingNumber");
            if !routing.is_empty() {
                parts.push(format!("Routing Number: {routing}"));
            }
            text = parts.join(", ").trim().to_string();
        }
        "pinCode" | "secret" => shown = FieldKind::Hidden,
        _ => {}
    }
    add_field(&mut d.fields, name, &text, shown);
}

/// `importCustomFields`.
fn import_custom_fields(custom: &Map<String, Value>, d: &mut Draft) {
    for (key, value) in custom {
        let (kind, name) = parse_field_key(key);
        if import_array_field(&kind, value, d) {
            continue;
        }
        let shown_name = if !name.is_empty() {
            name
        } else if !kind.is_empty() {
            kind.clone()
        } else {
            key.clone()
        };
        for item in make_array(value) {
            if import_expanding_field(&kind, item, d) {
                continue;
            }
            import_single_field(&kind, &shown_name, item, d);
        }
    }
}

/// `sanitizeFolderName`: Keeper allows `/` in a name, which Kemlock reads as a level.
fn sanitise_folder(name: &str) -> String {
    name.replace("\\\\", "-").replace('/', "-")
}

fn read_record(record: &Value) -> Draft {
    let mut d = Draft::new();
    d.name = nonblank(jstr(record, "title"));
    d.notes = nonblank(jstr(record, "notes"));
    d.username = nonblank(jstr(record, "login"));
    d.password = nonblank(jstr(record, "password"));
    d.uris = make_uris(jstr(record, "login_url"));
    d.uid = jstr(record, "uid").map(str::to_string);
    d.modified_ms = jint(record, "last_modified").map(|t| {
        if t < 100_000_000_000 {
            t.saturating_mul(1000)
        } else {
            t
        }
    });

    let mut custom: Map<String, Value> = record
        .get("custom_fields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    match jstr(record, "$type") {
        Some("bankCard") => import_bank_card(&mut d, &mut custom),
        Some("driverLicense") => import_document(
            &mut d,
            &mut custom,
            DocumentKind::DriversLicence,
            "$accountNumber:dlNumber",
            false,
        ),
        Some("ssnCard") => import_document(
            &mut d,
            &mut custom,
            DocumentKind::TaxNumber,
            "$accountNumber:identityNumber",
            false,
        ),
        Some("passport") => import_document(
            &mut d,
            &mut custom,
            DocumentKind::Passport,
            "$accountNumber:passportNumber",
            true,
        ),
        Some("sshKeys") => import_ssh_keys(&mut d, &mut custom),
        _ => {}
    }
    import_custom_fields(&custom, &mut d);

    if let Some(uid) = &d.uid
        && let Some(references) = record.get("references").and_then(Value::as_object)
        && !uid.is_empty()
    {
        for (key, values) in references {
            let (mut field, _) = parse_field_key(key);
            // The web exporter appends "Ref" to the type names.
            if let Some(stripped) = field.strip_suffix("Ref") {
                field = stripped.to_string();
            }
            for id in make_array(values).into_iter().filter_map(scalar_text) {
                d.references.push(Reference {
                    id,
                    field: field.clone(),
                });
            }
        }
    }

    for entry in jarr(record, "folders") {
        if let Some(folder) = jstr(entry, "folder")
            && d.folder.is_none()
            && !is_blank(folder)
        {
            d.folder = Some(sanitise_folder(folder));
        }
        if let Some(shared) = jstr(entry, "shared_folder") {
            let shared = sanitise_folder(shared);
            if !is_blank(&shared) && !d.spaces.contains(&shared) {
                d.spaces.push(shared);
            }
        }
    }
    d
}

/// Adds each record's referenced fields, from the record they point at.
fn resolve_references(drafts: &mut [Draft]) {
    let index: HashMap<String, usize> = drafts
        .iter()
        .enumerate()
        .filter_map(|(i, d)| d.uid.clone().map(|uid| (uid, i)))
        .collect();
    let mut additions: Vec<(usize, String, String)> = Vec::new();
    for (i, draft) in drafts.iter().enumerate() {
        for reference in &draft.references {
            let Some(&target) = index.get(&reference.id) else {
                continue;
            };
            let found = drafts
                .get(target)
                .and_then(|t| t.fields.iter().find(|f| f.name == reference.field));
            if let Some(field) = found
                && !field.value.is_empty()
            {
                additions.push((i, reference.field.clone(), field.value.clone()));
            }
        }
    }
    for (i, name, value) in additions {
        if let Some(draft) = drafts.get_mut(i) {
            add_field(&mut draft.fields, &name, &value, FieldKind::Text);
        }
    }
}

fn push_draft(b: &mut Builder<'_>, d: Draft) {
    let mut meta = Meta {
        modified_ms: d.modified_ms,
        source_id: d.uid.clone(),
        ..Meta::default()
    };
    if let Some(folder) = &d.folder {
        meta.folder = b.folder(folder);
    }
    for shared in &d.spaces {
        if let Some(space) = b.space(shared, shared, SharedKind::SharedFolder) {
            meta.spaces.push(space);
        }
    }
    let name = clean_name(d.name.as_deref());
    let notes = clean_notes(d.notes);

    let mut kind = d.kind;
    let login = Login {
        name: name.clone(),
        uris: d.uris,
        username: d.username,
        password: d.password,
        totp: d.totp,
        notes: notes.clone(),
        fields: d.fields,
        meta: meta.clone(),
        ..Login::default()
    };
    if kind == Kind::Login && is_noteworthy_login(&login) && login.totp.is_none() {
        kind = Kind::Note;
    }
    let owner = match kind {
        Kind::Login => b.login(login),
        Kind::Note => b.note(Note {
            name: name.clone(),
            text: notes,
            fields: login.fields,
            meta,
        }),
        Kind::Card => {
            let mut card = d.card;
            card.name = name.clone();
            card.notes = notes;
            card.fields = login.fields;
            card.meta = meta;
            b.card(card)
        }
        Kind::Identity => {
            let mut identity = d.identity;
            identity.name = name.clone();
            identity.notes = notes;
            identity.fields = login.fields;
            identity.meta = meta;
            b.identity(identity)
        }
        Kind::SshKey => {
            let mut key = d.ssh;
            key.name = name.clone();
            key.notes = notes;
            key.fields = login.fields;
            key.meta = meta;
            b.ssh_key(key)
        }
    };
    if owner.is_none() {
        return;
    }
    for value in d.codes {
        b.code(Code {
            name: name.clone(),
            value,
            ..Code::default()
        });
    }
}

/// Reads a Keeper JSON export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    ctx.limits.check_input(bytes)?;
    let source = decode_text(bytes);
    let root: Value = serde_json::from_str(&source).map_err(|_| ImportError::Unsupported)?;
    let records = root
        .get("records")
        .and_then(Value::as_array)
        .ok_or(ImportError::Unsupported)?;

    let mut b = Builder::new(Format::KeeperJson, ctx.limits);
    for shared in jarr(&root, "shared_folders") {
        let path = sanitise_folder(jstr(shared, "path").unwrap_or(""));
        if !is_blank(&path) {
            b.space(&path, &path, SharedKind::SharedFolder);
        }
    }

    let mut drafts: Vec<Draft> = Vec::new();
    for (i, record) in records.iter().enumerate() {
        if drafts.len() >= ctx.limits.max_entries {
            b.note_unread(records.len() - i);
            break;
        }
        if record.is_object() {
            drafts.push(read_record(record));
        } else {
            b.skip(
                None,
                SkipReason::Malformed,
                Some("a record that is not an object"),
            );
        }
    }
    resolve_references(&mut drafts);
    for draft in drafts {
        push_draft(&mut b, draft);
    }
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const EXPORT: &str = include_str!("../tests/fixtures/keeper/export.json");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    fn field<'a>(fields: &'a [CustomField], name: &str) -> Option<&'a CustomField> {
        fields.iter().find(|f| f.name == name)
    }

    fn value<'a>(fields: &'a [CustomField], name: &str) -> Option<&'a str> {
        field(fields, name).map(|f| f.value.as_str())
    }

    #[test]
    fn counts_by_kind() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.format, Format::KeeperJson);
        assert_eq!(batch.logins.len(), 2);
        // A note, a key that was no key, and a record with only a custom field.
        assert_eq!(batch.notes.len(), 3);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.identities.len(), 3);
        assert_eq!(batch.ssh_keys.len(), 1);
        assert_eq!(batch.codes.len(), 1);
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::Malformed);
    }

    #[test]
    fn a_login_reads_its_custom_fields() {
        let batch = read(EXPORT).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example Site");
        assert_eq!(login.username.as_deref(), Some("ada@example.com"));
        assert_eq!(login.password.as_deref(), Some("pw-1"));
        assert_eq!(login.notes.as_deref(), Some("A note"));
        assert!(
            login
                .totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://totp/Example:ada")
        );
        let uris: Vec<&str> = login.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(
            uris,
            [
                "https://example.com",
                "https://staging.example.com",
                "http://staging2.example.com"
            ]
        );
        assert_eq!(value(&login.fields, "Account number"), Some("12345"));
        assert_eq!(value(&login.fields, "Renewal"), Some("2023-11-14"));
        assert_eq!(value(&login.fields, "Hostname"), Some("db.example.com"));
        assert_eq!(value(&login.fields, "Port"), Some("5432"));
        assert_eq!(
            value(&login.fields, "Security question"),
            Some("First pet?")
        );
        let answer = field(&login.fields, "Security question answer").expect("answer");
        assert_eq!(
            (answer.value.as_str(), answer.kind),
            ("Rex", FieldKind::Hidden)
        );
        let pin = field(&login.fields, "pinCode").expect("pin");
        assert_eq!((pin.value.as_str(), pin.kind), ("4321", FieldKind::Hidden));
        assert_eq!(login.meta.modified_ms, Some(1_600_000_000_000));
        assert_eq!(login.meta.source_id.as_deref(), Some("u1"));
    }

    #[test]
    fn folders_and_shared_folders() {
        let batch = read(EXPORT).expect("batch");
        let paths: Vec<&str> = batch.folders.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["Personal", "Personal/Sites"]);
        assert_eq!(batch.spaces.len(), 1);
        assert_eq!(batch.spaces[0].name, "Team\\Ops");
        assert_eq!(batch.spaces[0].kind, SharedKind::SharedFolder);
        let login = &batch.logins[0];
        assert_eq!(login.meta.folder, Some(1));
        assert_eq!(login.meta.spaces, [0]);
        assert_eq!(batch.logins[1].meta.folder, None);
    }

    #[test]
    fn a_bank_card_is_a_card_and_its_code_a_code() {
        let batch = read(EXPORT).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.name, "Visa");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert_eq!(card.pin.as_deref(), Some("9999"));
        // The record's login became fields.
        assert_eq!(value(&card.fields, "Username"), Some("u"));
        assert_eq!(
            field(&card.fields, "Password").map(|f| f.kind),
            Some(FieldKind::Hidden)
        );
        assert_eq!(batch.codes[0].name, "Visa");
        assert_eq!(batch.codes[0].value, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn identities_hold_one_document_each() {
        let batch = read(EXPORT).expect("batch");
        let licence = &batch.identities[0];
        assert_eq!(licence.name, "Licence");
        assert_eq!(licence.given_name.as_deref(), Some("Grace"));
        assert_eq!(licence.middle_name.as_deref(), Some("B"));
        assert_eq!(licence.family_name.as_deref(), Some("Hopper"));
        assert_eq!(licence.birth_date.as_deref(), Some("1990-01-01"));
        assert_eq!(licence.documents.len(), 1);
        assert_eq!(licence.documents[0].kind, DocumentKind::DriversLicence);
        assert_eq!(licence.documents[0].number.as_deref(), Some("D1234"));
        assert_eq!(
            licence.documents[0].expires_on.as_deref(),
            Some("2030-01-01")
        );
        // Used, so not left as fields.
        assert!(licence.fields.is_empty());

        let ssn = &batch.identities[1];
        assert_eq!(ssn.documents[0].kind, DocumentKind::TaxNumber);
        assert_eq!(ssn.documents[0].number.as_deref(), Some("123-45-6789"));
        assert_eq!(ssn.family_name.as_deref(), Some("Lovelace"));

        let passport = &batch.identities[2];
        assert_eq!(passport.documents[0].kind, DocumentKind::Passport);
        assert_eq!(passport.documents[0].number.as_deref(), Some("P7654321"));
        assert_eq!(
            passport.documents[0].issued_on.as_deref(),
            Some("2020-01-01")
        );
        assert_eq!(
            passport.documents[0].expires_on.as_deref(),
            Some("2030-01-01")
        );
    }

    #[test]
    fn an_ssh_key_keeps_its_passphrase_hidden() {
        let batch = read(EXPORT).expect("batch");
        let key = &batch.ssh_keys[0];
        assert_eq!(key.name, "Deploy key");
        assert!(
            key.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(
            key.public_key.as_deref(),
            Some("ssh-ed25519 AAAAFAKE deploy")
        );
        let passphrase = field(&key.fields, "Passphrase").expect("passphrase");
        assert_eq!(passphrase.value, "passphrase!");
        assert_eq!(passphrase.kind, FieldKind::Hidden);
        assert_eq!(value(&key.fields, "Username"), Some("deploy"));
        assert_eq!(value(&key.fields, "Hostname"), Some("git.example.com"));
        assert_eq!(value(&key.fields, "Port"), Some("22"));
        // The key pair is not repeated as fields.
        assert!(field(&key.fields, "Private key").is_none());
        assert!(field(&key.fields, "Password").is_none());
    }

    #[test]
    fn notes_come_from_records_with_nothing_to_sign_in_with() {
        let batch = read(EXPORT).expect("batch");
        let names: Vec<&str> = batch.notes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["Broken key", "Just a note", "Office"]);
        let broken = &batch.notes[0];
        assert_eq!(value(&broken.fields, "Passphrase"), Some("pp"));
        assert_eq!(batch.notes[1].text.as_deref(), Some("hello"));
    }

    #[test]
    fn references_copy_a_field_of_another_record() {
        let batch = read(EXPORT).expect("batch");
        let server = &batch.logins[1];
        assert_eq!(server.name, "Server login");
        assert_eq!(
            value(&server.fields, "address"),
            Some("1 Main St, Springfield")
        );
        assert_eq!(
            value(&batch.notes[2].fields, "address"),
            Some("1 Main St, Springfield")
        );
    }

    #[test]
    fn references_in_a_loop_do_not_hang() {
        let text = r#"{"records":[
            {"uid":"a","title":"A","login":"x","references":{"$addressRef::1":["b","a"]}},
            {"uid":"b","title":"B","login":"y","references":{"$addressRef::1":["a"]},
             "custom_fields":{"$address:address:1":{"street1":"S"}}}]}"#;
        let batch = read(text).expect("batch");
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(value(&batch.logins[0].fields, "address"), Some("S"));
    }

    #[test]
    fn field_keys() {
        assert_eq!(
            parse_field_key("$url:Staging:1"),
            ("url".into(), "Staging".into())
        );
        assert_eq!(
            parse_field_key("$oneTimeCode::1"),
            ("oneTimeCode".into(), String::new())
        );
        assert_eq!(parse_field_key("$text"), ("text".into(), String::new()));
        assert_eq!(parse_field_key("Plain"), (String::new(), "Plain".into()));
        assert_eq!(parse_field_key("Plain:3"), (String::new(), "Plain".into()));
        assert_eq!(parse_field_key("  "), (String::new(), String::new()));
        assert_eq!(parse_field_key("$"), (String::new(), String::new()));
        assert_eq!(parse_field_key("$:x"), (String::new(), "x".into()));
        assert_eq!(strip_instance("a::1"), "a");
        assert_eq!(strip_instance("a:1"), "a");
        assert_eq!(strip_instance("a:12"), "a:12");
        assert_eq!(strip_instance("a"), "a");
        assert_eq!(sanitise_folder("a/b\\\\c"), "a-b-c");
        assert_eq!(sanitise_folder("a\\b"), "a\\b");
    }

    #[test]
    fn find_custom_walks_paths() {
        let custom: Map<String, Value> = serde_json::from_str(
            r#"{"$paymentCard:1":{"cardNumber":"4111","n":5,"z":null},"list":[1,2],"flag":false}"#,
        )
        .expect("map");
        assert_eq!(find_custom(&custom, "$paymentCard/cardNumber"), "4111");
        assert_eq!(find_custom(&custom, "$paymentCard/n"), "5");
        assert_eq!(find_custom(&custom, "$paymentCard/z"), "");
        assert_eq!(find_custom(&custom, "$paymentCard/missing"), "");
        assert_eq!(find_custom(&custom, "missing"), "");
        assert_eq!(find_custom(&custom, "list"), "1,2");
        assert_eq!(find_custom(&custom, "flag"), "false");
        assert_eq!(find_custom(&custom, "list/x"), "");
        assert!(js_string(&serde_json::json!({})).contains("object"));
    }

    #[test]
    fn entries_over_the_limit_are_counted() {
        let limits = Limits {
            max_entries: 3,
            ..Limits::default()
        };
        let batch = parse(EXPORT.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 3);
        assert!(batch.skipped_count() >= 1);
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("not json").err(), Some(ImportError::Unsupported));
        assert_eq!(read("{}").err(), Some(ImportError::Unsupported));
        assert_eq!(read("{\"records\":[]}").err(), Some(ImportError::Empty));
        let deep = format!("{}1{}", "[".repeat(300), "]".repeat(300));
        assert_eq!(read(&deep).err(), Some(ImportError::Unsupported));
    }

    #[test]
    fn damaged_records_do_not_panic() {
        for text in [
            r#"{"records":[{"title":"x","custom_fields":{"$":1,"":2,"$:":3,"$a:b:c:d":[null],"$url:u:1":5,"$host:h:1":"s"}}]}"#,
            r#"{"records":[{"$type":"bankCard","custom_fields":{"$paymentCard:1":"text","$pinCode":[1]}}]}"#,
            r#"{"records":[{"$type":"passport","custom_fields":{"$birthDate:1":"x","$name:1":5}}]}"#,
            r#"{"records":[{"$type":"sshKeys","custom_fields":{"$keyPair:1":{"privateKey":5}}}]}"#,
            r#"{"records":[{"title":5,"login":[],"folders":[1,{"folder":5}],"references":{"x":1},"uid":"u"},null,[],"s"]}"#,
            r#"{"records":[{"custom_fields":{"$date:d:1":"not a date","$phone:p:1":{"number":1},"$bankAccount:b:1":[]}}]}"#,
            r#"{"records":[{"last_modified":9223372036854775807}]}"#,
        ] {
            let _ = read(text);
        }
    }
}
