// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/onepassword/onepassword-1pux-importer.ts and
//   libs/importer/src/importers/onepassword/types/onepassword-1pux-importer-types.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! 1Password 1PUX: a ZIP of `export.attributes`, `export.data` (JSON: accounts, vaults, items) and
//! `files/`.
//!
//! Bitwarden reads the first account only; this reads every account and vault. A vault whose type
//! is not `P` (personal) is a shared vault, and its items name it in [`Meta::spaces`]. Items map to
//! Kemlock's kinds: logins, cards, notes, identities (a passport, driver's licence or social
//! security number also becomes an identity document), SSH keys and codes, and a document or file
//! field becomes a file. A bank account is a note: it has no card number, and a card without one
//! isn't a card.
//!
//! Where Bitwarden loses data, this keeps it: the Bitwarden note replaces the text that long fields
//! spill into, here the two are joined; a field holding an object (an address, a file) is turned
//! into text or a file, not `[object Object]`; the second one-time password becomes a code.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::builder::Builder;
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::model::{
    Address, Card, Code, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity,
    ImportBatch, ItemRef, Login, Meta, Note, PreviousPassword, SharedKind, SkipReason, SshKey,
};
use crate::util::{
    as_int, card_brand, card_number, civil_from_days, clean_name, clean_notes, days_from_civil,
    full_name, is_blank, is_noteworthy_login, jarr, jint, jstr, kvp, make_uris, nonblank,
    parse_iso_ms, parse_month, parse_year, split_newlines, ymd_from_ms,
};
use crate::zip::{Zip, looks_like_zip};

const LOGIN: &str = "001";
const CREDIT_CARD: &str = "002";
const SECURE_NOTE: &str = "003";
const IDENTITY: &str = "004";
const PASSWORD: &str = "005";
const DOCUMENT: &str = "006";
const SOFTWARE_LICENSE: &str = "100";
const BANK_ACCOUNT: &str = "101";
const DATABASE: &str = "102";
const DRIVERS_LICENSE: &str = "103";
const OUTDOOR_LICENSE: &str = "104";
const MEMBERSHIP: &str = "105";
const PASSPORT: &str = "106";
const REWARDS_PROGRAM: &str = "107";
const SOCIAL_SECURITY_NUMBER: &str = "108";
const WIRELESS_ROUTER: &str = "109";
const SERVER: &str = "110";
const EMAIL_ACCOUNT: &str = "111";
const API_CREDENTIAL: &str = "112";
const MEDICAL_RECORD: &str = "113";
const SSH_KEY: &str = "114";

/// Password history kept, as Bitwarden keeps it.
const HISTORY_KEPT: usize = 5;

static NULL: Value = Value::Null;

/// What an item becomes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Card,
    Note,
    Identity,
    Ssh,
}

fn kind_of(category: &str) -> Option<Kind> {
    Some(match category {
        LOGIN | DATABASE | PASSWORD | WIRELESS_ROUTER | SERVER | API_CREDENTIAL => Kind::Login,
        CREDIT_CARD => Kind::Card,
        SECURE_NOTE | SOFTWARE_LICENSE | EMAIL_ACCOUNT | MEDICAL_RECORD | DOCUMENT
        | BANK_ACCOUNT => Kind::Note,
        IDENTITY
        | OUTDOOR_LICENSE
        | MEMBERSHIP
        | REWARDS_PROGRAM
        | PASSPORT
        | DRIVERS_LICENSE
        | SOCIAL_SECURITY_NUMBER => Kind::Identity,
        SSH_KEY => Kind::Ssh,
        _ => return None,
    })
}

/// Everything read from an item before it is made into one of Kemlock's kinds.
struct Draft {
    kind: Kind,
    category: String,
    login: Login,
    card: Card,
    identity: Identity,
    ssh: SshKey,
    ssh_key_found: bool,
    doc: IdDocument,
    address: Address,
    notes: Option<String>,
    fields: Vec<CustomField>,
    history: Vec<PreviousPassword>,
    codes: Vec<String>,
    attachments: Vec<(String, String)>,
    /// The document ids in `attachments`, so a hostile list of files stays linear.
    attachment_ids: HashSet<String>,
}

/// One field of a section, with its value's key and the value under it.
struct FieldView<'a> {
    id: &'a str,
    title: &'a str,
    section: &'a str,
    key: &'a str,
    value: &'a Value,
}

fn sub<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

fn blank_opt(o: &Option<String>) -> bool {
    o.as_deref().is_none_or(is_blank)
}

fn blank_uri(login: &Login) -> bool {
    login.uris.first().is_none_or(|u| is_blank(&u.uri))
}

/// The title of the field, else its section's, else nothing.
fn field_name<'a>(title: &'a str, section: &'a str) -> &'a str {
    if !is_blank(title) {
        title
    } else if !is_blank(section) {
        section
    } else {
        ""
    }
}

/// JavaScript's `Date.toUTCString()` for epoch seconds: `Wed, 02 Dec 2020 04:01:00 GMT`.
pub fn utc_string(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = (days + 4).rem_euclid(7) as usize;
    let month_name = MONTHS.get((month - 1) as usize).copied().unwrap_or("Jan");
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS.get(weekday).copied().unwrap_or("Sun"),
        day,
        month_name,
        year,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `capitalize`: the first letter of each run of non-space characters that starts with a word
/// character, upper case.
fn capitalise(text: &str) -> String {
    let mut out = String::new();
    let mut in_word = false;
    for c in text.trim().chars() {
        if c.is_whitespace() {
            in_word = false;
            out.push(c);
        } else if !in_word && (c.is_ascii_alphanumeric() || c == '_') {
            in_word = true;
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn last_day(year: i64, month: i64) -> String {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let (y, m, d) = civil_from_days(days_from_civil(next_year, next_month, 1) - 1);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A field's date as `yyyy-mm-dd`: a `date` (epoch seconds), a `monthYear` (`yyyymm`, the last day
/// of the month when `end`, else the first) or text that reads as a date.
fn date_of(f: &FieldView<'_>, text: &str, end: bool) -> Option<String> {
    match f.key {
        "date" => as_int(f.value)
            .and_then(|secs| secs.checked_mul(1000))
            .and_then(ymd_from_ms),
        "monthYear" => {
            let n = as_int(f.value)?;
            let (year, month) = (n / 100, n % 100);
            if !(1..=12).contains(&month) || !(0..=9999).contains(&year) {
                return None;
            }
            Some(if end {
                last_day(year, month)
            } else {
                format!("{year:04}-{month:02}-01")
            })
        }
        _ => parse_iso_ms(text).and_then(ymd_from_ms),
    }
}

/// `extractValue`, for the value kinds an item holds. `None` for what has no text (a file, an SSH
/// key) or is empty.
fn value_text(key: &str, v: &Value) -> Option<String> {
    match key {
        "date" => as_int(v).map(utc_string),
        "monthYear" => as_int(v).map(|n| n.to_string()),
        "email" => jstr(v, "email_address").map(str::to_string),
        "address" => {
            let parts: Vec<&str> = ["street", "city", "state", "zip", "country"]
                .iter()
                .filter_map(|k| jstr(v, k))
                .filter(|s| !is_blank(s))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        "file" | "sshKey" => None,
        _ => match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        },
    }
}

impl Draft {
    fn new(kind: Kind, category: &str) -> Draft {
        Draft {
            kind,
            category: category.to_string(),
            login: Login::default(),
            card: Card::default(),
            identity: Identity::default(),
            ssh: SshKey::default(),
            ssh_key_found: false,
            doc: IdDocument::default(),
            address: Address::default(),
            notes: None,
            fields: Vec::new(),
            history: Vec::new(),
            codes: Vec::new(),
            attachments: Vec::new(),
            attachment_ids: HashSet::new(),
        }
    }

    fn add_attachment(&mut self, document_id: &str, file_name: &str) {
        if document_id.is_empty() || !self.attachment_ids.insert(document_id.to_string()) {
            return;
        }
        self.attachments
            .push((document_id.to_string(), file_name.to_string()));
    }
}

// ---------------------------------------------------------------------------------------------
// Reading an item
// ---------------------------------------------------------------------------------------------

fn read_overview_urls(d: &mut Draft, overview: &Value) {
    if d.kind != Kind::Login {
        return;
    }
    let mut urls: Vec<&str> = jarr(overview, "urls")
        .iter()
        .filter_map(|u| jstr(u, "url"))
        .filter(|u| !is_blank(u))
        .collect();
    if urls.is_empty()
        && let Some(url) = jstr(overview, "url")
    {
        urls.push(url);
    }
    d.login.uris = make_uris(urls);
}

fn read_login_fields(d: &mut Draft, details: &Value) {
    for entry in jarr(details, "loginFields") {
        if !entry.is_object() {
            continue;
        }
        let value = jstr(entry, "value")
            .map(str::to_string)
            .or_else(|| match entry.get("value") {
                Some(Value::Number(n)) => Some(n.to_string()),
                Some(Value::Bool(b)) => Some(b.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        let designation = jstr(entry, "designation");
        if d.kind == Kind::Login && !value.is_empty() {
            if designation == Some("username") {
                d.login.username = Some(value);
                continue;
            }
            if designation == Some("password") {
                d.login.password = Some(value);
                continue;
            }
        }
        let name = jstr(entry, "name").unwrap_or("");
        let (value, kind) = match jstr(entry, "fieldType") {
            Some("P") => (value, FieldKind::Hidden),
            Some("C") => (
                (if value.is_empty() { "false" } else { "true" }).to_string(),
                FieldKind::Boolean,
            ),
            _ => (value, FieldKind::Text),
        };
        kvp(&mut d.fields, &mut d.notes, name, &value, kind);
    }
}

fn read_history(d: &mut Draft, details: &Value) {
    let mut history: Vec<(i64, String)> = jarr(details, "passwordHistory")
        .iter()
        .filter_map(|entry| {
            let password = jstr(entry, "value").filter(|p| !is_blank(p))?;
            let time = jint(entry, "time")?;
            // Thirteen digits or more is milliseconds, fewer is seconds.
            let ms = if time.to_string().len() >= 13 {
                time
            } else {
                time.checked_mul(1000)?
            };
            Some((ms, password.to_string()))
        })
        .collect();
    // Newest first; the sort is stable.
    history.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    history.truncate(HISTORY_KEPT);
    d.history = history
        .into_iter()
        .map(|(until_ms, password)| PreviousPassword { password, until_ms })
        .collect();
}

fn read_sections(d: &mut Draft, details: &Value) {
    for section in jarr(details, "sections") {
        if !section.is_object() {
            continue;
        }
        let section_title = jstr(section, "title").unwrap_or("");
        for field in jarr(section, "fields") {
            let Some((key, inner)) = field
                .get("value")
                .and_then(Value::as_object)
                .and_then(|map| map.iter().next())
            else {
                continue;
            };
            if inner.is_null() || inner.as_str() == Some("") {
                continue;
            }
            let Some(text) = value_text(key, inner) else {
                // A file or an SSH key has no text but is still read.
                if key == "file" || key == "sshKey" {
                    let view = FieldView {
                        id: jstr(field, "id").unwrap_or(""),
                        title: jstr(field, "title").unwrap_or(""),
                        section: section_title,
                        key,
                        value: inner,
                    };
                    read_field(d, &view, "");
                }
                continue;
            };
            let view = FieldView {
                id: jstr(field, "id").unwrap_or(""),
                title: jstr(field, "title").unwrap_or(""),
                section: section_title,
                key,
                value: inner,
            };
            read_field(d, &view, &text);
        }
    }
}

fn read_field(d: &mut Draft, f: &FieldView<'_>, text: &str) {
    if f.key == "file" {
        if let Some(id) = jstr(f.value, "documentId") {
            d.add_attachment(id, jstr(f.value, "fileName").unwrap_or(""));
        }
        return;
    }
    if f.key == "sshKey" && d.kind != Kind::Ssh {
        return;
    }
    let handled = match d.kind {
        Kind::Login => fill_login(d, f, text),
        Kind::Card => fill_card(d, f, text),
        Kind::Identity => fill_identity(d, f, text),
        Kind::Ssh => fill_ssh(d, f),
        Kind::Note => false,
    };
    if !handled {
        read_other_field(d, f, text);
    }
}

fn fill_login(d: &mut Draft, f: &FieldView<'_>, text: &str) -> bool {
    if blank_opt(&d.login.username) && f.title == "username" {
        d.login.username = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.login.password) && f.title == "password" {
        d.login.password = Some(text.to_string());
        return true;
    }
    if f.key == "totp" || f.id.starts_with("TOTP_") {
        if blank_opt(&d.login.totp) {
            d.login.totp = Some(text.to_string());
        } else {
            d.codes.push(text.to_string());
        }
        return true;
    }
    match d.category.as_str() {
        SERVER => {
            if blank_uri(&d.login) && f.id == "url" {
                d.login.uris = make_uris([text]);
                return true;
            }
        }
        API_CREDENTIAL => {
            if blank_opt(&d.login.password) && f.title == "credential" {
                d.login.password = Some(text.to_string());
                return true;
            }
            if blank_uri(&d.login) && f.title == "hostname" {
                d.login.uris = make_uris([text]);
                return true;
            }
        }
        _ => {}
    }
    false
}

fn fill_card(d: &mut Draft, f: &FieldView<'_>, text: &str) -> bool {
    match f.id {
        "ccnum" if d.card.number.is_none() => {
            let number = card_number(text);
            d.card.brand = number.as_deref().and_then(card_brand);
            d.card.number = number;
            true
        }
        "cvv" if d.card.code.is_none() => {
            d.card.code = Some(text.to_string());
            true
        }
        "cardholder" if d.card.cardholder.is_none() => {
            d.card.cardholder = Some(text.to_string());
            true
        }
        "pin" if d.card.pin.is_none() => {
            d.card.pin = Some(text.to_string());
            true
        }
        "expiry" if d.card.exp_year.is_none() => {
            // `yyyymm`
            let t = text.trim();
            d.card.exp_month = t.get(4..6).and_then(parse_month);
            d.card.exp_year = t.get(0..4).and_then(parse_year);
            d.card.exp_year.is_some() || d.card.exp_month.is_some()
        }
        "validFrom" if d.card.valid_from_year.is_none() => {
            let t = text.trim();
            d.card.valid_from_month = t.get(4..6).and_then(parse_month);
            d.card.valid_from_year = t.get(0..4).and_then(parse_year);
            d.card.valid_from_year.is_some() || d.card.valid_from_month.is_some()
        }
        // The brand comes from the number.
        "type" => true,
        _ => false,
    }
}

/// Sets a name from `Given Middle Last`, for whichever parts are found.
fn set_full_name(identity: &mut Identity, text: &str) {
    let (first, middle, last) = full_name(text);
    if first.is_some() {
        identity.given_name = first;
    }
    if middle.is_some() {
        identity.middle_name = middle;
    }
    if last.is_some() {
        identity.family_name = last;
    }
}

fn fill_identity(d: &mut Draft, f: &FieldView<'_>, text: &str) -> bool {
    if blank_opt(&d.identity.given_name) && f.id == "firstname" {
        d.identity.given_name = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.identity.family_name) && f.id == "lastname" {
        d.identity.family_name = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.identity.middle_name) && f.id == "initial" {
        d.identity.middle_name = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.identity.phone) && f.id == "defphone" {
        d.identity.phone = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.identity.company) && f.id == "company" {
        d.identity.company = Some(text.to_string());
        return true;
    }
    if blank_opt(&d.identity.email) {
        if f.key == "email" {
            d.identity.email = nonblank(Some(text));
            kvp(
                &mut d.fields,
                &mut d.notes,
                "provider",
                jstr(f.value, "provider").unwrap_or(""),
                FieldKind::Text,
            );
            return true;
        }
        if f.id == "email" {
            d.identity.email = Some(text.to_string());
            return true;
        }
    }
    if blank_opt(&d.identity.username) && f.id == "username" {
        d.identity.username = Some(text.to_string());
        return true;
    }
    if f.key == "address" {
        let street = jstr(f.value, "street").unwrap_or("");
        if !is_blank(street) {
            d.address.lines.push(street.to_string());
        }
        d.address.city = nonblank(jstr(f.value, "city"));
        d.address.country = nonblank(jstr(f.value, "country")).map(|c| c.to_uppercase());
        d.address.postal_code = nonblank(jstr(f.value, "zip"));
        d.address.region = nonblank(jstr(f.value, "state"));
        return true;
    }
    fill_identity_category(d, f, text)
}

fn fill_identity_category(d: &mut Draft, f: &FieldView<'_>, text: &str) -> bool {
    let no_name = blank_opt(&d.identity.given_name);
    match d.category.as_str() {
        DRIVERS_LICENSE => {
            if no_name && f.id == "fullname" {
                set_full_name(&mut d.identity, text);
                return true;
            }
            match f.id {
                "number" if d.doc.number.is_none() => d.doc.number = Some(text.to_string()),
                "country" if d.doc.issuing_country.is_none() => {
                    d.doc.issuing_country = Some(text.to_string());
                }
                "state" if d.doc.issuing_authority.is_none() => {
                    d.doc.issuing_authority = Some(text.to_string());
                }
                "address" if d.address.lines.is_empty() => d.address.lines.push(text.to_string()),
                "birthdate" if d.identity.birth_date.is_none() => {
                    let Some(date) = date_of(f, text, false) else {
                        return false;
                    };
                    d.identity.birth_date = Some(date);
                }
                "expiry_date" if d.doc.expires_on.is_none() => {
                    let Some(date) = date_of(f, text, true) else {
                        return false;
                    };
                    d.doc.expires_on = Some(date);
                }
                _ => return false,
            }
            true
        }
        OUTDOOR_LICENSE => {
            if no_name && f.id == "name" {
                set_full_name(&mut d.identity, text);
                true
            } else if d.address.country.is_none() && f.id == "country" {
                d.address.country = Some(text.to_string());
                true
            } else if d.address.region.is_none() && f.id == "state" {
                d.address.region = Some(text.to_string());
                true
            } else {
                false
            }
        }
        MEMBERSHIP => {
            if no_name && f.id == "member_name" {
                set_full_name(&mut d.identity, text);
                true
            } else if blank_opt(&d.identity.company) && f.id == "org_name" {
                d.identity.company = Some(text.to_string());
                true
            } else if blank_opt(&d.identity.phone) && f.id == "phone" {
                d.identity.phone = Some(text.to_string());
                true
            } else {
                false
            }
        }
        PASSPORT => {
            if no_name && f.id == "fullname" {
                set_full_name(&mut d.identity, text);
                return true;
            }
            match f.id {
                "issuing_country" if d.doc.issuing_country.is_none() => {
                    d.doc.issuing_country = Some(text.to_string());
                }
                "number" if d.doc.number.is_none() => d.doc.number = Some(text.to_string()),
                "issuing_authority" if d.doc.issuing_authority.is_none() => {
                    d.doc.issuing_authority = Some(text.to_string());
                }
                "birthdate" if d.identity.birth_date.is_none() => {
                    let Some(date) = date_of(f, text, false) else {
                        return false;
                    };
                    d.identity.birth_date = Some(date);
                }
                "issue_date" if d.doc.issued_on.is_none() => {
                    let Some(date) = date_of(f, text, false) else {
                        return false;
                    };
                    d.doc.issued_on = Some(date);
                }
                "expiry_date" if d.doc.expires_on.is_none() => {
                    let Some(date) = date_of(f, text, true) else {
                        return false;
                    };
                    d.doc.expires_on = Some(date);
                }
                _ => return false,
            }
            true
        }
        REWARDS_PROGRAM => {
            if no_name && f.id == "member_name" {
                set_full_name(&mut d.identity, text);
                true
            } else if blank_opt(&d.identity.company) && f.id == "company_name" {
                d.identity.company = Some(text.to_string());
                true
            } else {
                false
            }
        }
        SOCIAL_SECURITY_NUMBER => {
            if no_name && f.id == "name" {
                set_full_name(&mut d.identity, text);
                true
            } else if d.doc.number.is_none() && f.id == "number" {
                d.doc.number = Some(text.to_string());
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn fill_ssh(d: &mut Draft, f: &FieldView<'_>) -> bool {
    if f.key != "sshKey" {
        return false;
    }
    // `sshKey.metadata.privateKey`, not `sshKey.privateKey`, which has no consistent format.
    let metadata = sub(f.value, "metadata");
    if let Some(private) = jstr(metadata, "privateKey").filter(|k| !is_blank(k)) {
        d.ssh.private_key = private.to_string();
        d.ssh.public_key = nonblank(jstr(metadata, "publicKey"));
        d.ssh.fingerprint = nonblank(jstr(metadata, "fingerprint"));
        d.ssh_key_found = true;
    }
    true
}

/// A field no kind took: a custom field, a note line, a code.
fn read_other_field(d: &mut Draft, f: &FieldView<'_>, text: &str) {
    let name = field_name(f.title, f.section);
    if f.key == "email" {
        kvp(&mut d.fields, &mut d.notes, name, text, FieldKind::Text);
        kvp(
            &mut d.fields,
            &mut d.notes,
            "provider",
            jstr(f.value, "provider").unwrap_or(""),
            FieldKind::Text,
        );
        return;
    }
    // Do not include a password field that is already in the history.
    if f.title == "password" && d.history.iter().any(|h| h.password == text) {
        return;
    }
    if f.key == "totp" || f.id.starts_with("TOTP_") {
        d.codes.push(text.to_string());
        return;
    }
    let bank_secret = d.category == BANK_ACCOUNT
        && ["accountNo", "iban", "telephonePin", "routingNo"].contains(&f.id);
    let kind = if f.key == "concealed" || bank_secret {
        FieldKind::Hidden
    } else {
        FieldKind::Text
    };
    kvp(&mut d.fields, &mut d.notes, name, text, kind);
}

// ---------------------------------------------------------------------------------------------
// Making Kemlock items
// ---------------------------------------------------------------------------------------------

enum Built {
    Login(Login),
    Card(Card),
    Note(Note),
    Identity(Box<Identity>),
    Ssh(SshKey),
    Nothing,
}

/// The note, with the lines long fields spilled into it after it.
fn join_notes(plain: Option<String>, spilled: Option<String>) -> Option<String> {
    let spilled = spilled
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.is_empty());
    match (plain, spilled) {
        (Some(p), Some(s)) => Some(format!("{p}\n{s}")),
        (Some(p), None) => Some(p),
        (None, s) => s,
    }
}

fn has_document(doc: &IdDocument) -> bool {
    doc.number.is_some()
        || doc.issuing_country.is_some()
        || doc.issuing_authority.is_some()
        || doc.issued_on.is_some()
        || doc.expires_on.is_some()
}

fn has_address(a: &Address) -> bool {
    !a.lines.is_empty()
        || a.city.is_some()
        || a.region.is_some()
        || a.postal_code.is_some()
        || a.country.is_some()
}

fn assemble(d: &mut Draft, name: &str, notes: Option<String>, meta: Meta) -> Built {
    match d.kind {
        Kind::Login => {
            let mut login = std::mem::take(&mut d.login);
            login.name = name.to_string();
            login.fields = std::mem::take(&mut d.fields);
            login.notes = notes;
            login.previous_passwords = std::mem::take(&mut d.history);
            login.meta = meta.clone();
            if is_noteworthy_login(&login) && login.totp.is_none() && d.codes.is_empty() {
                Built::Note(Note {
                    name: name.to_string(),
                    text: login.notes.take(),
                    fields: std::mem::take(&mut login.fields),
                    meta,
                })
            } else {
                Built::Login(login)
            }
        }
        Kind::Card => {
            let mut card = std::mem::take(&mut d.card);
            card.name = name.to_string();
            card.notes = notes;
            card.fields = std::mem::take(&mut d.fields);
            card.meta = meta;
            Built::Card(card)
        }
        Kind::Note => {
            let note = Note {
                name: name.to_string(),
                text: notes,
                fields: std::mem::take(&mut d.fields),
                meta,
            };
            // A note that is only its one-time password is the code alone.
            if note.text.is_none() && note.fields.is_empty() && !d.codes.is_empty() {
                Built::Nothing
            } else {
                Built::Note(note)
            }
        }
        Kind::Identity => {
            let mut identity = std::mem::take(&mut d.identity);
            identity.name = name.to_string();
            identity.notes = notes;
            identity.fields = std::mem::take(&mut d.fields);
            identity.meta = meta;
            let mut address = std::mem::take(&mut d.address);
            address.lines.truncate(3);
            if has_address(&address) {
                identity.address = Some(address);
            }
            let mut doc = std::mem::take(&mut d.doc);
            if has_document(&doc) {
                doc.kind = match d.category.as_str() {
                    PASSPORT => DocumentKind::Passport,
                    DRIVERS_LICENSE => DocumentKind::DriversLicence,
                    SOCIAL_SECURITY_NUMBER => DocumentKind::TaxNumber,
                    _ => DocumentKind::Other,
                };
                identity.documents.push(doc);
            }
            Built::Identity(Box::new(identity))
        }
        Kind::Ssh => {
            if !d.ssh_key_found {
                return Built::Nothing;
            }
            let mut key = std::mem::take(&mut d.ssh);
            key.name = name.to_string();
            key.notes = notes;
            key.fields = std::mem::take(&mut d.fields);
            key.meta = meta;
            Built::Ssh(key)
        }
    }
}

/// `files/<documentId>__<name>` in the archive, by document id.
fn index_files(zip: &Zip<'_>) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for (index, entry) in zip.entries().iter().enumerate() {
        if entry.is_dir() {
            continue;
        }
        let Some(rest) = entry.name.strip_prefix("files/") else {
            continue;
        };
        let id = rest.split_once("__").map_or(rest, |(id, _)| id);
        if !id.is_empty() {
            map.entry(id.to_string()).or_insert(index);
        }
    }
    map
}

fn attach(
    b: &mut Builder<'_>,
    zip: &mut Zip<'_>,
    files: &HashMap<String, usize>,
    owner: ItemRef,
    document_id: &str,
    file_name: &str,
) {
    let Some(&index) = files.get(document_id) else {
        return;
    };
    let name = if file_name.is_empty() {
        document_id
    } else {
        file_name
    };
    match zip.read(index) {
        Ok(data) => b.file(name, None, data, Some(owner)),
        Err(ImportError::LimitExceeded(_)) => b.skip(Some(name), SkipReason::FileOverLimit, None),
        Err(_) => b.skip(Some(name), SkipReason::Malformed, Some("a file in the ZIP")),
    }
}

fn process_item(
    b: &mut Builder<'_>,
    zip: &mut Zip<'_>,
    files: &HashMap<String, usize>,
    item: &Value,
    space: Option<usize>,
) {
    if b.full() {
        b.note_unread(1);
        return;
    }
    if !item.is_object() {
        b.skip(None, SkipReason::Malformed, None);
        return;
    }
    let overview = sub(item, "overview");
    let details = sub(item, "details");
    let title = jstr(overview, "title");
    if jstr(item, "state") == Some("trashed") {
        b.skip(title, SkipReason::Trashed, None);
        return;
    }
    let category = jstr(item, "categoryUuid").unwrap_or("");
    let Some(kind) = kind_of(category) else {
        let detail = if category.is_empty() {
            "no category"
        } else {
            category
        };
        b.skip(title, SkipReason::UnsupportedKind, Some(detail));
        return;
    };

    let mut d = Draft::new(kind, category);
    read_overview_urls(&mut d, overview);
    read_login_fields(&mut d, details);
    if category == PASSWORD
        && kind == Kind::Login
        && let Some(password) = jstr(details, "password")
    {
        d.login.password = Some(password.to_string());
    }
    read_history(&mut d, details);
    read_sections(&mut d, details);
    let attributes = sub(details, "documentAttributes");
    if let Some(id) = jstr(attributes, "documentId") {
        d.add_attachment(id, jstr(attributes, "fileName").unwrap_or(""));
    }
    let plain = jstr(details, "notesPlain")
        .filter(|n| !is_blank(n))
        .map(|n| split_newlines(n).join("\n").trim_end().to_string());
    let notes = clean_notes(join_notes(plain, d.notes.take()));

    // The first tag is the folder, the rest are tags.
    let tags: Vec<String> = jarr(overview, "tags")
        .iter()
        .filter_map(Value::as_str)
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let folder = tags.first().and_then(|t| b.folder(&capitalise(t)));
    let meta = Meta {
        folder,
        spaces: space.into_iter().collect(),
        favorite: jint(item, "favIndex") == Some(1),
        created_ms: jint(item, "createdAt").and_then(|s| s.checked_mul(1000)),
        modified_ms: jint(item, "updatedAt").and_then(|s| s.checked_mul(1000)),
        source_id: nonblank(jstr(item, "uuid")),
        tags: tags.get(1..).unwrap_or(&[]).to_vec(),
    };

    let name = clean_name(title);
    if kind == Kind::Ssh && !d.ssh_key_found {
        b.skip(title, SkipReason::BadKey, Some("no private key"));
        return;
    }
    let code_meta = meta.clone();
    let built = assemble(&mut d, &name, notes, meta);
    let owner = match built {
        Built::Login(v) => b.login(v),
        Built::Card(v) => b.card(v),
        Built::Note(v) => b.note(v),
        Built::Identity(v) => b.identity(*v),
        Built::Ssh(v) => b.ssh_key(v),
        Built::Nothing => None,
    };
    for value in std::mem::take(&mut d.codes) {
        b.code(Code {
            name: name.clone(),
            value,
            notes: None,
            meta: code_meta.clone(),
        });
    }
    if let Some(owner) = owner {
        for (document_id, file_name) in &d.attachments {
            attach(b, zip, files, owner, document_id, file_name);
        }
    }
}

/// Reads a 1Password 1PUX export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    ctx.limits.check_zip_input(bytes)?;
    if !looks_like_zip(bytes) {
        return Err(ImportError::Unsupported);
    }
    let mut zip = Zip::open(bytes, ctx.limits)?;
    let Some(data_index) = zip.find("export.data") else {
        return Err(ImportError::Unsupported);
    };
    let data = zip.read(data_index)?;
    let root: Value = serde_json::from_slice(&data)
        .map_err(|_| ImportError::malformed("export.data is not valid JSON"))?;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::malformed("export.data has no accounts"))?;
    let files = index_files(&zip);

    let mut b = Builder::new(Format::OnePasswordPux, ctx.limits);
    for account in accounts {
        for vault in jarr(account, "vaults") {
            let items = jarr(vault, "items");
            if items.is_empty() {
                continue;
            }
            let attrs = sub(vault, "attrs");
            let space = match jstr(attrs, "type") {
                Some(kind) if kind != "P" => {
                    let name = jstr(attrs, "name").unwrap_or("");
                    let key = jstr(attrs, "uuid")
                        .filter(|k| !k.is_empty())
                        .unwrap_or(name);
                    b.space(key, or_name(name), SharedKind::Vault)
                }
                _ => None,
            };
            for item in items {
                process_item(&mut b, &mut zip, &files, item, space);
            }
        }
    }
    b.finish()
}

fn or_name(name: &str) -> &str {
    if is_blank(name) { "Shared vault" } else { name }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::zip::build_stored_zip;

    const SAMPLE: &[u8] = include_bytes!("../tests/fixtures/onepassword/sample.1pux");

    fn run(bytes: &[u8]) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(bytes, &Context::new(&limits))
    }

    fn pux(json: &str) -> Vec<u8> {
        build_stored_zip(&[("export.data", json.as_bytes())])
    }

    fn one_item(item: &str) -> String {
        format!(
            r#"{{"accounts":[{{"attrs":{{}},"vaults":[{{"attrs":{{"uuid":"V","name":"P","type":"P"}},"items":[{item}]}}]}}]}}"#
        )
    }

    #[test]
    fn utc_strings_follow_javascript() {
        assert_eq!(utc_string(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(utc_string(86_400), "Fri, 02 Jan 1970 00:00:00 GMT");
        assert_eq!(utc_string(1_600_000_000), "Sun, 13 Sep 2020 12:26:40 GMT");
        assert_eq!(utc_string(-1), "Wed, 31 Dec 1969 23:59:59 GMT");
    }

    #[test]
    fn folder_names_are_capitalised() {
        assert_eq!(capitalise("work stuff"), "Work Stuff");
        assert_eq!(capitalise("  (home) base_1 "), "(Home) Base_1");
        assert_eq!(capitalise(""), "");
    }

    #[test]
    fn the_sample_has_the_expected_shape() {
        let batch = run(SAMPLE).expect("batch");
        assert_eq!(batch.format, Format::OnePasswordPux);
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.identities.len(), 2);
        assert_eq!(batch.ssh_keys.len(), 1);
        assert_eq!(batch.notes.len(), 3);
        assert_eq!(batch.codes.len(), 1);
        assert_eq!(batch.files.len(), 1);
        assert_eq!(batch.skipped.len(), 2);
        assert_eq!(batch.spaces.len(), 1);
        assert_eq!(batch.spaces[0].name, "Family");
    }

    #[test]
    fn a_login_keeps_every_url_its_history_its_code_and_its_folder() {
        let batch = run(SAMPLE).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example Login");
        let uris: Vec<&str> = login.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(
            uris,
            ["https://example.com", "https://alt.example.com/login"]
        );
        assert_eq!(login.username.as_deref(), Some("ada"));
        assert_eq!(login.password.as_deref(), Some("pw-current"));
        assert!(
            login
                .totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://totp/Example:ada")
        );
        let history: Vec<(&str, i64)> = login
            .previous_passwords
            .iter()
            .map(|p| (p.password.as_str(), p.until_ms))
            .collect();
        assert_eq!(
            history,
            [
                ("pw-old-2", 1_550_000_000_000),
                ("pw-old-1", 1_500_000_000_000),
                ("pw-older", 1_400_000_000_000)
            ]
        );
        assert_eq!(login.fields.len(), 2);
        assert_eq!(login.fields[0].name, "Remember");
        assert_eq!(login.fields[0].kind, FieldKind::Boolean);
        assert_eq!(login.fields[0].value, "true");
        assert_eq!(login.fields[1].name, "Security question");
        assert_eq!(login.fields[1].kind, FieldKind::Hidden);
        assert_eq!(
            login.notes.as_deref(),
            Some("login notes\nsecond line\nRecovery: line1\nline2")
        );
        assert!(login.meta.favorite);
        assert_eq!(login.meta.created_ms, Some(1_600_000_000_000));
        assert_eq!(login.meta.modified_ms, Some(1_600_000_500_000));
        assert_eq!(login.meta.source_id.as_deref(), Some("I1"));
        assert_eq!(login.meta.tags, ["extra"]);
        let folder = login.meta.folder.expect("folder");
        assert_eq!(batch.folders[folder].name, "Work Stuff");
        assert!(login.meta.spaces.is_empty());
    }

    #[test]
    fn a_card_has_its_parts() {
        let batch = run(SAMPLE).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.name, "Everyday Visa");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!(card.pin.as_deref(), Some("4321"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert!(card.fields.is_empty());
    }

    #[test]
    fn an_identity_has_its_address_and_keeps_the_rest_as_fields() {
        let batch = run(SAMPLE).expect("batch");
        let id = &batch.identities[0];
        assert_eq!(id.name, "Ada");
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.middle_name.as_deref(), Some("K"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.phone.as_deref(), Some("555-0100"));
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        assert_eq!(id.username.as_deref(), Some("ada99"));
        let address = id.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 Main St"]);
        assert_eq!(address.city.as_deref(), Some("London"));
        assert_eq!(address.country.as_deref(), Some("GB"));
        assert_eq!(address.postal_code.as_deref(), Some("N1 1AA"));
        assert_eq!(address.region.as_deref(), Some("Greater London"));
        let names: Vec<(&str, &str)> = id
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("birth date", "Fri, 02 Jan 1970 00:00:00 GMT"),
                ("provider", "example"),
                ("occupation", "Mathematician")
            ]
        );
        assert!(id.documents.is_empty());
    }

    #[test]
    fn a_passport_is_an_identity_with_a_document() {
        let batch = run(SAMPLE).expect("batch");
        let id = &batch.identities[1];
        assert_eq!(id.name, "Passport");
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.middle_name.as_deref(), Some("K"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.documents.len(), 1);
        let doc = &id.documents[0];
        assert_eq!(doc.kind, DocumentKind::Passport);
        assert_eq!(doc.number.as_deref(), Some("P1234567"));
        assert_eq!(doc.issuing_country.as_deref(), Some("United Kingdom"));
        assert_eq!(doc.issued_on.as_deref(), Some("2020-01-01"));
        assert_eq!(doc.expires_on.as_deref(), Some("2030-01-01"));
        assert_eq!(id.fields.len(), 1);
        assert_eq!(id.fields[0].name, "nationality");
    }

    #[test]
    fn an_ssh_key_keeps_its_parts() {
        let batch = run(SAMPLE).expect("batch");
        let key = &batch.ssh_keys[0];
        assert_eq!(key.name, "Deploy key");
        assert!(key.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(
            key.public_key.as_deref(),
            Some("ssh-ed25519 AAAAC3Nza fake")
        );
        assert_eq!(key.fingerprint.as_deref(), Some("SHA256:fakefingerprint"));
        assert_eq!(key.fields.len(), 1);
        assert_eq!(key.fields[0].name, "key type");
    }

    #[test]
    fn a_document_is_a_note_with_its_file() {
        let batch = run(SAMPLE).expect("batch");
        let scan = batch
            .notes
            .iter()
            .position(|n| n.name == "Scan")
            .expect("note");
        assert_eq!(batch.files[0].name, "scan.txt");
        assert_eq!(batch.files[0].data, b"hello world");
        let owner = batch.files[0].owner.expect("owner");
        assert_eq!(owner.kind, crate::model::ItemKind::Note);
        assert_eq!(owner.index, scan);
    }

    #[test]
    fn shared_vaults_archived_items_codes_and_skips() {
        let batch = run(SAMPLE).expect("batch");
        let shared = batch
            .logins
            .iter()
            .find(|l| l.name == "Shared Login")
            .expect("login");
        assert_eq!(shared.meta.spaces, [0]);
        let old = batch
            .notes
            .iter()
            .find(|n| n.name == "Old Note")
            .expect("archived note");
        assert_eq!(old.text.as_deref(), Some("archived text"));
        let wifi = batch
            .notes
            .iter()
            .find(|n| n.name == "Wifi note")
            .expect("note");
        assert_eq!(wifi.meta.spaces, [0]);
        assert_eq!(batch.codes[0].name, "Wifi note");
        assert!(batch.codes[0].value.starts_with("otpauth://totp/"));
        let mystery = batch
            .skipped
            .iter()
            .find(|s| s.name.as_deref() == Some("Mystery"))
            .expect("skip");
        assert_eq!(mystery.reason, SkipReason::UnsupportedKind);
        assert_eq!(mystery.detail.as_deref(), Some("999"));
        let trashed = batch
            .skipped
            .iter()
            .find(|s| s.reason == SkipReason::Trashed)
            .expect("trashed");
        assert_eq!(trashed.name.as_deref(), Some("Deleted Login"));
    }

    #[test]
    fn password_history_keeps_the_five_newest() {
        let history: Vec<String> = (1..=7)
            .map(|n| format!(r#"{{"value":"old{n}","time":{}}}"#, 1_500_000_000 + n))
            .collect();
        let item = format!(
            r#"{{"uuid":"x","categoryUuid":"001","overview":{{"title":"H"}},"details":{{"loginFields":[{{"value":"u","name":"username","designation":"username"}}],"passwordHistory":[{}]}}}}"#,
            history.join(",")
        );
        let batch = run(&pux(&one_item(&item))).expect("batch");
        let kept: Vec<&str> = batch.logins[0]
            .previous_passwords
            .iter()
            .map(|p| p.password.as_str())
            .collect();
        assert_eq!(kept, ["old7", "old6", "old5", "old4", "old3"]);
    }

    #[test]
    fn a_password_field_already_in_the_history_is_not_added_again() {
        let item = r#"{"uuid":"x","categoryUuid":"001","overview":{"title":"H"},"details":{"loginFields":[{"value":"u","name":"username","designation":"username"},{"value":"cur","name":"password","designation":"password"}],"passwordHistory":[{"value":"same","time":1500000000}],"sections":[{"title":"","fields":[{"title":"password","id":"p","value":{"concealed":"same"}}]}]}}"#;
        let batch = run(&pux(&one_item(item))).expect("batch");
        assert!(batch.logins[0].fields.is_empty());
    }

    #[test]
    fn a_login_with_nothing_to_sign_in_with_is_a_note() {
        let item = r#"{"uuid":"x","categoryUuid":"001","overview":{"title":"Just text"},"details":{"notesPlain":"hello"}}"#;
        let batch = run(&pux(&one_item(item))).expect("batch");
        assert!(batch.logins.is_empty());
        assert_eq!(batch.notes[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn a_bank_account_is_a_note_with_hidden_numbers() {
        let item = r#"{"uuid":"x","categoryUuid":"101","overview":{"title":"Bank"},"details":{"sections":[{"title":"","fields":[{"title":"bank name","id":"bankName","value":{"string":"Fake Bank"}},{"title":"account number","id":"accountNo","value":{"string":"12345678"}}]}]}}"#;
        let batch = run(&pux(&one_item(item))).expect("batch");
        let note = &batch.notes[0];
        assert_eq!(note.fields[0].kind, FieldKind::Text);
        assert_eq!(note.fields[1].name, "account number");
        assert_eq!(note.fields[1].kind, FieldKind::Hidden);
    }

    #[test]
    fn a_driving_licence_and_a_social_security_number_are_documents() {
        let licence = r#"{"uuid":"a","categoryUuid":"103","overview":{"title":"Licence"},"details":{"sections":[{"title":"","fields":[{"title":"full name","id":"fullname","value":{"string":"Ada Lovelace"}},{"title":"number","id":"number","value":{"string":"D123"}},{"title":"expiry date","id":"expiry_date","value":{"monthYear":203002}},{"title":"state","id":"state","value":{"string":"CA"}}]}]}}"#;
        let ssn = r#"{"uuid":"b","categoryUuid":"108","overview":{"title":"SSN"},"details":{"sections":[{"title":"","fields":[{"title":"number","id":"number","value":{"concealed":"000-00-0000"}}]}]}}"#;
        let batch = run(&pux(&one_item(&format!("{licence},{ssn}")))).expect("batch");
        let doc = &batch.identities[0].documents[0];
        assert_eq!(doc.kind, DocumentKind::DriversLicence);
        assert_eq!(doc.number.as_deref(), Some("D123"));
        assert_eq!(doc.expires_on.as_deref(), Some("2030-02-28"));
        assert_eq!(doc.issuing_authority.as_deref(), Some("CA"));
        assert_eq!(batch.identities[0].family_name.as_deref(), Some("Lovelace"));
        let tax = &batch.identities[1].documents[0];
        assert_eq!(tax.kind, DocumentKind::TaxNumber);
        assert_eq!(tax.number.as_deref(), Some("000-00-0000"));
    }

    #[test]
    fn an_ssh_key_item_without_a_key_is_skipped() {
        let item = r#"{"uuid":"x","categoryUuid":"114","overview":{"title":"Broken key"},"details":{"sections":[]}}"#;
        let batch = run(&pux(&one_item(item))).expect("batch");
        assert!(batch.ssh_keys.is_empty());
        assert_eq!(batch.skipped[0].reason, SkipReason::BadKey);
    }

    #[test]
    fn an_item_that_is_not_an_object_is_skipped_not_fatal() {
        let items = format!(
            r#""text",{}"#,
            r#"{"uuid":"x","categoryUuid":"003","overview":{"title":"Fine"},"details":{"notesPlain":"ok"}}"#
        );
        let batch = run(&pux(&one_item(&items))).expect("batch");
        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::Malformed);
    }

    #[test]
    fn a_file_over_the_entry_limit_is_skipped_by_name() {
        let item = r#"{"uuid":"x","categoryUuid":"006","overview":{"title":"Big"},"details":{"documentAttributes":{"fileName":"big.bin","documentId":"D1","decryptedSize":1000}}}"#;
        let json = one_item(item);
        let big = vec![7u8; 1000];
        let zip = build_stored_zip(&[
            ("export.data", json.as_bytes()),
            ("files/D1__big.bin", big.as_slice()),
        ]);
        // export.data fits the per-entry limit; the file does not.
        let limits = Limits {
            max_entry_bytes: json.len(),
            ..Limits::default()
        };
        let batch = parse(&zip, &Context::new(&limits)).expect("batch");
        assert_eq!(batch.notes.len(), 1);
        assert!(batch.files.is_empty());
        assert_eq!(batch.skipped[0].reason, SkipReason::FileOverLimit);
        assert_eq!(batch.skipped[0].name.as_deref(), Some("big.bin"));
    }

    #[test]
    fn the_entry_limit_applies() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let batch = parse(SAMPLE, &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 2);
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::OverLimit)
        );
    }

    #[test]
    fn the_zip_limits_apply() {
        let limits = Limits {
            max_zip_entries: 1,
            ..Limits::default()
        };
        assert!(matches!(
            parse(SAMPLE, &Context::new(&limits)),
            Err(ImportError::LimitExceeded(_))
        ));
        let limits = Limits {
            max_zip_bytes: 100,
            ..Limits::default()
        };
        assert!(matches!(
            parse(SAMPLE, &Context::new(&limits)),
            Err(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn refuses_what_is_not_a_1pux() {
        assert_eq!(run(b"").err(), Some(ImportError::Unsupported));
        assert_eq!(
            run(b"{\"accounts\":[]}").err(),
            Some(ImportError::Unsupported)
        );
        let no_data = build_stored_zip(&[("export.attributes", "{}".as_bytes())]);
        assert_eq!(run(&no_data).err(), Some(ImportError::Unsupported));
        assert!(matches!(
            run(&pux("not json")),
            Err(ImportError::Malformed(_))
        ));
        assert!(matches!(run(&pux("{}")), Err(ImportError::Malformed(_))));
        assert_eq!(
            run(&pux(r#"{"accounts":[]}"#)).err(),
            Some(ImportError::Empty)
        );
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for json in [
            r#"{"accounts":[null]}"#,
            r#"{"accounts":[{"vaults":[{"items":[null,1,[],{"details":5,"overview":"x"}]}]}]}"#,
            r#"{"accounts":[{"vaults":[{"attrs":{"type":"E"},"items":[{"categoryUuid":"004","details":{"sections":[null,{"fields":[null,{"value":null},{"value":{}},{"value":{"address":5}}]}]}}]}]}]}"#,
            r#"{"accounts":[{"vaults":[{"items":[{"categoryUuid":"002","details":{"sections":[{"fields":[{"id":"expiry","value":{"monthYear":"x"}},{"id":"ccnum","value":{"creditCardNumber":""}}]}]}}]}]}]}"#,
        ] {
            let _ = run(&pux(json));
        }
        let mut cut = SAMPLE.to_vec();
        cut.truncate(SAMPLE.len() / 2);
        let _ = run(&cut);
        let mut flipped = SAMPLE.to_vec();
        flipped[40] ^= 0xFF;
        let _ = run(&flipped);
    }
}
