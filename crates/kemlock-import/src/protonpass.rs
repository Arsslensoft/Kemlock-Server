// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/protonpass/protonpass-json-importer.ts,
//   protonpass-import-utils.ts and types/protonpass-json-type.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Proton Pass: the JSON export, the ZIP export (the JSON and the files), and the export encrypted
//! with a passphrase (an OpenPGP message, decrypted here with rPGP).
//!
//! [`parse`] works out which of the three it is given from the content. Bitwarden's importer reads
//! only the plain JSON; the encrypted forms and the ZIP are this crate's own.
//!
//! What maps to what: a login (or an alias, with its address as the username) to a [`Login`], a
//! note, a custom item and a Wi-Fi item to a [`Note`] whose fields hold the rest, a credit card to
//! a [`Card`], an identity to an [`Identity`] (its social security, passport and licence numbers as
//! documents), an SSH key to an [`SshKey`]. Each vault is a folder. Items in the trash are
//! skipped.
//!
//! Proton Pass passkeys: the export's passkey entries are not read. Whether they carry a private
//! key Kemlock can use is an open question in the design (only a sample export will tell), so each
//! is listed as skipped and its login is kept.
//!
//! The ZIP's layout is not documented; the data file is found by its name (`data.json`, or a `.pgp`
//! file), and every other file is kept as an [`ImportFile`](crate::model::ImportFile), attached to
//! the item whose id is one of the folders in the file's path, when there is one.

use std::collections::HashMap;
use std::io::Read as _;

use pgp::composed::Message;
use pgp::types::Password;
use serde_json::Value;

use crate::builder::Builder;
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::model::{
    Address, Card, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity, ImportBatch,
    ItemRef, Login, Meta, Note, SkipReason, SshKey,
};
use crate::util::{
    card_brand, card_number, clean_name, clean_notes, decode_text, jarr, jbool, jint, jstr, kvp,
    make_uris, nonblank, parse_month, parse_year, scalar_text, split_name_words,
};
use crate::zip::{Zip, looks_like_zip};

const PGP_ARMOR: &[u8] = b"-----BEGIN PGP MESSAGE-----";

/// Whether `bytes` look like an OpenPGP message: ASCII armor, or a binary message that starts with
/// a symmetric-key (3) or encrypted-data (18) packet.
pub fn looks_like_pgp(bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let rest = bytes.get(start..).unwrap_or(&[]);
    if rest.starts_with(PGP_ARMOR) {
        return true;
    }
    let Some(&first) = rest.first() else {
        return false;
    };
    if first & 0x80 == 0 {
        return false;
    }
    let tag = if first & 0x40 != 0 {
        first & 0x3F
    } else {
        (first >> 2) & 0x0F
    };
    tag == 3 || tag == 18
}

/// Reads a Proton Pass export: plain JSON, a ZIP, or a passphrase-encrypted OpenPGP message (the
/// password is `ctx.password`; without it, [`ImportError::PasswordRequired`]).
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    if looks_like_zip(bytes) {
        return parse_zip(bytes, ctx);
    }
    ctx.limits.check_input(bytes)?;
    if looks_like_pgp(bytes) {
        let json = decrypt(bytes, ctx)?;
        let mut reader = Reader::new(Format::ProtonPassPgp, ctx);
        reader.read_json(&json)?;
        return reader.b.finish();
    }
    let mut reader = Reader::new(Format::ProtonPassJson, ctx);
    reader.read_json(bytes)?;
    reader.b.finish()
}

/// Decrypts a symmetric OpenPGP message with `ctx.password`.
fn decrypt(bytes: &[u8], ctx: &Context<'_>) -> Result<Vec<u8>> {
    let Some(password) = ctx.password else {
        return Err(ImportError::PasswordRequired);
    };
    let (message, _headers) = Message::from_reader(bytes)
        .map_err(|_| ImportError::malformed("not an OpenPGP message"))?;
    if !message.is_encrypted() {
        return Err(ImportError::malformed(
            "the OpenPGP message is not encrypted",
        ));
    }
    let password = Password::from(password);
    let mut message = message
        .decrypt_with_password(&password)
        .map_err(|_| ImportError::BadPassword)?;
    if message.is_compressed() {
        message = message
            .decompress()
            .map_err(|_| ImportError::malformed("the OpenPGP message is damaged"))?;
    }
    let limit = ctx.limits.max_entry_bytes as u64;
    let mut plain = Vec::new();
    // A wrong password can pass the quick check and fail the integrity check as the data is read.
    (&mut message)
        .take(limit.saturating_add(1))
        .read_to_end(&mut plain)
        .map_err(|_| ImportError::BadPassword)?;
    if plain.len() as u64 > limit {
        return Err(ImportError::LimitExceeded("size of the decrypted export"));
    }
    Ok(plain)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parse_zip(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let mut zip = Zip::open(bytes, ctx.limits)?;
    let json_at = zip
        .entries()
        .iter()
        .position(|e| !e.is_dir() && basename(&e.name) == "data.json");
    let pgp_at = zip
        .entries()
        .iter()
        .position(|e| !e.is_dir() && basename(&e.name).ends_with(".pgp"));
    let data_at = json_at.or(pgp_at).ok_or(ImportError::Unsupported)?;
    let raw = zip.read(data_at)?;
    let json = if json_at.is_some() {
        raw
    } else {
        decrypt(&raw, ctx)?
    };
    let mut reader = Reader::new(Format::ProtonPassZip, ctx);
    reader.read_json(&json)?;

    let others: Vec<(usize, String)> = zip
        .entries()
        .iter()
        .enumerate()
        .filter(|(i, e)| *i != data_at && !e.is_dir() && !basename(&e.name).is_empty())
        .map(|(i, e)| (i, e.name.clone()))
        .collect();
    for (index, path) in others {
        let name = basename(&path);
        match zip.read(index) {
            Ok(data) => {
                let owner = path
                    .split('/')
                    .find_map(|segment| reader.ids.get(segment).copied());
                reader.b.file(name, None, data, owner);
            }
            Err(ImportError::LimitExceeded(_)) => {
                reader.b.skip(Some(name), SkipReason::FileOverLimit, None);
            }
            Err(_) => {
                reader.b.skip(
                    Some(name),
                    SkipReason::Malformed,
                    Some("a damaged file in the ZIP"),
                );
            }
        }
    }
    reader.b.finish()
}

/// Reads the items of the JSON into the builder.
struct Reader<'a> {
    b: Builder<'a>,
    /// Item id to the entry made from it, to attach files.
    ids: HashMap<String, ItemRef>,
}

impl<'a> Reader<'a> {
    fn new(format: Format, ctx: &Context<'a>) -> Reader<'a> {
        Reader {
            b: Builder::new(format, ctx.limits),
            ids: HashMap::new(),
        }
    }

    fn read_json(&mut self, bytes: &[u8]) -> Result<()> {
        let text = decode_text(bytes);
        let root: Value = serde_json::from_str(&text)
            .map_err(|_| ImportError::malformed("the export is not valid JSON"))?;
        if !root.is_object() {
            return Err(ImportError::Unsupported);
        }
        if jbool(&root, "encrypted") == Some(true) {
            return Err(ImportError::UnsupportedEncryption(
                "a Proton Pass JSON file marked encrypted; export it with a passphrase instead"
                    .to_string(),
            ));
        }
        let vaults = root
            .get("vaults")
            .and_then(Value::as_object)
            .ok_or(ImportError::Unsupported)?;
        for vault in vaults.values() {
            let folder = jstr(vault, "name").and_then(|name| self.b.folder(name));
            for item in jarr(vault, "items") {
                self.item(item, folder);
            }
        }
        Ok(())
    }

    fn item(&mut self, item: &Value, folder: Option<usize>) {
        let data = &item["data"];
        let title = jstr(&data["metadata"], "name");
        if jint(item, "state") == Some(2) {
            self.b.skip(title, SkipReason::Trashed, None);
            return;
        }
        let name = clean_name(title);
        let meta = Meta {
            folder,
            favorite: jbool(item, "pinned").unwrap_or(false),
            created_ms: time_ms(item, "createTime"),
            modified_ms: time_ms(item, "modifyTime"),
            source_id: jstr(item, "itemId").map(str::to_string),
            ..Meta::default()
        };
        let note = nonblank(jstr(&data["metadata"], "note"));
        let content = &data["content"];
        let mut fields: Vec<CustomField> = Vec::new();
        let mut spill: Option<String> = None;
        let kind = jstr(data, "type").unwrap_or("");

        let placed: Option<ItemRef> = match kind {
            "login" | "alias" => {
                let mut login = Login {
                    name,
                    meta,
                    ..Login::default()
                };
                if kind == "login" {
                    login.uris = make_uris(jarr(content, "urls").iter().filter_map(Value::as_str));
                    let username = nonblank(jstr(content, "itemUsername"));
                    let email = nonblank(jstr(content, "itemEmail"));
                    match (username, email) {
                        (Some(user), Some(email)) => {
                            login.username = Some(user);
                            kvp(&mut fields, &mut spill, "email", &email, FieldKind::Text);
                        }
                        (user, email) => login.username = user.or(email),
                    }
                    login.password = nonblank(jstr(content, "password"));
                    login.totp = nonblank(jstr(content, "totpUri"));
                    for _ in jarr(content, "passkeys") {
                        self.b.skip(
                            title,
                            SkipReason::UnsupportedPasskey,
                            Some("Proton Pass passkey keys are not read yet"),
                        );
                    }
                } else {
                    login.username = nonblank(jstr(item, "aliasEmail"));
                }
                extra_fields(&mut fields, &mut spill, jarr(data, "extraFields"));
                login.fields = fields;
                login.notes = join_notes(note, spill);
                self.b.login(login)
            }
            "creditCard" => {
                let mut card = Card {
                    name,
                    meta,
                    ..Card::default()
                };
                card.cardholder = nonblank(jstr(content, "cardholderName"));
                card.number = jstr(content, "number").and_then(card_number);
                card.brand = card.number.as_deref().and_then(card_brand);
                card.code = nonblank(jstr(content, "verificationNumber"));
                card.pin = nonblank(jstr(content, "pin"));
                if let Some(expiry) = jstr(content, "expirationDate") {
                    // `yyyy-mm`
                    card.exp_year = expiry.get(0..4).and_then(parse_year);
                    card.exp_month = expiry.get(5..7).and_then(parse_month);
                }
                extra_fields(&mut fields, &mut spill, jarr(data, "extraFields"));
                card.fields = fields;
                card.notes = join_notes(note, spill);
                self.b.card(card)
            }
            "identity" => {
                let mut identity = identity_of(content, &mut fields, &mut spill);
                extra_fields(&mut fields, &mut spill, jarr(data, "extraFields"));
                identity.name = name;
                identity.meta = meta;
                identity.fields = fields;
                identity.notes = join_notes(note, spill);
                self.b.identity(identity)
            }
            "sshKey" => {
                let private_key = jstr(content, "privateKey").unwrap_or("");
                if private_key.trim().is_empty() {
                    self.b.skip(
                        title,
                        SkipReason::BadKey,
                        Some("an SSH key item without a private key"),
                    );
                    None
                } else {
                    extra_fields(&mut fields, &mut spill, jarr(data, "extraFields"));
                    sections(&mut fields, &mut spill, jarr(content, "sections"));
                    self.b.ssh_key(SshKey {
                        name,
                        private_key: private_key.to_string(),
                        public_key: nonblank(jstr(content, "publicKey")),
                        fingerprint: nonblank(jstr(content, "fingerprint")),
                        notes: join_notes(note, spill),
                        fields,
                        meta,
                    })
                }
            }
            other => {
                if other == "wifi" {
                    wifi_fields(content, &mut fields, &mut spill);
                }
                extra_fields(&mut fields, &mut spill, jarr(data, "extraFields"));
                if other == "custom" || other == "wifi" {
                    sections(&mut fields, &mut spill, jarr(content, "sections"));
                } else if let Some(map) = content.as_object() {
                    // A kind this reader doesn't know: strings and numbers become fields.
                    for (key, value) in map {
                        if key == "sections" {
                            sections(&mut fields, &mut spill, jarr(content, "sections"));
                        } else if let Some(text) = scalar_text(value) {
                            kvp(&mut fields, &mut spill, key, &text, FieldKind::Text);
                        }
                    }
                }
                self.b.note(Note {
                    name,
                    text: join_notes(note, spill),
                    fields,
                    meta,
                })
            }
        };
        if let (Some(entry), Some(id)) = (placed, jstr(item, "itemId")) {
            self.ids.insert(id.to_string(), entry);
        }
    }
}

/// Proton's times are epoch seconds; a larger number is taken as milliseconds already.
fn time_ms(item: &Value, key: &str) -> Option<i64> {
    jint(item, key).map(|t| {
        if t.unsigned_abs() < 1_000_000_000_000 {
            t.saturating_mul(1000)
        } else {
            t
        }
    })
}

/// `processExtraFields`: each field is a custom field, hidden for `hidden` and `totp`.
fn extra_fields(fields: &mut Vec<CustomField>, spill: &mut Option<String>, list: &[Value]) {
    for field in list {
        let name = jstr(field, "fieldName").unwrap_or("");
        let kind = jstr(field, "type").unwrap_or("text");
        let data = &field["data"];
        let value = match kind {
            "totp" => scalar_text(&data["totpUri"]),
            "timestamp" => scalar_text(&data["timestamp"]),
            _ => scalar_text(&data["content"]),
        }
        .unwrap_or_default();
        let shown = if kind == "totp" || kind == "hidden" {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        kvp(fields, spill, name, &value, shown);
    }
}

/// `processSections`: the fields of each section.
fn sections(fields: &mut Vec<CustomField>, spill: &mut Option<String>, list: &[Value]) {
    for section in list {
        extra_fields(fields, spill, jarr(section, "sectionFields"));
    }
}

fn wifi_fields(content: &Value, fields: &mut Vec<CustomField>, spill: &mut Option<String>) {
    if let Some(password) = jstr(content, "password") {
        kvp(fields, spill, "Password", password, FieldKind::Hidden);
    }
    if let Some(ssid) = jstr(content, "ssid") {
        kvp(fields, spill, "SSID", ssid, FieldKind::Text);
    }
    if let Some(security) = jint(content, "security") {
        let label = match security {
            1 => "WPA",
            2 => "WPA2",
            3 => "WPA3",
            4 => "WEP",
            _ => "Unknown",
        };
        kvp(fields, spill, "Security", label, FieldKind::Text);
    }
}

fn is_ymd(s: &str) -> bool {
    s.len() == 10
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

/// The keys of an identity that map to a field of [`Identity`].
const MAPPED_IDENTITY_KEYS: [&str; 18] = [
    "fullName",
    "firstName",
    "middleName",
    "lastName",
    "email",
    "phoneNumber",
    "company",
    "socialSecurityNumber",
    "passportNumber",
    "licenseNumber",
    "organization",
    "streetAddress",
    "floor",
    "county",
    "city",
    "stateOrProvince",
    "zipOrPostalCode",
    "countryOrRegion",
];

/// The lists of extra fields an identity has.
const IDENTITY_EXTRA_LISTS: [&str; 4] = [
    "extraPersonalDetails",
    "extraAddressDetails",
    "extraContactDetails",
    "extraWorkDetails",
];

fn identity_of(
    content: &Value,
    fields: &mut Vec<CustomField>,
    spill: &mut Option<String>,
) -> Identity {
    // `processNames`: a full name wins, split on whitespace; the separate names fill what it lacks.
    let (first, middle, last) = match nonblank(jstr(content, "fullName")) {
        Some(full) => split_name_words(&full),
        None => (None, None, None),
    };
    let birth = jstr(content, "birthdate").filter(|d| is_ymd(d));

    let street = |key: &str| nonblank(jstr(content, key));
    let floor_county = [street("floor"), street("county")]
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" ");
    let lines: Vec<String> = [
        street("organization"),
        street("streetAddress"),
        nonblank(Some(floor_county.as_str())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let address = Address {
        lines,
        city: street("city"),
        region: street("stateOrProvince"),
        postal_code: street("zipOrPostalCode"),
        country: street("countryOrRegion"),
    };
    let has_address = !address.lines.is_empty()
        || address.city.is_some()
        || address.region.is_some()
        || address.postal_code.is_some()
        || address.country.is_some();

    let mut documents = Vec::new();
    for (key, kind) in [
        ("socialSecurityNumber", DocumentKind::TaxNumber),
        ("passportNumber", DocumentKind::Passport),
        ("licenseNumber", DocumentKind::DriversLicence),
    ] {
        if let Some(number) = street(key) {
            documents.push(IdDocument {
                kind,
                number: Some(number),
                ..IdDocument::default()
            });
        }
    }

    // `processIdentityItemUnmappedAndExtraFields`
    if let Some(map) = content.as_object() {
        for (key, value) in map {
            if MAPPED_IDENTITY_KEYS.contains(&key.as_str())
                || (key == "birthdate" && birth.is_some())
            {
                continue;
            }
            if key == "extraSections" {
                if let Some(list) = value.as_array() {
                    sections(fields, spill, list);
                }
            } else if IDENTITY_EXTRA_LISTS.contains(&key.as_str()) {
                if let Some(list) = value.as_array() {
                    extra_fields(fields, spill, list);
                }
            } else if let Some(text) = scalar_text(value) {
                kvp(fields, spill, key, &text, FieldKind::Text);
            }
        }
    }

    Identity {
        given_name: first.or_else(|| street("firstName")),
        middle_name: middle.or_else(|| street("middleName")),
        family_name: last.or_else(|| street("lastName")),
        company: street("company"),
        email: street("email"),
        phone: street("phoneNumber"),
        birth_date: birth.map(str::to_string),
        address: if has_address { Some(address) } else { None },
        documents,
        ..Identity::default()
    }
}

/// The item's note and the lines that spilled out of its fields, one under the other.
fn join_notes(note: Option<String>, spill: Option<String>) -> Option<String> {
    let joined = match (note, spill) {
        (Some(note), Some(spill)) => Some(format!("{note}\n{spill}")),
        (note, spill) => note.or(spill),
    };
    clean_notes(joined.map(|text| text.trim_end().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::zip::build_stored_zip;

    const EXPORT: &str = include_str!("../tests/fixtures/protonpass/export.json");
    const PGP: &[u8] = include_bytes!("../tests/fixtures/protonpass/encrypted.pgp");
    const ASC: &[u8] = include_bytes!("../tests/fixtures/protonpass/encrypted.asc");
    const PGP_COMPRESSED: &[u8] =
        include_bytes!("../tests/fixtures/protonpass/encrypted-compressed.pgp");
    const PASSWORD: &str = "correct horse";

    fn read(bytes: &[u8]) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(bytes, &Context::new(&limits))
    }

    fn read_with(bytes: &[u8], password: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(bytes, &Context::new(&limits).with_password(password))
    }

    #[test]
    fn reads_every_kind_of_item() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        assert_eq!(batch.format, Format::ProtonPassJson);
        assert_eq!(batch.logins.len(), 3);
        assert_eq!(batch.notes.len(), 3);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.identities.len(), 1);
        assert_eq!(batch.ssh_keys.len(), 1);
        assert_eq!(batch.folders.len(), 2);
        assert_eq!(batch.folders[0].name, "Personal");
        assert_eq!(batch.folders[1].name, "Work");
    }

    #[test]
    fn a_login_keeps_its_addresses_code_fields_and_dates() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example Mail");
        assert_eq!(login.username.as_deref(), Some("ada"));
        assert_eq!(login.password.as_deref(), Some("correct-horse-1"));
        assert_eq!(login.uris.len(), 2);
        assert_eq!(login.uris[1].uri, "https://mail2.example.com");
        assert!(
            login
                .totp
                .as_deref()
                .expect("totp")
                .contains("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(login.notes.as_deref(), Some("Recovery on paper"));
        assert!(login.meta.favorite);
        assert_eq!(login.meta.folder, Some(0));
        assert_eq!(login.meta.created_ms, Some(1_700_000_000_000));
        assert_eq!(login.meta.modified_ms, Some(1_700_000_100_000));
        assert_eq!(login.meta.source_id.as_deref(), Some("item-login"));

        let names: Vec<(&str, &str, FieldKind)> = login
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str(), f.kind))
            .collect();
        assert_eq!(
            names,
            [
                ("email", "ada@example.com", FieldKind::Text),
                ("Security question", "first pet", FieldKind::Text),
                ("Backup code", "1234-5678", FieldKind::Hidden),
                (
                    "Second factor",
                    "otpauth://totp/Extra?secret=KRSXG5CTMVRXEZLU",
                    FieldKind::Hidden
                ),
                ("Joined", "2020-01-02T03:04:05Z", FieldKind::Text),
            ]
        );
    }

    #[test]
    fn an_alias_and_an_email_only_login_use_the_address_as_the_username() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        assert_eq!(batch.logins[1].name, "Newsletter alias");
        assert_eq!(
            batch.logins[1].username.as_deref(),
            Some("news.abc123@passmail.example")
        );
        let work = &batch.logins[2];
        assert_eq!(work.username.as_deref(), Some("ada@work.example"));
        assert_eq!(work.uris[0].uri, "http://tickets.example.org");
        assert_eq!(work.meta.folder, Some(1));
        assert!(work.fields.is_empty());
    }

    #[test]
    fn notes_custom_items_and_wifi_become_notes_with_fields() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        let note = &batch.notes[0];
        assert_eq!(note.name, "Safe combination");
        assert_eq!(note.text.as_deref(), Some("Left 10, right 22, left 5"));
        assert_eq!(note.fields[0].name, "Where");

        let rack = &batch.notes[1];
        assert_eq!(rack.name, "Server rack");
        assert_eq!(rack.text.as_deref(), Some("Basement"));
        let rack_fields: Vec<(&str, FieldKind)> = rack
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.kind))
            .collect();
        assert_eq!(
            rack_fields,
            [
                ("Asset tag", FieldKind::Text),
                ("Gateway", FieldKind::Text),
                ("Console password", FieldKind::Hidden)
            ]
        );

        let wifi = &batch.notes[2];
        assert_eq!(wifi.name, "Home Wi-Fi");
        assert_eq!(wifi.text, None);
        let wifi_fields: Vec<(&str, &str, FieldKind)> = wifi
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str(), f.kind))
            .collect();
        assert_eq!(
            wifi_fields,
            [
                ("Password", "wifi-pass", FieldKind::Hidden),
                ("SSID", "HomeNet", FieldKind::Text),
                ("Security", "WPA2", FieldKind::Text)
            ]
        );
    }

    #[test]
    fn a_card_keeps_its_digits_brand_expiry_and_pin() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.name, "Everyday Visa");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!(card.pin.as_deref(), Some("4321"));
    }

    #[test]
    fn an_identity_gets_a_split_name_an_address_documents_and_the_rest_as_fields() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        let id = &batch.identities[0];
        assert_eq!(id.name, "Ada, home");
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.middle_name.as_deref(), Some("Augusta King"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        assert_eq!(id.phone.as_deref(), Some("+44 20 7946 0000"));
        assert_eq!(id.company.as_deref(), Some("Analytical Engines Ltd"));
        assert_eq!(id.birth_date.as_deref(), Some("1815-12-10"));
        let address = id.address.as_ref().expect("address");
        assert_eq!(
            address.lines,
            [
                "Analytical Engines Ltd",
                "12 St James's Square",
                "3 Westminster"
            ]
        );
        assert_eq!(address.city.as_deref(), Some("London"));
        assert_eq!(address.region.as_deref(), Some("England"));
        assert_eq!(address.postal_code.as_deref(), Some("SW1Y 4JH"));
        assert_eq!(address.country.as_deref(), Some("GB"));
        let docs: Vec<(DocumentKind, &str)> = id
            .documents
            .iter()
            .map(|d| (d.kind, d.number.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(
            docs,
            [
                (DocumentKind::TaxNumber, "123-45-6789"),
                (DocumentKind::Passport, "X1234567"),
                (DocumentKind::DriversLicence, "LOVEL 801215 A99AA")
            ]
        );
        let fields: Vec<(&str, &str)> = id
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            fields,
            [
                ("Nickname", "Countess"),
                ("Blood type", "A+"),
                ("website", "https://example.com")
            ]
        );
    }

    #[test]
    fn an_ssh_key_keeps_its_parts() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        let key = &batch.ssh_keys[0];
        assert_eq!(key.name, "Laptop key");
        assert!(
            key.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(
            key.public_key
                .as_deref()
                .expect("public")
                .starts_with("ssh-ed25519 ")
        );
        assert_eq!(key.fingerprint.as_deref(), Some("SHA256:fakefingerprint"));
        assert_eq!(key.fields[0].name, "Host");
    }

    #[test]
    fn trashed_items_and_passkeys_are_listed_as_skipped() {
        let batch = read(EXPORT.as_bytes()).expect("batch");
        assert_eq!(batch.skipped.len(), 2);
        assert_eq!(batch.skipped[0].reason, SkipReason::UnsupportedPasskey);
        assert_eq!(batch.skipped[0].name.as_deref(), Some("Example Mail"));
        assert_eq!(batch.skipped[1].reason, SkipReason::Trashed);
        assert_eq!(batch.skipped[1].name.as_deref(), Some("Old forum"));
        assert!(batch.logins.iter().all(|l| l.name != "Old forum"));
        assert!(batch.logins[0].passkeys.is_empty());
    }

    #[test]
    fn a_zip_reads_the_json_and_attaches_the_files() {
        let zip = build_stored_zip(&[
            ("Proton Pass/data.json", EXPORT.as_bytes()),
            (
                "Proton Pass/files/item-login/recovery.txt",
                b"code-1\ncode-2\n",
            ),
            ("Proton Pass/files/loose.bin", &[1, 2, 3]),
        ]);
        let batch = read(&zip).expect("batch");
        assert_eq!(batch.format, Format::ProtonPassZip);
        assert_eq!(batch.logins.len(), 3);
        assert_eq!(batch.files.len(), 2);
        assert_eq!(batch.files[0].name, "recovery.txt");
        assert_eq!(batch.files[0].data, b"code-1\ncode-2\n");
        assert_eq!(
            batch.files[0].owner,
            Some(ItemRef {
                kind: crate::model::ItemKind::Login,
                index: 0
            })
        );
        assert_eq!(batch.files[1].name, "loose.bin");
        assert_eq!(batch.files[1].owner, None);
    }

    #[test]
    fn a_zip_without_the_data_file_is_not_a_proton_export() {
        let zip = build_stored_zip(&[("notes.txt", b"hello")]);
        assert_eq!(read(&zip).err(), Some(ImportError::Unsupported));
    }

    #[test]
    fn a_zip_over_the_limits_is_refused() {
        let zip = build_stored_zip(&[("data.json", EXPORT.as_bytes()), ("a", b"1"), ("b", b"2")]);
        let limits = Limits {
            max_zip_entries: 2,
            ..Limits::default()
        };
        assert!(matches!(
            parse(&zip, &Context::new(&limits)),
            Err(ImportError::LimitExceeded(_))
        ));
        let limits = Limits {
            max_entry_bytes: 100,
            ..Limits::default()
        };
        assert!(matches!(
            parse(&zip, &Context::new(&limits)),
            Err(ImportError::LimitExceeded(_))
        ));
    }

    #[test]
    fn a_zip_holding_an_encrypted_export_is_decrypted() {
        let zip = build_stored_zip(&[("Proton Pass/data.pgp", PGP)]);
        assert_eq!(read(&zip).err(), Some(ImportError::PasswordRequired));
        let batch = read_with(&zip, PASSWORD).expect("batch");
        assert_eq!(batch.format, Format::ProtonPassZip);
        assert_eq!(batch.logins.len(), 3);
    }

    #[test]
    fn the_encrypted_exports_open_with_the_passphrase() {
        let plain = read(EXPORT.as_bytes()).expect("plain");
        for (bytes, label) in [
            (PGP, "binary"),
            (ASC, "armored"),
            (PGP_COMPRESSED, "compressed"),
        ] {
            let batch = read_with(bytes, PASSWORD).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(batch.format, Format::ProtonPassPgp, "{label}");
            assert_eq!(batch.logins, plain.logins, "{label}");
            assert_eq!(batch.cards, plain.cards, "{label}");
            assert_eq!(batch.skipped, plain.skipped, "{label}");
        }
    }

    #[test]
    fn the_encrypted_exports_need_the_right_passphrase() {
        for bytes in [PGP, ASC, PGP_COMPRESSED] {
            assert_eq!(read(bytes).err(), Some(ImportError::PasswordRequired));
            assert_eq!(
                read_with(bytes, "wrong horse").err(),
                Some(ImportError::BadPassword)
            );
        }
    }

    #[test]
    fn damaged_encrypted_exports_fail_cleanly() {
        let cut = &PGP[..PGP.len() / 2];
        assert!(read_with(cut, PASSWORD).is_err());
        let mut flipped = PGP.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x55;
        assert!(read_with(&flipped, PASSWORD).is_err());
        assert!(read_with(&PGP[..3], PASSWORD).is_err());
        assert!(
            read_with(
                b"-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n",
                PASSWORD
            )
            .is_err()
        );
    }

    #[test]
    fn the_decrypted_size_is_capped() {
        let limits = Limits {
            max_entry_bytes: 100,
            ..Limits::default()
        };
        assert_eq!(
            parse(PGP, &Context::new(&limits).with_password(PASSWORD)).err(),
            Some(ImportError::LimitExceeded("size of the decrypted export"))
        );
    }

    #[test]
    fn looks_like_pgp_checks_the_first_packet() {
        assert!(looks_like_pgp(PGP));
        assert!(looks_like_pgp(ASC));
        assert!(looks_like_pgp(b"\n  -----BEGIN PGP MESSAGE-----"));
        assert!(!looks_like_pgp(EXPORT.as_bytes()));
        assert!(!looks_like_pgp(b""));
        assert!(!looks_like_pgp(b"\xEF\xBB\xBF{}"));
    }

    #[test]
    fn json_marked_encrypted_is_not_read() {
        let json = r#"{"version":"1","userId":"u","encrypted":true,"vaults":{}}"#;
        assert!(matches!(
            read(json.as_bytes()),
            Err(ImportError::UnsupportedEncryption(_))
        ));
    }

    #[test]
    fn other_text_and_empty_exports_are_refused() {
        assert_eq!(read(b"[]").err(), Some(ImportError::Unsupported));
        assert_eq!(
            read(b"{\"items\":[]}").err(),
            Some(ImportError::Unsupported)
        );
        assert!(matches!(read(b"not json"), Err(ImportError::Malformed(_))));
        assert_eq!(read(b"{\"vaults\":{}}").err(), Some(ImportError::Empty));
        assert_eq!(
            read(b"{\"vaults\":{\"a\":{\"name\":\"V\",\"items\":[]}}}").err(),
            Some(ImportError::Empty)
        );
    }

    #[test]
    fn an_unknown_item_type_becomes_a_note_with_its_strings_and_numbers() {
        let json = r#"{"vaults":{"a":{"name":"V","items":[
            {"itemId":"x","data":{"metadata":{"name":"Future","note":""},"extraFields":[],
             "type":"loyaltyCard","content":{"programName":"Miles","memberNumber":42,"nested":{"a":1}}},
             "state":1,"pinned":false}]}}}"#;
        let batch = read(json.as_bytes()).expect("batch");
        let note = &batch.notes[0];
        assert_eq!(note.name, "Future");
        let fields: Vec<(&str, &str)> = note
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(fields, [("memberNumber", "42"), ("programName", "Miles")]);
    }

    #[test]
    fn items_over_the_entry_limit_are_counted() {
        let limits = Limits {
            max_entries: 4,
            ..Limits::default()
        };
        let batch = parse(EXPORT.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 4);
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::OverLimit && s.count == 5)
        );
    }

    #[test]
    fn damaged_json_does_not_panic() {
        for text in [
            "{\"vaults\":{\"a\":{\"items\":[null,1,\"x\",[],{}]}}}",
            "{\"vaults\":{\"a\":{\"name\":null,\"items\":[{\"data\":null}]}}}",
            "{\"vaults\":{\"a\":{\"items\":[{\"data\":{\"type\":\"creditCard\",\"content\":{\"expirationDate\":\"20\"}}}]}}}",
            "{\"vaults\":{\"a\":{\"items\":[{\"data\":{\"type\":\"identity\",\"content\":[1]}}]}}}",
            "{\"vaults\":[]}",
            "\u{feff}{\"vaults\":{}}",
        ] {
            let _ = read(text.as_bytes());
        }
    }
}
