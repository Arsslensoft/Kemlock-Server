// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/dashlane/dashlane-csv-importer.ts and
//   libs/importer/src/importers/dashlane/types/dashlane-csv-types.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Dashlane's CSV export: a ZIP of CSV files (`credentials.csv`, `payments.csv`, `ids.csv`,
//! `personalInfo.csv`, `securenotes.csv`), or one of those files alone.
//!
//! The kind of file is read from its first column names, as Bitwarden does:
//!
//! - `username, ...` credentials: logins, in a folder named by `category`; one with nothing to sign
//!   in with is a note;
//! - `type, account_name, ...` payments: a card for `credit_card` and `payment_card`, a note for a
//!   bank account (an account number is not a card number);
//! - `type, number, ...` ids: an identity with one document (passport, driver's licence, social
//!   security or tax number, ID card);
//! - `type, title, ...` personal information: when exactly one row is a `name`, all rows make one
//!   identity; otherwise each row is a note;
//! - `title, note` secure notes.
//!
//! Columns the mapping doesn't use become custom fields (or note lines, when long).

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, Record, Table};
use crate::error::{ImportError, Result};
use crate::model::{
    Address, Card, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity, ImportBatch,
    Login, Meta, Note, SkipReason,
};
use crate::util::{
    card_brand, card_number, clean_name, clean_notes, decode_text, full_name, is_blank,
    is_noteworthy_login, kvp, make_uris, nonblank, set_card_expiration,
};
use crate::zip::{Zip, looks_like_zip};

/// Reads a Dashlane export: the ZIP, or one CSV file.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    if looks_like_zip(bytes) {
        return parse_zip(bytes, ctx);
    }
    ctx.limits.check_input(bytes)?;
    let text = decode_text(bytes);
    let table = Table::parse(&text, CsvOptions::default(), ctx.limits.max_entries);
    let mut b = Builder::new(Format::DashlaneCsv, ctx.limits);
    if !read_table(&mut b, &table) {
        return Err(ImportError::Unsupported);
    }
    b.finish()
}

fn parse_zip(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let mut zip = Zip::open(bytes, ctx.limits)?;
    let csvs: Vec<(usize, String)> = zip
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_dir() && e.name.to_ascii_lowercase().ends_with(".csv"))
        .map(|(i, e)| (i, e.name.clone()))
        .collect();
    if csvs.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::DashlaneZip, ctx.limits);
    let mut recognised = false;
    for (index, name) in csvs {
        let data = zip.read(index)?;
        let text = decode_text(&data);
        let table = Table::parse(&text, CsvOptions::default(), ctx.limits.max_entries);
        if read_table(&mut b, &table) {
            recognised = true;
        } else {
            b.skip(
                Some(&name),
                SkipReason::UnsupportedKind,
                Some("a CSV file Kemlock doesn't know"),
            );
        }
    }
    if !recognised {
        return Err(ImportError::Unsupported);
    }
    b.finish()
}

/// Reads one CSV by the kind its header shows; false when it is none of the five.
fn read_table(b: &mut Builder<'_>, table: &Table) -> bool {
    let first = table.headers.first().map(String::as_str).unwrap_or("");
    let second = table.headers.get(1).map(String::as_str).unwrap_or("");
    match (first, second) {
        ("username", _) => credentials(b, table),
        ("type", "account_name") => payments(b, table),
        ("type", "number") => ids(b, table),
        ("type", "title") => personal_information(b, table),
        ("title", "note") => secure_notes(b, table),
        _ => return false,
    }
    b.note_unread(table.unread);
    true
}

/// A column the mapping doesn't use, as a custom field or note line.
fn import_unmapped(
    rec: &Record<'_>,
    mapped: &[&str],
    fields: &mut Vec<CustomField>,
    notes: &mut Option<String>,
    hidden: &[&str],
) {
    for (key, value) in rec.pairs() {
        if mapped.contains(&key) {
            continue;
        }
        let kind = if hidden.contains(&key) {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        kvp(fields, notes, key, value, kind);
    }
}

/// `2020-1-5` as `2020-01-05`; `None` unless there are three parts.
fn dashlane_date(date: Option<&str>) -> Option<String> {
    let mut parts = date?.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || is_blank(year) || is_blank(month) || is_blank(day) {
        return None;
    }
    Some(format!("{year}-{month:0>2}-{day:0>2}"))
}

fn credentials(b: &mut Builder<'_>, table: &Table) {
    const MAPPED: [&str; 9] = [
        "title",
        "note",
        "username",
        "password",
        "url",
        "otpSecret",
        "otpUrl",
        "category",
        "",
    ];
    for rec in table.records() {
        let folder = rec.get("category").and_then(|category| b.folder(category));
        let meta = Meta {
            folder,
            ..Meta::default()
        };
        let mut fields = Vec::new();
        let mut notes = nonblank(rec.get("note"));
        import_unmapped(&rec, &MAPPED, &mut fields, &mut notes, &[]);
        let login = Login {
            name: clean_name(rec.get("title")),
            uris: make_uris(rec.get("url")),
            username: nonblank(rec.get("username")),
            password: nonblank(rec.get("password")),
            // `otpUrl` replaced `otpSecret` in newer exports.
            totp: nonblank(rec.get("otpUrl")).or_else(|| nonblank(rec.get("otpSecret"))),
            notes: clean_notes(notes),
            fields,
            meta,
            ..Login::default()
        };
        if is_noteworthy_login(&login) && login.totp.is_none() {
            b.note(Note {
                name: login.name,
                text: login.notes,
                fields: login.fields,
                meta: login.meta,
            });
        } else {
            b.login(login);
        }
    }
}

fn payments(b: &mut Builder<'_>, table: &Table) {
    for rec in table.records() {
        let kind = rec.get("type").unwrap_or("");
        let account_name = rec.get("account_name");
        let mut notes = None;
        if kind == "credit_card" || kind == "payment_card" {
            let mut card = Card {
                // Dashlane's `name` is the card's own name; `account_name` the cardholder.
                name: clean_name(nonblank(rec.get("name")).as_deref().or(account_name)),
                cardholder: nonblank(account_name),
                number: card_number(rec.get("cc_number").unwrap_or("")),
                code: nonblank(rec.get("code")),
                ..Card::default()
            };
            card.brand = card.number.as_deref().and_then(card_brand);
            let month = rec.get("expiration_month").unwrap_or("");
            let year = rec.get("expiration_year").unwrap_or("");
            if !set_card_expiration(&mut card, &format!("{month}/{year}"))
                && !(is_blank(month) && is_blank(year))
            {
                kvp(
                    &mut card.fields,
                    &mut notes,
                    "expiration",
                    &format!("{month}/{year}"),
                    FieldKind::Text,
                );
            }
            const MAPPED: [&str; 8] = [
                "type",
                "account_name",
                "cc_number",
                "code",
                "expiration_month",
                "expiration_year",
                "name",
                "",
            ];
            import_unmapped(&rec, &MAPPED, &mut card.fields, &mut notes, &[]);
            card.notes = clean_notes(notes);
            b.card(card);
        } else {
            // A bank account, or a kind this version doesn't know: a note with every column.
            let mut fields = Vec::new();
            let mapped: &[&str] = if kind == "bank" {
                &["account_name", "type", ""]
            } else {
                &["account_name", ""]
            };
            import_unmapped(
                &rec,
                mapped,
                &mut fields,
                &mut notes,
                &["account_number", "routing_number"],
            );
            b.note(Note {
                name: clean_name(account_name),
                text: clean_notes(notes),
                fields,
                meta: Meta::default(),
            });
        }
    }
}

fn set_names(identity: &mut Identity, full: &str) {
    let (first, middle, last) = full_name(full);
    identity.given_name = first;
    identity.middle_name = middle;
    identity.family_name = last;
}

fn ids(b: &mut Builder<'_>, table: &Table) {
    for rec in table.records() {
        let kind = rec.get("type").unwrap_or("");
        let full = rec.get("name").unwrap_or("");
        let number = nonblank(rec.get("number"));
        let mut identity = Identity::default();
        let mut mapped: Vec<&str> = vec!["name", "number", "type", ""];
        let mut document = IdDocument {
            number,
            ..IdDocument::default()
        };
        match kind {
            "card" | "passport" | "license" | "social_security" => {
                identity.name = format!("{full} {kind}").trim().to_string();
                set_names(&mut identity, full);
                document.kind = match kind {
                    "card" => DocumentKind::IdCard,
                    "passport" => DocumentKind::Passport,
                    "license" => DocumentKind::DriversLicence,
                    _ => DocumentKind::TaxNumber,
                };
            }
            "tax_number" => {
                identity.name = kind.to_string();
                document.kind = DocumentKind::TaxNumber;
            }
            _ => {
                // An id of a kind this version doesn't know: a note with every column.
                let mut fields = Vec::new();
                let mut notes = None;
                import_unmapped(&rec, &["name", ""], &mut fields, &mut notes, &["number"]);
                b.note(Note {
                    name: clean_name(rec.get("name")),
                    text: clean_notes(notes),
                    fields,
                    meta: Meta::default(),
                });
                continue;
            }
        }
        if kind == "passport" || kind == "license" {
            document.issued_on = dashlane_date(rec.get("issue_date"));
            document.expires_on = dashlane_date(rec.get("expiration_date"));
            document.issuing_country = nonblank(rec.get("place_of_issue"));
            mapped.extend(["issue_date", "expiration_date", "place_of_issue"]);
        }
        if kind == "license" {
            mapped.push("state");
            if let Some(state) = nonblank(rec.get("state")) {
                identity.address = Some(Address {
                    region: Some(state),
                    ..Address::default()
                });
            }
        }
        identity.documents.push(document);
        let mut notes = None;
        import_unmapped(&rec, &mapped, &mut identity.fields, &mut notes, &[]);
        identity.notes = clean_notes(notes);
        identity.name = clean_name(Some(&identity.name));
        b.identity(identity);
    }
}

fn personal_information(b: &mut Builder<'_>, table: &Table) {
    let names = table
        .records()
        .filter(|rec| rec.get("type") == Some("name"))
        .count();
    if names == 1 {
        personal_identity(b, table);
        return;
    }
    // Several people (or none): each row is a note.
    for rec in table.records() {
        let name = if rec.get("type") == Some("name") {
            let joined = format!(
                "{} {} {} {}",
                rec.get("title").unwrap_or(""),
                rec.get("first_name").unwrap_or(""),
                rec.get("middle_name").unwrap_or(""),
                rec.get("last_name").unwrap_or("")
            );
            joined.replacen("  ", " ", 1).trim().to_string()
        } else {
            rec.get("item_name").unwrap_or("").to_string()
        };
        let mut fields = Vec::new();
        let mut notes = None;
        for (key, value) in rec.pairs() {
            kvp(&mut fields, &mut notes, key, value, FieldKind::Text);
        }
        b.note(Note {
            name: clean_name(Some(&name)),
            text: clean_notes(notes),
            fields,
            meta: Meta::default(),
        });
    }
}

/// All the rows of a personal-information file as one identity.
fn personal_identity(b: &mut Builder<'_>, table: &Table) {
    const MAPPED: [&str; 15] = [
        "type",
        "title",
        "first_name",
        "middle_name",
        "last_name",
        "login",
        "email",
        "phone_number",
        "address",
        "country",
        "state",
        "city",
        "zip",
        "item_name",
        "",
    ];
    let mut identity = Identity::default();
    let mut notes = None;
    for rec in table.records() {
        let mut mapped: Vec<&str> = MAPPED.to_vec();
        match rec.get("type").unwrap_or("") {
            "name" => {
                let joined = format!(
                    "{} {} {}",
                    rec.get("first_name").unwrap_or(""),
                    rec.get("middle_name").unwrap_or(""),
                    rec.get("last_name").unwrap_or("")
                );
                set_names(&mut identity, &joined);
                identity.title = nonblank(rec.get("title"));
                identity.username = nonblank(rec.get("login"));
                if let Some(date) = dashlane_date(rec.get("date_of_birth")) {
                    identity.birth_date = Some(date);
                    mapped.push("date_of_birth");
                }
            }
            "email" => {
                if let Some(email) = nonblank(rec.get("email")) {
                    identity.email = Some(email);
                }
            }
            "number" => {
                if let Some(phone) = nonblank(rec.get("phone_number")) {
                    identity.phone = Some(phone);
                }
            }
            "address" => {
                let address = identity.address.get_or_insert_with(Address::default);
                if let Some(line) = nonblank(rec.get("address")) {
                    address.lines = vec![line];
                }
                address.city = nonblank(rec.get("city"));
                address.postal_code = nonblank(rec.get("zip"));
                address.region = nonblank(rec.get("state"));
                address.country = nonblank(rec.get("country"));
            }
            _ => {}
        }
        import_unmapped(&rec, &mapped, &mut identity.fields, &mut notes, &[]);
    }
    identity.notes = clean_notes(notes);
    let shown: Vec<&str> = [
        identity.given_name.as_deref(),
        identity.middle_name.as_deref(),
        identity.family_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    identity.name = clean_name(Some(&shown.join(" ")));
    b.identity(identity);
}

fn secure_notes(b: &mut Builder<'_>, table: &Table) {
    for rec in table.records() {
        let mut fields = Vec::new();
        let mut notes = nonblank(rec.get("note"));
        import_unmapped(&rec, &["title", "note", ""], &mut fields, &mut notes, &[]);
        b.note(Note {
            name: clean_name(rec.get("title")),
            text: clean_notes(notes),
            fields,
            meta: Meta::default(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::zip::build_stored_zip;

    const CREDENTIALS: &str = include_str!("../tests/fixtures/dashlane/credentials.csv");
    const PAYMENTS: &str = include_str!("../tests/fixtures/dashlane/payments.csv");
    const IDS: &str = include_str!("../tests/fixtures/dashlane/ids.csv");
    const PERSONAL: &str = include_str!("../tests/fixtures/dashlane/personalInfo.csv");
    const PERSONAL_MANY: &str = include_str!("../tests/fixtures/dashlane/personalInfo-many.csv");
    const NOTES: &str = include_str!("../tests/fixtures/dashlane/securenotes.csv");
    const ZIP: &[u8] = include_bytes!("../tests/fixtures/dashlane/export.zip");

    fn read(bytes: &[u8]) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(bytes, &Context::new(&limits))
    }

    fn field<'a>(fields: &'a [CustomField], name: &str) -> Option<&'a CustomField> {
        fields.iter().find(|f| f.name == name)
    }

    #[test]
    fn credentials_make_logins_in_folders_and_notes() {
        let batch = read(CREDENTIALS.as_bytes()).expect("batch");
        assert_eq!(batch.format, Format::DashlaneCsv);
        assert_eq!(batch.logins.len(), 2);
        let first = &batch.logins[0];
        assert_eq!(first.name, "Example");
        assert_eq!(first.username.as_deref(), Some("ada@example.com"));
        assert_eq!(first.password.as_deref(), Some("pw-1"));
        assert_eq!(first.notes.as_deref(), Some("Some note"));
        assert_eq!(first.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(first.uris[0].uri, "https://example.com");
        assert_eq!(first.meta.folder, Some(0));
        assert!(first.fields.is_empty());

        let second = &batch.logins[1];
        assert_eq!(second.name, "Mail, Inc");
        assert_eq!(second.uris[0].uri, "http://mail.example.org");
        assert_eq!(second.meta.folder, Some(1));
        assert_eq!(
            field(&second.fields, "username2").map(|f| f.value.as_str()),
            Some("alt1")
        );

        assert_eq!(batch.folders[1].path, "Work/Sub");
        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].name, "OnlyNote");
        assert_eq!(batch.notes[0].text.as_deref(), Some("just a note"));
    }

    #[test]
    fn payments_make_cards_and_bank_notes() {
        let batch = read(PAYMENTS.as_bytes()).expect("batch");
        assert_eq!(batch.cards.len(), 1);
        let card = &batch.cards[0];
        assert_eq!(card.name, "Everyday Visa");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        let names: Vec<&str> = card.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["country", "issuing_bank"]);

        assert_eq!(batch.notes.len(), 1);
        let bank = &batch.notes[0];
        assert_eq!(bank.name, "Main Account");
        assert_eq!(bank.fields.len(), 5);
        assert_eq!(
            field(&bank.fields, "account_number").map(|f| f.kind),
            Some(FieldKind::Hidden)
        );
        assert_eq!(
            field(&bank.fields, "account_holder").map(|f| f.kind),
            Some(FieldKind::Text)
        );
    }

    #[test]
    fn ids_make_identities_with_a_document() {
        let batch = read(IDS.as_bytes()).expect("batch");
        assert_eq!(batch.identities.len(), 5);
        let passport = &batch.identities[0];
        assert_eq!(passport.name, "Ada Lovelace passport");
        assert_eq!(passport.given_name.as_deref(), Some("Ada"));
        assert_eq!(passport.family_name.as_deref(), Some("Lovelace"));
        let doc = &passport.documents[0];
        assert_eq!(doc.kind, DocumentKind::Passport);
        assert_eq!(doc.number.as_deref(), Some("P1234567"));
        assert_eq!(doc.issued_on.as_deref(), Some("2020-01-05"));
        assert_eq!(doc.expires_on.as_deref(), Some("2030-01-05"));
        assert_eq!(doc.issuing_country.as_deref(), Some("UK"));
        assert!(passport.fields.is_empty());

        let licence = &batch.identities[1];
        assert_eq!(licence.name, "Grace Hopper license");
        assert_eq!(licence.documents[0].kind, DocumentKind::DriversLicence);
        assert_eq!(licence.documents[0].number.as_deref(), Some("D555"));
        assert_eq!(
            licence.address.as_ref().and_then(|a| a.region.as_deref()),
            Some("NY")
        );

        assert_eq!(
            batch.identities[2].documents[0].kind,
            DocumentKind::TaxNumber
        );
        assert_eq!(
            batch.identities[2].documents[0].number.as_deref(),
            Some("123-45-6789")
        );
        assert_eq!(batch.identities[3].documents[0].kind, DocumentKind::IdCard);
        assert_eq!(batch.identities[4].name, "tax_number");
        assert_eq!(
            batch.identities[4].documents[0].number.as_deref(),
            Some("TAX-1")
        );
    }

    #[test]
    fn one_name_row_makes_one_identity_of_the_whole_file() {
        let batch = read(PERSONAL.as_bytes()).expect("batch");
        assert_eq!(batch.identities.len(), 1);
        assert!(batch.notes.is_empty());
        let id = &batch.identities[0];
        assert_eq!(id.name, "Ada Lovelace");
        assert_eq!(id.title.as_deref(), Some("Ms"));
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.middle_name, None);
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.username.as_deref(), Some("ada_l"));
        assert_eq!(id.birth_date.as_deref(), Some("1815-12-10"));
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        assert_eq!(id.phone.as_deref(), Some("+44 20 7946 0000"));
        let address = id.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 Analytical Way"]);
        assert_eq!(address.city.as_deref(), Some("London"));
        assert_eq!(address.region.as_deref(), Some("England"));
        assert_eq!(address.postal_code.as_deref(), Some("N1 1AA"));
        assert_eq!(address.country.as_deref(), Some("GB"));
        let names: Vec<&str> = id.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["place_of_birth", "email_type"]);
    }

    #[test]
    fn several_name_rows_make_notes() {
        let batch = read(PERSONAL_MANY.as_bytes()).expect("batch");
        assert!(batch.identities.is_empty());
        assert_eq!(batch.notes.len(), 2);
        assert_eq!(batch.notes[0].name, "Mr Alan Turing");
        let names: Vec<&str> = batch.notes[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, ["type", "title", "first_name", "last_name", "login"]);
        assert_eq!(batch.notes[1].name, "Dr Grace Hopper");
    }

    #[test]
    fn secure_notes() {
        let batch = read(NOTES.as_bytes()).expect("batch");
        assert_eq!(batch.notes.len(), 2);
        assert_eq!(batch.notes[0].name, "Wifi");
        assert_eq!(
            batch.notes[0].text.as_deref(),
            Some("Network: home\nPassword: pw")
        );
        assert_eq!(batch.notes[1].name, "Empty");
        assert_eq!(batch.notes[1].text, None);
    }

    #[test]
    fn the_zip_is_read_file_by_file() {
        let batch = read(ZIP).expect("batch");
        assert_eq!(batch.format, Format::DashlaneZip);
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.identities.len(), 6);
        // OnlyNote, the bank account, and the two secure notes.
        assert_eq!(batch.notes.len(), 4);
        assert_eq!(batch.folders.len(), 2);
        assert!(batch.skipped.is_empty());
    }

    #[test]
    fn a_zip_skips_files_it_does_not_know_but_needs_one_it_does() {
        let zip = build_stored_zip(&[
            ("a/securenotes.csv", NOTES.as_bytes()),
            ("other.csv", &b"a,b\n1,2\n"[..]),
            ("readme.txt", &b"hello"[..]),
        ]);
        let batch = read(&zip).expect("batch");
        assert_eq!(batch.notes.len(), 2);
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::UnsupportedKind);
        assert_eq!(batch.skipped[0].name.as_deref(), Some("other.csv"));

        let none = build_stored_zip(&[("readme.txt", &b"hello"[..])]);
        assert_eq!(read(&none).err(), Some(ImportError::Unsupported));
        let unknown = build_stored_zip(&[("x.csv", &b"a,b\n1,2\n"[..])]);
        assert_eq!(read(&unknown).err(), Some(ImportError::Unsupported));
    }

    #[test]
    fn zip_limits_apply() {
        let zip = build_stored_zip(&[
            ("securenotes.csv", NOTES.as_bytes()),
            ("b.csv", &b"x\n1"[..]),
        ]);
        let limits = Limits {
            max_zip_entries: 1,
            ..Limits::default()
        };
        assert_eq!(
            parse(&zip, &Context::new(&limits)).err(),
            Some(ImportError::LimitExceeded("files in the ZIP"))
        );
        let limits = Limits {
            max_entry_bytes: 5,
            ..Limits::default()
        };
        assert!(matches!(
            parse(&zip, &Context::new(&limits)),
            Err(ImportError::LimitExceeded(_))
        ));
    }

    #[test]
    fn entries_over_the_limit_are_counted() {
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        let batch = parse(IDS.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 1);
        assert_eq!(batch.skipped_count(), 4);
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read(b"").err(), Some(ImportError::Unsupported));
        assert_eq!(read(b"a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read(b"username,password\n").err(), Some(ImportError::Empty));
        let limits = Limits::small();
        let big = vec![b'a'; limits.max_input_bytes + 1];
        assert!(matches!(
            parse(&big, &Context::new(&limits)),
            Err(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn dates() {
        assert_eq!(
            dashlane_date(Some("2020-1-5")).as_deref(),
            Some("2020-01-05")
        );
        assert_eq!(dashlane_date(Some("2020-01")), None);
        assert_eq!(dashlane_date(Some("2020-01-02-03")), None);
        assert_eq!(dashlane_date(Some("--")), None);
        assert_eq!(dashlane_date(None), None);
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "username,title\n\"unterminated",
            "type,account_name\ncredit_card\n,,,",
            "type,number\n\u{0}",
            "type,title\nname",
            "title,note\n,",
            "PK\u{3}\u{4}garbage",
        ] {
            let _ = read(text.as_bytes());
        }
    }
}
