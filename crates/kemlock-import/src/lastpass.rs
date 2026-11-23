// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/lastpass/lastpass-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! LastPass CSV (`url,username,password,totp,extra,name,grouping,fav`), the only way in: there is
//! no direct account import. Secure notes are entries whose address is `http://sn`; their `extra`
//! column holds `NoteType:` and `key:value` lines, which become a card (Credit Card), an identity
//! (Address, Passport, Driver's License) or a note with fields (Bank Account, others). The form-fill
//! export (`profilename,profilelanguage,...`) gives identities and cards; an identity with a card
//! number also yields a card.

use std::collections::HashMap;

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, Record, read_table};
use crate::error::{ImportError, Result};
use crate::model::{
    Address, Card, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity, ImportBatch,
    Login, Meta, Note,
};
use crate::util::{
    card_brand, card_number, clean_notes, full_name, is_blank, kvp, make_uris, nonblank,
    or_default, parse_month, parse_year, split_newlines,
};

const MONTHS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

/// LastPass writes dates as `June,20,2020` and expiries as `June,2020`: a month number from the
/// name, or from its first letters.
fn month_from_name(name: &str) -> Option<u8> {
    let lower = name.trim().to_lowercase();
    if lower.len() < 3 {
        return None;
    }
    let at = MONTHS.iter().position(|m| m.starts_with(lower.as_str()))?;
    u8::try_from(at + 1).ok()
}

/// `June,20,2020` as `2020-06-20`; `None` when a part is missing or not a date.
fn parse_full_date(text: &str) -> Option<String> {
    let mut parts = text.split(',');
    let month = month_from_name(parts.next()?)?;
    let day: u8 = parts.next()?.trim().parse().ok()?;
    let year: u16 = parts.next()?.trim().parse().ok()?;
    if !(1..=31).contains(&day) || year > 9999 {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn up_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// What a secure note's `extra` lines gave.
#[derive(Debug, Default)]
struct Mapped {
    /// The values of the keys asked for, by key.
    values: HashMap<String, String>,
    fields: Vec<CustomField>,
    notes: Option<String>,
}

impl Mapped {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).filter(|v| !is_blank(v)).cloned()
    }
}

/// `parseSecureNoteMapping`: the `key:value` lines, keeping the values of `known` keys, putting the
/// other keys into custom fields (or the note, as `kvp` does) and everything from a `Notes:` line
/// on into the note.
fn map_note(lines: &[&str], known: &[&str]) -> Mapped {
    let mut out = Mapped::default();
    let mut in_notes = false;
    for line in lines {
        if in_notes {
            let notes = out.notes.get_or_insert_with(String::new);
            notes.push('\n');
            notes.push_str(line);
            continue;
        }
        if is_blank(line) {
            continue;
        }
        let (key, value) = match line.find(':') {
            Some(at) => (&line[..at], &line[at + 1..]),
            None => (*line, ""),
        };
        if is_blank(key) || is_blank(value) || key == "NoteType" {
            continue;
        }
        if key == "Notes" {
            if out.notes.as_deref().is_some_and(|n| !is_blank(n)) {
                if let Some(notes) = out.notes.as_mut() {
                    notes.push('\n');
                    notes.push_str(value);
                }
            } else {
                out.notes = Some(value.to_string());
            }
            in_notes = true;
        } else if known.contains(&key) {
            out.values.insert(key.to_string(), value.to_string());
        } else {
            kvp(&mut out.fields, &mut out.notes, key, value, FieldKind::Text);
        }
    }
    out
}

fn card_from_record(record: &Record<'_>) -> Card {
    let number = record.get("ccnum").and_then(card_number);
    let mut card = Card {
        cardholder: nonblank(record.get("ccname")),
        code: nonblank(record.get("cccsc")),
        brand: number.as_deref().and_then(card_brand),
        number,
        ..Card::default()
    };
    // `2029-06`: the year, then the month.
    if let Some(expiry) = record.get("ccexp").filter(|e| !is_blank(e))
        && let Some((year, month)) = expiry.split_once('-')
    {
        card.exp_year = parse_year(year);
        card.exp_month = parse_month(month);
    }
    card
}

fn identity_from_record(record: &Record<'_>) -> Identity {
    let text = |key: &str| nonblank(record.get(key));
    let lines: Vec<String> = ["address1", "address2", "address3"]
        .iter()
        .filter_map(|&k| text(k))
        .collect();
    let (city, region, postal_code, country) =
        (text("city"), text("state"), text("zip"), text("country"));
    let address = if lines.is_empty()
        && city.is_none()
        && region.is_none()
        && postal_code.is_none()
        && country.is_none()
    {
        None
    } else {
        Some(Address {
            lines,
            city,
            region,
            postal_code,
            country,
        })
    };
    let mut documents = Vec::new();
    if let Some(number) = text("ssn") {
        documents.push(IdDocument {
            kind: DocumentKind::TaxNumber,
            number: Some(number),
            ..IdDocument::default()
        });
    }
    Identity {
        title: text("title").map(|t| up_first(&t)),
        given_name: text("firstname"),
        middle_name: text("middlename"),
        family_name: text("lastname"),
        company: text("company"),
        email: text("email"),
        phone: text("phone"),
        username: text("username"),
        address,
        documents,
        ..Identity::default()
    }
}

/// Reads a LastPass CSV export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    let form_fill = table.has("profilename") && table.has("profilelanguage");
    let site_list = table.has("url") && (table.has("extra") || table.has("grouping"));
    if !(form_fill || site_list) {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::LastPassCsv, ctx.limits);
    for record in table.records() {
        // `grouping`: backslashes are separators, control characters are dropped, `(none)` is no
        // folder.
        let grouping: String = record
            .get("grouping")
            .unwrap_or("")
            .replace('\\', "/")
            .chars()
            .filter(|c| !matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
            .collect();
        let folder = if grouping.trim().is_empty() || grouping == "(none)" {
            None
        } else {
            b.folder(&grouping)
        };
        let mut meta = Meta {
            folder,
            ..Meta::default()
        };

        if form_fill {
            let name = or_default(record.get("profilename"), "--");
            let notes = clean_notes(nonblank(record.get("notes")));
            let is_identity = [
                "title",
                "firstname",
                "lastname",
                "address1",
                "phone",
                "username",
                "email",
            ]
            .iter()
            .any(|k| nonblank(record.get(k)).is_some());
            if is_identity {
                if nonblank(record.get("ccnum")).is_some() {
                    b.card(Card {
                        name: name.clone(),
                        meta: meta.clone(),
                        ..card_from_record(&record)
                    });
                }
                b.identity(Identity {
                    name,
                    notes,
                    meta,
                    ..identity_from_record(&record)
                });
            } else {
                b.card(Card {
                    name,
                    notes,
                    meta,
                    ..card_from_record(&record)
                });
            }
            continue;
        }

        meta.favorite = record.get("fav") == Some("1");
        let name = or_default(record.get("name"), "--");
        let extra = record.get("extra").unwrap_or("");
        if record.get("url") == Some("http://sn") {
            read_note(&mut b, name, extra, meta);
        } else {
            b.login(Login {
                name,
                uris: make_uris(record.get("url")),
                username: nonblank(record.get("username")),
                password: nonblank(record.get("password")),
                totp: nonblank(record.get("totp")),
                notes: clean_notes(nonblank(Some(extra))),
                meta,
                ..Login::default()
            });
        }
    }
    b.note_unread(table.unread);
    b.finish()
}

fn read_note(b: &mut Builder<'_>, name: String, extra: &str, meta: Meta) {
    let lines = split_newlines(extra);
    let kind: Option<&str> = lines.first().and_then(|first| {
        let parts: Vec<&str> = first.split(':').collect();
        if parts.len() > 1 && parts[0] == "NoteType" {
            Some(parts[1])
        } else {
            None
        }
    });
    match kind {
        Some("Credit Card") => {
            let m = map_note(
                &lines,
                &["Number", "Name on Card", "Security Code", "Expiration Date"],
            );
            let number = m.get("Number").and_then(|n| card_number(&n));
            let mut card = Card {
                name,
                cardholder: m.get("Name on Card"),
                code: m.get("Security Code"),
                brand: number.as_deref().and_then(card_brand),
                number,
                notes: clean_notes(m.notes.clone()),
                fields: m.fields.clone(),
                meta,
                ..Card::default()
            };
            // `June,2020`
            if let Some(expiry) = m.get("Expiration Date").filter(|e| e.trim() != ",")
                && let Some((month, year)) = expiry.split_once(',')
            {
                card.exp_month = month_from_name(month);
                card.exp_year = parse_year(year);
            }
            b.card(card);
        }
        Some("Address") => {
            let m = map_note(
                &lines,
                &[
                    "Title",
                    "First Name",
                    "Last Name",
                    "Middle Name",
                    "Company",
                    "Address 1",
                    "Address 2",
                    "Address 3",
                    "City / Town",
                    "State",
                    "Zip / Postal Code",
                    "Country",
                    "Email Address",
                    "Username",
                ],
            );
            let lines: Vec<String> = ["Address 1", "Address 2", "Address 3"]
                .iter()
                .filter_map(|k| m.get(k))
                .collect();
            let (city, region, postal_code, country) = (
                m.get("City / Town"),
                m.get("State"),
                m.get("Zip / Postal Code"),
                m.get("Country"),
            );
            let address = if lines.is_empty()
                && city.is_none()
                && region.is_none()
                && postal_code.is_none()
                && country.is_none()
            {
                None
            } else {
                Some(Address {
                    lines,
                    city,
                    region,
                    postal_code,
                    country,
                })
            };
            b.identity(Identity {
                name,
                title: m.get("Title"),
                given_name: m.get("First Name"),
                middle_name: m.get("Middle Name"),
                family_name: m.get("Last Name"),
                company: m.get("Company"),
                email: m.get("Email Address"),
                username: m.get("Username"),
                address,
                notes: clean_notes(m.notes.clone()),
                fields: m.fields.clone(),
                meta,
                ..Identity::default()
            });
        }
        Some("Passport") => {
            let m = map_note(
                &lines,
                &[
                    "Type",
                    "Name",
                    "Country",
                    "Number",
                    "Nationality",
                    "Issuing Authority",
                    "Date of Birth",
                    "Issued Date",
                    "Expiration Date",
                ],
            );
            let (given, middle, family) = m
                .get("Name")
                .map(|n| full_name(&n))
                .unwrap_or((None, None, None));
            let mut fields = m.fields.clone();
            for key in ["Type", "Nationality"] {
                if let Some(value) = m.get(key) {
                    fields.push(CustomField {
                        name: key.to_string(),
                        value,
                        kind: FieldKind::Text,
                    });
                }
            }
            b.identity(Identity {
                name,
                given_name: given,
                middle_name: middle,
                family_name: family,
                birth_date: m.get("Date of Birth").and_then(|d| parse_full_date(&d)),
                documents: vec![IdDocument {
                    kind: DocumentKind::Passport,
                    number: m.get("Number"),
                    issuing_country: m.get("Country"),
                    issuing_authority: m.get("Issuing Authority"),
                    issued_on: m.get("Issued Date").and_then(|d| parse_full_date(&d)),
                    expires_on: m.get("Expiration Date").and_then(|d| parse_full_date(&d)),
                }],
                notes: clean_notes(m.notes.clone()),
                fields,
                meta,
                ..Identity::default()
            });
        }
        Some("Driver's License") => {
            let m = map_note(
                &lines,
                &[
                    "Number",
                    "Expiration Date",
                    "License Class",
                    "Name",
                    "State",
                    "Country",
                    "Date of Birth",
                ],
            );
            let (given, middle, family) = m
                .get("Name")
                .map(|n| full_name(&n))
                .unwrap_or((None, None, None));
            let mut fields = m.fields.clone();
            if let Some(value) = m.get("License Class") {
                fields.push(CustomField {
                    name: "License Class".to_string(),
                    value,
                    kind: FieldKind::Text,
                });
            }
            b.identity(Identity {
                name,
                given_name: given,
                middle_name: middle,
                family_name: family,
                birth_date: m.get("Date of Birth").and_then(|d| parse_full_date(&d)),
                documents: vec![IdDocument {
                    kind: DocumentKind::DriversLicence,
                    number: m.get("Number"),
                    issuing_country: m.get("Country"),
                    issuing_authority: m.get("State"),
                    issued_on: None,
                    expires_on: m.get("Expiration Date").and_then(|d| parse_full_date(&d)),
                }],
                notes: clean_notes(m.notes.clone()),
                fields,
                meta,
                ..Identity::default()
            });
        }
        Some("Bank Account") => {
            let keys = [
                "Bank Name",
                "Account Type",
                "Routing Number",
                "Account Number",
                "SWIFT Code",
                "IBAN Number",
                "Pin",
                "Branch Phone",
                "Branch Address",
            ];
            let m = map_note(&lines, &keys);
            let mut fields = Vec::new();
            for key in keys {
                if let Some(value) = m.get(key) {
                    let hidden = matches!(
                        key,
                        "Routing Number" | "Account Number" | "IBAN Number" | "Pin"
                    );
                    fields.push(CustomField {
                        name: key.to_string(),
                        value,
                        kind: if hidden {
                            FieldKind::Hidden
                        } else {
                            FieldKind::Text
                        },
                    });
                }
            }
            fields.extend(m.fields.iter().cloned());
            b.note(Note {
                name,
                text: clean_notes(m.notes.clone()),
                fields,
                meta,
            });
        }
        _ => {
            b.note(Note {
                name,
                text: clean_notes(nonblank(Some(extra))),
                fields: Vec::new(),
                meta,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const NOTES: &str = include_str!("../tests/fixtures/lastpass/export.csv");
    const FORM: &str = include_str!("../tests/fixtures/lastpass/formfill.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_a_login_with_its_folder_totp_and_favourite() {
        let batch = read(NOTES).expect("batch");
        assert_eq!(batch.logins.len(), 1);
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example");
        assert_eq!(login.uris[0].uri, "https://example.com");
        assert_eq!(login.username.as_deref(), Some("ada"));
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(login.notes.as_deref(), Some("site note"));
        assert!(login.meta.favorite);
        assert_eq!(
            batch.folders[login.meta.folder.expect("folder")].path,
            "Work/Sub"
        );
        assert_eq!(batch.folders.len(), 3);
    }

    #[test]
    fn a_credit_card_note_is_a_card() {
        let batch = read(NOTES).expect("batch");
        assert_eq!(batch.cards.len(), 1);
        let card = &batch.cards[0];
        assert_eq!(card.name, "Visa note");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(6), Some(2029)));
        assert_eq!(card.notes.as_deref(), Some("card note\nsecond line"));
        let names: Vec<&str> = card.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Type", "Start Date"]);
        assert_eq!(card.fields[1].value, "January,2020");
        assert_eq!(card.meta.folder, None);
    }

    #[test]
    fn address_passport_and_bank_notes_map_to_kemlock_kinds() {
        let batch = read(NOTES).expect("batch");
        assert_eq!(batch.identities.len(), 2);
        let home = &batch.identities[0];
        assert_eq!(home.name, "Home");
        assert_eq!(home.given_name.as_deref(), Some("Ada"));
        assert_eq!(home.email.as_deref(), Some("ada@example.com"));
        let address = home.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 St"]);
        assert_eq!(address.city.as_deref(), Some("London"));
        assert_eq!(address.postal_code.as_deref(), Some("N1"));
        assert_eq!(home.fields[0].name, "Phone");

        let passport = &batch.identities[1];
        assert_eq!(passport.given_name.as_deref(), Some("Ada"));
        assert_eq!(passport.middle_name.as_deref(), Some("Augusta"));
        assert_eq!(passport.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(passport.birth_date.as_deref(), Some("1815-12-10"));
        assert_eq!(passport.documents[0].kind, DocumentKind::Passport);
        assert_eq!(passport.documents[0].number.as_deref(), Some("P1"));
        assert_eq!(
            passport.documents[0].expires_on.as_deref(),
            Some("2035-06-20")
        );

        let bank = batch.notes.iter().find(|n| n.name == "Bank").expect("bank");
        assert_eq!(bank.fields[0].name, "Bank Name");
        assert_eq!(bank.fields[1].name, "Account Number");
        assert_eq!(bank.fields[1].kind, FieldKind::Hidden);
        assert_eq!(bank.text.as_deref(), Some("n"));
    }

    #[test]
    fn other_notes_stay_notes() {
        let batch = read(NOTES).expect("batch");
        let plain = batch
            .notes
            .iter()
            .find(|n| n.name == "Plain note")
            .expect("note");
        assert_eq!(plain.text.as_deref(), Some("just a note\nmore"));
    }

    #[test]
    fn the_form_fill_export_gives_identities_and_cards() {
        let batch = read(FORM).expect("batch");
        assert_eq!(batch.identities.len(), 1);
        assert_eq!(batch.cards.len(), 2);
        // The identity's card comes first.
        assert_eq!(batch.cards[0].name, "Home");
        assert_eq!(batch.cards[0].number.as_deref(), Some("5555555555554444"));
        assert_eq!(batch.cards[0].brand.as_deref(), Some("Mastercard"));
        assert_eq!(
            (batch.cards[0].exp_month, batch.cards[0].exp_year),
            (Some(7), Some(2030))
        );
        let who = &batch.identities[0];
        assert_eq!(who.title.as_deref(), Some("Mr"));
        assert_eq!(who.given_name.as_deref(), Some("Alan"));
        assert_eq!(who.notes.as_deref(), Some("form note"));
        assert_eq!(who.documents[0].kind, DocumentKind::TaxNumber);
        let address = who.address.as_ref().expect("address");
        assert_eq!(address.region.as_deref(), Some("Bucks"));
        assert_eq!(batch.cards[1].name, "Cardonly");
        assert_eq!(
            (batch.cards[1].exp_month, batch.cards[1].exp_year),
            (Some(1), Some(2028))
        );
    }

    #[test]
    fn dates_and_months() {
        assert_eq!(month_from_name("June"), Some(6));
        assert_eq!(month_from_name("sept"), Some(9));
        assert_eq!(month_from_name("Ma"), None);
        assert_eq!(month_from_name("Smarch"), None);
        assert_eq!(
            parse_full_date("June,20,2020").as_deref(),
            Some("2020-06-20")
        );
        assert_eq!(parse_full_date("June,2020"), None);
        assert_eq!(parse_full_date(",,"), None);
        assert_eq!(parse_full_date("June,40,2020"), None);
    }

    #[test]
    fn note_lines_map_known_keys_and_spill_the_rest() {
        let m = map_note(
            &[
                "NoteType:X",
                "Known:1",
                "Other:2",
                "",
                "bad",
                "Empty:",
                "Notes:first",
                "Notes:later",
                "tail",
            ],
            &["Known"],
        );
        assert_eq!(m.get("Known").as_deref(), Some("1"));
        assert_eq!(m.fields.len(), 1);
        assert_eq!(m.fields[0].name, "Other");
        assert_eq!(m.notes.as_deref(), Some("first\nNotes:later\ntail"));
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read("url,extra,name\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "url,extra\nhttp://sn,\"NoteType:Credit Card\nExpiration Date:,\"",
            "url,extra\nhttp://sn,NoteType:Passport\nhttp://sn,:::",
            "url,extra\nhttp://sn,\"NoteType:Address\nAddress 1:\u{0}\"",
        ] {
            let _ = read(text);
        }
    }
}
