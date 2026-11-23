// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/nordpass-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! NordPass CSV: `name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,
//! expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,
//! type,custom_fields`. `type` is `password`, `credit_card`, `note` or `identity`; `additional_urls`
//! and `custom_fields` hold JSON.

use serde_json::Value;

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, Record, read_table};
use crate::error::{ImportError, Result};
use crate::model::{
    Address, Card, CustomField, FieldKind, Format, Identity, ImportBatch, Login, Meta, Note,
    SkipReason,
};
use crate::util::{
    card_brand, card_number, clean_notes, full_name, jstr, kvp, make_uris, nonblank, or_default,
    set_card_expiration,
};

/// `custom_fields`: a JSON array of `{label, type, value}`; `hidden` ones are hidden. A cell that
/// isn't that JSON gives no fields (Bitwarden's importer fails the whole file on it).
fn custom_fields(cell: &str, notes: &mut Option<String>) -> Vec<CustomField> {
    let mut fields = Vec::new();
    let Ok(Value::Array(list)) = serde_json::from_str::<Value>(cell) else {
        return fields;
    };
    for field in &list {
        let kind = if jstr(field, "type") == Some("hidden") {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        kvp(
            &mut fields,
            notes,
            jstr(field, "label").unwrap_or(""),
            jstr(field, "value").unwrap_or(""),
            kind,
        );
    }
    fields
}

/// `additional_urls`: a JSON array of addresses.
fn additional_urls(cell: &str) -> Vec<String> {
    match serde_json::from_str::<Value>(cell) {
        Ok(Value::Array(list)) => list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn read_record(b: &mut Builder<'_>, record: &Record<'_>) {
    let kind = record.get("type").unwrap_or("");
    let title = record.get("name");
    if !matches!(kind, "password" | "credit_card" | "note" | "identity") {
        b.skip(title, SkipReason::UnsupportedKind, Some(kind));
        return;
    }
    let meta = Meta {
        folder: record.get("folder").and_then(|f| b.folder(f)),
        ..Meta::default()
    };
    let name = or_default(title, "--");
    let mut notes = clean_notes(nonblank(record.get("note")));
    let fields = record
        .get("custom_fields")
        .filter(|c| !c.trim().is_empty())
        .map(|c| custom_fields(c, &mut notes))
        .unwrap_or_default();
    let notes = clean_notes(notes);
    let text = |key: &str| nonblank(record.get(key));

    match kind {
        "password" => {
            let mut urls: Vec<String> = Vec::new();
            urls.extend(record.get("url").map(str::to_string));
            if let Some(cell) = record
                .get("additional_urls")
                .filter(|c| !c.trim().is_empty())
            {
                urls.extend(additional_urls(cell));
            }
            b.login(Login {
                name,
                uris: make_uris(urls.iter().map(String::as_str)),
                username: text("username"),
                password: text("password"),
                notes,
                fields,
                meta,
                ..Login::default()
            });
        }
        "credit_card" => {
            let number = record.get("cardnumber").and_then(card_number);
            let mut card = Card {
                name,
                cardholder: text("cardholdername"),
                code: text("cvc"),
                brand: number.as_deref().and_then(card_brand),
                number,
                notes,
                fields,
                meta,
                ..Card::default()
            };
            if let Some(expiry) = record.get("expirydate") {
                set_card_expiration(&mut card, expiry);
            }
            b.card(card);
        }
        "identity" => {
            let (given, middle, family) = text("full_name")
                .map(|n| full_name(&n))
                .unwrap_or((None, None, None));
            let lines: Vec<String> = ["address1", "address2"]
                .iter()
                .filter_map(|&k| text(k))
                .collect();
            let (city, region, postal_code, country) = (
                text("city"),
                text("state"),
                text("zipcode"),
                text("country").map(|c| c.to_uppercase()),
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
                given_name: given,
                middle_name: middle,
                family_name: family,
                email: text("email"),
                phone: text("phone_number"),
                address,
                notes,
                fields,
                meta,
                ..Identity::default()
            });
        }
        _ => {
            b.note(Note {
                name,
                text: notes,
                fields,
                meta,
            });
        }
    }
}

/// Reads a NordPass export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if !table.has("type") || !table.has("name") {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::NordPassCsv, ctx.limits);
    for record in table.records() {
        read_record(&mut b, &record);
    }
    b.note_unread(table.unread);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const EXPORT: &str = include_str!("../tests/fixtures/nordpass/export.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_a_login_with_extra_urls_fields_and_a_folder() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.logins.len(), 1);
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example");
        let uris: Vec<&str> = login.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(uris, ["https://example.com", "https://example.net"]);
        assert_eq!(login.username.as_deref(), Some("ada@example.com"));
        assert_eq!(login.password.as_deref(), Some("pw1"));
        assert_eq!(login.notes.as_deref(), Some("a note"));
        assert_eq!(login.fields.len(), 2);
        assert_eq!(login.fields[0].name, "Account");
        assert_eq!(login.fields[1].kind, FieldKind::Hidden);
        assert_eq!(
            batch.folders[login.meta.folder.expect("folder")].name,
            "Family"
        );
    }

    #[test]
    fn reads_cards_identities_and_notes() {
        let batch = read(EXPORT).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));

        let id = &batch.identities[0];
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        let address = id.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 St", "Flat 2"]);
        assert_eq!(address.country.as_deref(), Some("GB"));

        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].text.as_deref(), Some("remember"));
    }

    #[test]
    fn other_types_are_skipped_and_damaged_json_is_ignored() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].detail.as_deref(), Some("passkey"));
        let text = "name,type,custom_fields,additional_urls,url\nX,password,not json,[also not,https://x.example\n";
        let batch = read(text).expect("batch");
        assert_eq!(batch.logins[0].fields.len(), 0);
        assert_eq!(batch.logins[0].uris.len(), 1);
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read("name,type\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "name,type,custom_fields\nx,password,\"[{\"\"label\"\":1}]\"",
            "name,type,expirydate\nx,credit_card,///",
            "name,type\n\u{0},identity",
        ] {
            let _ = read(text);
        }
    }
}
