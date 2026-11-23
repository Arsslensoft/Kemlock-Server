// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/onepassword/onepassword-csv-importer.ts,
//   onepassword-mac-csv-importer.ts and onepassword-win-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! 1Password CSV, from the Mac app or the Windows app. The two differ in their columns: the Windows
//! export has capitalised `UUID` and `TITLE` columns and numbered ones (`2: NUMBER`,
//! `NAME 1: FIRST NAME`), the Mac export has a `Type` column.
//!
//! Each row is a login, a card or an identity (a login with nothing to sign in with is a note).
//! Columns that are not known become custom fields; a long or tall value goes to the note. Where
//! Bitwarden's code drops data, this keeps it: the `URL` column adds to the addresses (Bitwarden's
//! `concat` result is discarded), a column holding an email is kept as the username when nothing
//! else claims it, and the note is trimmed.

use std::collections::HashSet;

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, Record, read_table};
use crate::error::{ImportError, Result};
use crate::model::{
    Card, CustomField, FieldKind, Format, Identity, ImportBatch, Login, Meta, Note,
};
use crate::onepassword::utc_string;
use crate::util::{
    card_brand, card_number, clean_name, clean_notes, is_blank, is_noteworthy_login, kvp,
    make_uris, nonblank, parse_month, parse_year, split_newlines,
};

/// Columns that are read elsewhere or not kept (`IgnoredProperties`).
const IGNORED: [&str; 9] = [
    "ainfo",
    "autosubmit",
    "notesplain",
    "ps",
    "scope",
    "tags",
    "title",
    "uuid",
    "notes",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Mac,
    Windows,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Card,
    Identity,
}

/// What a row is turned into while its columns are read.
struct Row {
    kind: Kind,
    login: Login,
    card: Card,
    identity: Identity,
    notes: Option<String>,
    fields: Vec<CustomField>,
    alt_username: Option<String>,
    /// The addresses in `login`, so a hostile list of them stays linear.
    seen_uris: HashSet<String>,
}

fn blank_opt(o: &Option<String>) -> bool {
    o.as_deref().is_none_or(is_blank)
}

/// Whether `key` (lower case) has `prefix`, digits, then `suffix` anywhere in it: the
/// `/prefix\d+suffix/i` Bitwarden tests Windows columns with.
fn matches_numbered(key: &str, prefix: &str, suffix: &str) -> bool {
    // Found from each place the suffix occurs, looking back over the digits to the prefix, so a
    // long run of digits costs one pass.
    key.match_indices(suffix).any(|(at, _)| {
        let before = key.get(..at).unwrap_or("");
        let without_digits = before.trim_end_matches(|c: char| c.is_ascii_digit());
        without_digits.len() < before.len() && without_digits.ends_with(prefix)
    })
}

/// The value of the first column matching `prefix`, digits, `suffix` (`getPropByRegexp`).
fn value_by_pattern<'a>(record: &Record<'a>, prefix: &str, suffix: &str) -> Option<&'a str> {
    record
        .pairs()
        .find(|(name, _)| matches_numbered(&name.to_lowercase(), prefix, suffix))
        .map(|(_, value)| value)
}

fn present(value: Option<&str>) -> bool {
    value.is_some_and(|v| !is_blank(v))
}

fn kind_of(variant: Variant, record: &Record<'_>) -> (Kind, bool) {
    match variant {
        Variant::Mac => {
            let one_password_type = match record.get_ci("type") {
                Some(t) if !is_blank(t) => t,
                _ => "Login",
            };
            match one_password_type {
                "Credit Card" => (Kind::Card, true),
                "Identity" => (Kind::Identity, true),
                "Login" | "Secure Note" => (Kind::Login, true),
                _ => (Kind::Login, false),
            }
        }
        Variant::Windows => {
            let mut kind = Kind::Login;
            if present(value_by_pattern(record, "", ": number"))
                && present(value_by_pattern(record, "", ": expiry date"))
            {
                kind = Kind::Card;
            }
            if present(value_by_pattern(record, "name ", ": first name"))
                || present(value_by_pattern(record, "name ", ": initial"))
                || present(value_by_pattern(record, "name ", ": last name"))
                || present(value_by_pattern(record, "internet ", ": email"))
            {
                kind = Kind::Identity;
            }
            (kind, false)
        }
    }
}

fn known_login(row: &mut Row, lower: &str, value: &str) -> bool {
    if blank_opt(&row.login.username) && lower == "username" {
        row.login.username = Some(value.to_string());
        return true;
    }
    if blank_opt(&row.login.password) && lower == "password" {
        row.login.password = Some(value.to_string());
        return true;
    }
    if lower == "urls" || lower == "url" {
        for uri in make_uris(split_newlines(value)) {
            if row.seen_uris.insert(uri.uri.clone()) {
                row.login.uris.push(uri);
            }
        }
        return true;
    }
    false
}

fn known_card(variant: Variant, row: &mut Row, lower: &str, value: &str) -> bool {
    if row.card.number.is_none() && lower.contains("number") && !lower.contains("verification") {
        let number = card_number(value);
        row.card.brand = number.as_deref().and_then(card_brand);
        row.card.number = number;
        return true;
    }
    if row.card.code.is_none() && lower.contains("verification number") {
        row.card.code = Some(value.to_string());
        return true;
    }
    if row.card.cardholder.is_none() && lower.contains("cardholder name") {
        row.card.cardholder = Some(value.to_string());
        return true;
    }
    if row.card.exp_year.is_none() && lower.contains("expiry date") {
        return match variant {
            Variant::Mac => {
                // `MM/YYYY`, exactly seven characters.
                let chars: Vec<char> = value.chars().collect();
                if chars.len() != 7 {
                    return false;
                }
                let month: String = chars[0..2].iter().collect();
                let year: String = chars[3..7].iter().collect();
                row.card.exp_month = parse_month(&month);
                row.card.exp_year = parse_year(&year);
                row.card.exp_month.is_some() || row.card.exp_year.is_some()
            }
            Variant::Windows => {
                // `M/D/YYYY h:mm AM`: the month is first, the year is the third part.
                let parts: Vec<&str> = value.split('/').collect();
                if parts.len() < 3 {
                    return false;
                }
                let year: String = parts[2].trim().chars().take(4).collect();
                row.card.exp_month = parse_month(parts[0]);
                row.card.exp_year = parse_year(&year);
                row.card.exp_month.is_some() || row.card.exp_year.is_some()
            }
        };
    }
    false
}

fn known_identity(variant: Variant, row: &mut Row, lower: &str, value: &str) -> bool {
    let id = &mut row.identity;
    if blank_opt(&id.given_name) && lower.contains("first name") {
        id.given_name = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.middle_name) && lower.contains("initial") {
        id.middle_name = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.family_name) && lower.contains("last name") {
        id.family_name = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.username) && lower.contains("username") {
        id.username = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.email) && lower.contains("email") {
        id.email = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.phone) && lower.contains("default phone") {
        id.phone = Some(value.to_string());
        return true;
    }
    if blank_opt(&id.company) && lower.contains("company") {
        id.company = Some(value.to_string());
        return true;
    }
    if variant == Variant::Windows && matches_numbered(lower, "address ", ": address") {
        kvp(
            &mut row.fields,
            &mut row.notes,
            "address",
            value,
            FieldKind::Text,
        );
        return true;
    }
    false
}

/// A column that is none of the kind's known ones.
fn unknown(row: &mut Row, property: &str, lower: &str, value: &str, ignore_type: bool) {
    if IGNORED.contains(&lower)
        || (ignore_type && lower == "type")
        || lower.starts_with("section:")
        || lower.starts_with("section ")
    {
        return;
    }
    if row.alt_username.is_none() && lower == "email" {
        row.alt_username = Some(value.to_string());
        return;
    }
    if lower == "created date" || lower == "modified date" {
        // `parseInt`: the leading digits.
        let digits: String = value
            .trim()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(seconds) = digits.parse::<i64>() {
            let name = format!("1Password {property}");
            kvp(
                &mut row.fields,
                &mut row.notes,
                &name,
                &utc_string(seconds),
                FieldKind::Text,
            );
        }
        return;
    }
    let kind = if lower.contains("password") || lower.contains("key") || lower.contains("secret") {
        FieldKind::Hidden
    } else {
        FieldKind::Text
    };
    kvp(&mut row.fields, &mut row.notes, property, value, kind);
}

/// `notesPlain` and `notes`, one after the other.
fn base_notes(record: &Record<'_>) -> Option<String> {
    let parts: Vec<&str> = [record.get_ci("notesplain"), record.get_ci("notes")]
        .into_iter()
        .flatten()
        .filter(|s| !is_blank(s))
        .collect();
    if parts.is_empty() {
        None
    } else {
        // What the columns spill into the note starts on a new line.
        Some(format!("{}\n", parts.join("\n").trim()))
    }
}

/// Reads a 1Password CSV export, from the Mac or the Windows app.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(
        bytes,
        ctx,
        CsvOptions {
            backslash_escape: true,
        },
    )?;
    if !table.has_ci("title") {
        return Err(ImportError::Unsupported);
    }
    let variant = if table.has("TITLE") {
        Variant::Windows
    } else {
        Variant::Mac
    };
    let mut b = Builder::new(Format::OnePasswordCsv, ctx.limits);
    for record in table.records() {
        let title = record.get_ci("title").unwrap_or("");
        if is_blank(title) {
            continue;
        }
        let (kind, ignore_type) = kind_of(variant, &record);
        let mut row = Row {
            kind,
            login: Login::default(),
            card: Card::default(),
            identity: Identity::default(),
            notes: base_notes(&record),
            fields: Vec::new(),
            alt_username: None,
            seen_uris: HashSet::new(),
        };
        for (property, value) in record.pairs() {
            if is_blank(value) {
                continue;
            }
            let lower = property.to_lowercase();
            let known = match row.kind {
                Kind::Login => known_login(&mut row, &lower, value),
                Kind::Card => known_card(variant, &mut row, &lower, value),
                Kind::Identity => known_identity(variant, &mut row, &lower, value),
            };
            if !known {
                unknown(&mut row, property, &lower, value, ignore_type);
            }
        }
        if row.kind == Kind::Login
            && blank_opt(&row.login.username)
            && let Some(alt) = row.alt_username.as_deref()
            && !is_blank(alt)
            && !alt.contains("://")
        {
            row.login.username = Some(alt.to_string());
        }

        let name = clean_name(Some(title));
        let notes = clean_notes(row.notes.take().map(|n| n.trim_end().to_string()));
        let meta = Meta {
            source_id: nonblank(record.get_ci("uuid")),
            ..Meta::default()
        };
        match row.kind {
            Kind::Login => {
                let mut login = row.login;
                login.name = name.clone();
                login.fields = row.fields;
                login.notes = notes;
                login.meta = meta.clone();
                if is_noteworthy_login(&login) {
                    b.note(Note {
                        name,
                        text: login.notes.take(),
                        fields: std::mem::take(&mut login.fields),
                        meta,
                    });
                } else {
                    b.login(login);
                }
            }
            Kind::Card => {
                let mut card = row.card;
                card.name = name;
                card.notes = notes;
                card.fields = row.fields;
                card.meta = meta;
                b.card(card);
            }
            Kind::Identity => {
                let mut identity = row.identity;
                identity.name = name;
                identity.notes = notes;
                identity.fields = row.fields;
                identity.meta = meta;
                b.identity(identity);
            }
        }
    }
    b.note_unread(table.unread);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const WINDOWS: &str = include_str!("../tests/fixtures/onepassword/windows.csv");
    const MAC: &str = include_str!("../tests/fixtures/onepassword/mac.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn numbered_columns_are_matched_like_the_regular_expressions() {
        assert!(matches_numbered("2: number", "", ": number"));
        assert!(matches_numbered("card 12: number", "", ": number"));
        assert!(!matches_numbered("3: verification number", "", ": number"));
        assert!(!matches_numbered(": number", "", ": number"));
        assert!(matches_numbered(
            "name 1: first name",
            "name ",
            ": first name"
        ));
        assert!(!matches_numbered("1: first name", "name ", ": first name"));
        assert!(matches_numbered(
            "address 1: address",
            "address ",
            ": address"
        ));
        assert!(!matches_numbered("", "", ": number"));
    }

    #[test]
    fn windows_login_with_every_address() {
        let batch = read(WINDOWS).expect("batch");
        assert_eq!(batch.format, Format::OnePasswordCsv);
        assert_eq!(batch.logins.len(), 1);
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example Login");
        assert_eq!(login.username.as_deref(), Some("ada"));
        assert_eq!(login.password.as_deref(), Some("pw-one"));
        let uris: Vec<&str> = login.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(
            uris,
            ["https://login.example.com", "https://alt.example.com"]
        );
        assert_eq!(login.notes.as_deref(), Some("a login note"));
        assert_eq!(login.meta.source_id.as_deref(), Some("aaaa"));
        assert_eq!(login.fields.len(), 1);
        assert_eq!(login.fields[0].name, "EXTRA 1: SECRET");
        assert_eq!(login.fields[0].kind, FieldKind::Hidden);
        assert_eq!(login.fields[0].value, "tok-123");
    }

    #[test]
    fn windows_card() {
        let batch = read(WINDOWS).expect("batch");
        assert_eq!(batch.cards.len(), 1);
        let card = &batch.cards[0];
        assert_eq!(card.name, "Test Card");
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert!(card.fields.is_empty());
    }

    #[test]
    fn windows_identity_keeps_its_address_as_a_field() {
        let batch = read(WINDOWS).expect("batch");
        assert_eq!(batch.identities.len(), 1);
        let id = &batch.identities[0];
        assert_eq!(id.name, "Identity Item");
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.middle_name.as_deref(), Some("K"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.username.as_deref(), Some("ada99"));
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        assert_eq!(id.fields.len(), 1);
        assert_eq!(id.fields[0].name, "address");
        assert_eq!(id.fields[0].value, "1 Main St");
    }

    #[test]
    fn mac_login_with_its_dates() {
        let batch = read(MAC).expect("batch");
        assert_eq!(batch.logins.len(), 1);
        let login = &batch.logins[0];
        assert_eq!(login.name, "Mac Login");
        assert_eq!(login.username.as_deref(), Some("bob"));
        assert_eq!(login.password.as_deref(), Some("pw-two"));
        assert_eq!(login.uris[0].uri, "https://mac.example.org");
        assert_eq!(login.notes.as_deref(), Some("note one"));
        assert_eq!(login.meta.source_id.as_deref(), Some("m1"));
        let fields: Vec<(&str, &str)> = login
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            fields,
            [
                ("1Password Created Date", "Sun, 13 Sep 2020 12:26:40 GMT"),
                ("1Password Modified Date", "Sun, 13 Sep 2020 12:28:20 GMT")
            ]
        );
    }

    #[test]
    fn mac_card_identity_and_note() {
        let batch = read(MAC).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.name, "Mac Card");
        assert_eq!(card.cardholder.as_deref(), Some("Bob Builder"));
        assert_eq!(card.number.as_deref(), Some("5555555555554444"));
        assert_eq!(card.brand.as_deref(), Some("Mastercard"));
        assert_eq!(card.code.as_deref(), Some("321"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2030)));

        let id = &batch.identities[0];
        assert_eq!(id.name, "Mac Identity");
        assert_eq!(id.given_name.as_deref(), Some("Bob"));
        assert_eq!(id.middle_name.as_deref(), Some("Q"));
        assert_eq!(id.family_name.as_deref(), Some("Builder"));
        assert_eq!(id.phone.as_deref(), Some("555-0100"));
        assert_eq!(id.email.as_deref(), Some("bob@example.com"));
        assert_eq!(id.company.as_deref(), Some("Acme"));

        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].name, "Mac Note");
        assert_eq!(batch.notes[0].text.as_deref(), Some("just text"));
    }

    #[test]
    fn a_long_value_goes_to_the_note_and_a_stray_email_becomes_the_username() {
        let long = "x".repeat(250);
        let text =
            format!("Title,Type,Password,Email,Comment\nSite,Login,pw,me@example.com,\"{long}\"\n");
        let batch = read(&text).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.username.as_deref(), Some("me@example.com"));
        assert_eq!(
            login.notes.as_deref(),
            Some(format!("Comment: {long}").as_str())
        );
        assert!(login.fields.is_empty());
    }

    #[test]
    fn rows_without_a_title_are_left_out() {
        let batch = read("Title,Type,Username\n,Login,x\nKept,Login,y\n").expect("batch");
        assert_eq!(batch.logins.len(), 1);
        assert_eq!(batch.logins[0].name, "Kept");
    }

    #[test]
    fn escaped_quotes_inside_a_field_are_read() {
        let batch = read("Title,Type,Username,Password\n\"He said \\\"hi\\\"\",Login,u,p\n")
            .expect("batch");
        assert_eq!(batch.logins[0].name, "He said \"hi\"");
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("a,b\n1,2\n").err(), Some(ImportError::Unsupported));
        assert_eq!(read("Title,Type\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn the_entry_limit_applies() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let batch = parse(MAC.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 2);
        assert_eq!(batch.skipped_count(), 2);
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "Title\n\"unterminated",
            "TITLE,1: NUMBER,4: EXPIRY DATE\nx,1,//\nx,2,1/2",
            "Title,Type,expiry date(expiry)\nx,Credit Card,5/2030\nx,Credit Card,\u{0}",
            "TITLE,NAME 1: FIRST NAME\nx,\u{1F600}",
            "Title,Created Date\nx,notanumber\nx,99999999999999999999999",
        ] {
            let _ = read(text);
        }
    }
}
