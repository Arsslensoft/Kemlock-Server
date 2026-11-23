// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Bitwarden CSV: `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,
//! login_password,login_totp`. An organisation export has `collections` (comma-separated names)
//! instead of `folder`; each collection becomes a shared vault. `login_uri` holds several addresses
//! as one CSV line; `fields` holds `name: value` lines.

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, read_table, split_row};
use crate::error::{ImportError, Result};
use crate::model::{CustomField, FieldKind, Format, ImportBatch, Login, Meta, Note, SharedKind};
use crate::util::{clean_notes, is_blank, make_uris, nonblank, or_default, split_newlines};

/// `a || b` on strings as JavaScript reads it: the first one that is present and not empty.
fn first_nonempty<'a>(a: Option<&'a str>, b: Option<&'a str>) -> Option<&'a str> {
    match a {
        Some(a) if !a.is_empty() => Some(a),
        _ => b,
    }
}

/// The `fields` cell: one `name: value` per line, split at the last `: `; a line with no `: ` is
/// dropped.
fn parse_fields(cell: &str) -> Vec<CustomField> {
    let mut fields = Vec::new();
    for line in split_newlines(cell) {
        if is_blank(line) {
            continue;
        }
        let Some(at) = line.rfind(": ") else {
            continue;
        };
        fields.push(CustomField {
            name: line[..at].to_string(),
            value: line[at + 2..].to_string(),
            kind: FieldKind::Text,
        });
    }
    fields
}

/// Reads a Bitwarden CSV export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if ![
        "name",
        "type",
        "login_uri",
        "login_username",
        "login_password",
    ]
    .iter()
    .any(|column| table.has(column))
    {
        return Err(ImportError::Unsupported);
    }
    let organisation = table.has("collections");
    let mut b = Builder::new(Format::BitwardenCsv, ctx.limits);
    for record in table.records() {
        let mut meta = Meta::default();
        if organisation {
            if let Some(cell) = record.get("collections").filter(|c| !is_blank(c)) {
                for name in cell.split(',') {
                    if is_blank(name) {
                        continue;
                    }
                    if let Some(space) = b.space(name.trim(), name.trim(), SharedKind::Collection)
                        && !meta.spaces.contains(&space)
                    {
                        meta.spaces.push(space);
                    }
                }
            }
        } else if let Some(folder) = record.get("folder") {
            meta.folder = b.folder(folder);
        }
        let favorite = record
            .get("favorite")
            .filter(|f| !is_blank(f))
            .unwrap_or("0");
        meta.favorite = !organisation && favorite != "0";

        let name = or_default(record.get("name"), "--");
        let notes = clean_notes(nonblank(record.get("notes")));
        let fields = record.get("fields").map(parse_fields).unwrap_or_default();

        let kind = record.get("type").map(str::to_lowercase);
        if kind.as_deref() == Some("note") {
            b.note(Note {
                name,
                text: notes,
                fields,
                meta,
            });
            continue;
        }
        let uri_cell = first_nonempty(record.get("login_uri"), record.get("uri"));
        let uri_parts = uri_cell.map(split_row).unwrap_or_default();
        b.login(Login {
            name,
            uris: make_uris(uri_parts.iter().map(String::as_str)),
            username: nonblank(first_nonempty(
                record.get("login_username"),
                record.get("username"),
            )),
            password: nonblank(first_nonempty(
                record.get("login_password"),
                record.get("password"),
            )),
            totp: nonblank(first_nonempty(record.get("login_totp"), record.get("totp"))),
            notes,
            fields,
            meta,
            ..Login::default()
        });
    }
    b.note_unread(table.unread);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const EXPORT: &str = include_str!("../tests/fixtures/bitwarden/export.csv");
    const ORG: &str = include_str!("../tests/fixtures/bitwarden/org.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_logins_notes_folders_and_fields() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.notes.len(), 1);
        let mail = &batch.logins[0];
        assert_eq!(mail.name, "Example Mail");
        assert_eq!(mail.username.as_deref(), Some("ada"));
        assert_eq!(mail.password.as_deref(), Some("pw-now"));
        assert!(
            mail.totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://")
        );
        let uris: Vec<&str> = mail.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(uris, ["https://mail.example.com", "http://alt.example.com"]);
        assert!(mail.meta.favorite);
        assert_eq!(
            batch.folders[mail.meta.folder.expect("folder")].path,
            "Work/Projects"
        );
        assert_eq!(mail.fields.len(), 2);
        assert_eq!(mail.fields[0].name, "pin");
        assert_eq!(mail.fields[0].value, "1234");
        assert_eq!(mail.fields[1].name, "a: b");
        assert_eq!(mail.fields[1].value, "c");
        assert_eq!(batch.logins[1].meta.folder, None);
        assert!(!batch.logins[1].meta.favorite);
        assert_eq!(batch.notes[0].text.as_deref(), Some("line one\nline two"));
    }

    #[test]
    fn an_organisation_export_makes_collections() {
        let batch = read(ORG).expect("batch");
        assert_eq!(batch.spaces.len(), 2);
        assert_eq!(batch.spaces[0].name, "Shared");
        assert_eq!(batch.logins[0].meta.spaces, [0, 1]);
        assert_eq!(batch.logins[1].meta.spaces, [1]);
        assert!(batch.folders.is_empty());
        assert!(!batch.logins[0].meta.favorite);
    }

    #[test]
    fn field_lines_split_at_the_last_separator() {
        let fields = parse_fields("a: b: c\nno separator\n\nlone: ");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "a: b");
        assert_eq!(fields[0].value, "c");
        assert_eq!(fields[1].name, "lone");
        assert_eq!(fields[1].value, "");
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read("folder,type,name\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "name,login_uri\nx,\"unterminated",
            "name,fields\nx,\": \"",
            "name,type\n,\u{0}",
        ] {
            let _ = read(text);
        }
    }
}
