// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/roboform-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! RoboForm CSV: `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`. A row may be longer than the
//! header: each extra cell is one more form field. Older exports use `Rf_fields` with
//! `name:type:value` fields. An entry with no username, password or address is a note.

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, read_table};
use crate::error::{ImportError, Result};
use crate::model::{CustomField, FieldKind, Format, ImportBatch, Login, Meta, Note};
use crate::util::{
    clean_notes, is_blank, is_noteworthy_login, kvp, make_uris, nonblank, or_default,
};

/// `Rf_fields`: each cell is `name:type:value` (four parts and `rck` as the type means the value
/// is the second part).
fn rf_fields_v1<'a>(
    cells: impl Iterator<Item = &'a str>,
    fields: &mut Vec<CustomField>,
    notes: &mut Option<String>,
) {
    for cell in cells {
        let parts: Vec<&str> = cell.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        let key = if parts[0] == "-no-name-" {
            ""
        } else {
            parts[0]
        };
        let value = if parts.len() == 4 && parts[2] == "rck" {
            parts[1]
        } else {
            parts[2]
        };
        kvp(fields, notes, key, value, FieldKind::Text);
    }
}

/// `RfFieldsV2`: each cell is `name,,,type,value`. A `TOTP KEY$` field is the login's code, the
/// `User ID$` and `Password$` that repeat the login are dropped, and further ones are numbered.
fn rf_fields_v2<'a>(
    cells: impl Iterator<Item = &'a str>,
    login: &mut Login,
    notes: &mut Option<String>,
) {
    let mut user_ids = 1;
    let mut passwords = 1;
    for cell in cells {
        let parts: Vec<&str> = cell.split(',').collect();
        if parts.len() < 5 {
            continue;
        }
        let key = if parts[0] == "-no-name-" {
            ""
        } else {
            parts[0]
        };
        let kind = if parts[3] == "pwd" {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        let value = parts[4];
        if key == "TOTP KEY$" {
            login.totp = Some(value.to_string());
            continue;
        }
        if key == "User ID$" && Some(value) == login.username.as_deref() {
            continue;
        }
        if key == "Password$" && Some(value) == login.password.as_deref() {
            continue;
        }
        let shown = match key {
            "User ID$" => {
                user_ids += 1;
                format!("Alternate User ID {}", user_ids - 1)
            }
            "Password$" => {
                passwords += 1;
                format!("Alternate Password {}", passwords - 1)
            }
            other => other.to_string(),
        };
        kvp(&mut login.fields, notes, &shown, value, kind);
    }
}

/// Reads a RoboForm export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if !["Name", "Url", "URL", "Login", "Pwd", "Password"]
        .iter()
        .any(|column| table.has(column))
    {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::RoboFormCsv, ctx.limits);
    let total = table.rows.len();
    for (n, record) in table.records().enumerate() {
        // A folder written `/a` is `a`.
        let folder = record
            .get("Folder")
            .filter(|f| !is_blank(f))
            .map(|f| f.strip_prefix('/').unwrap_or(f));
        let meta = Meta {
            folder: folder.and_then(|f| b.folder(f)),
            ..Meta::default()
        };
        let mut notes = nonblank(record.get("Note"));
        let url = record
            .get("Url")
            .or_else(|| record.get("URL"))
            .unwrap_or("");
        let mut login = Login {
            name: or_default(record.get("Name"), "--"),
            username: nonblank(record.get("Login")),
            password: nonblank(record.get("Pwd")).or_else(|| nonblank(record.get("Password"))),
            uris: make_uris([url]),
            ..Login::default()
        };
        if let Some(cell) = record.get("Rf_fields").filter(|c| !is_blank(c)) {
            let cells = std::iter::once(cell).chain(record.extra().iter().map(String::as_str));
            rf_fields_v1(cells, &mut login.fields, &mut notes);
        } else if let Some(cell) = record.get("RfFieldsV2").filter(|c| !is_blank(c)) {
            let cells = std::iter::once(cell).chain(record.extra().iter().map(String::as_str));
            rf_fields_v2(cells, &mut login, &mut notes);
        }
        let notes = clean_notes(notes);
        // The export ends with an empty row some versions write.
        if n + 1 == total && login.name == "--" && login.password.is_none() {
            continue;
        }
        if is_noteworthy_login(&login) {
            b.note(Note {
                name: login.name,
                text: notes,
                fields: login.fields,
                meta,
            });
        } else {
            login.notes = notes;
            login.meta = meta;
            b.login(login);
        }
    }
    b.note_unread(table.unread);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const EXPORT: &str = include_str!("../tests/fixtures/roboform/export.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_logins_with_their_form_fields() {
        let batch = read(EXPORT).expect("batch");
        assert_eq!(batch.logins.len(), 2);
        let first = &batch.logins[0];
        assert_eq!(first.name, "Example");
        assert_eq!(first.username.as_deref(), Some("ada"));
        assert_eq!(first.password.as_deref(), Some("pw1"));
        assert_eq!(first.uris[0].uri, "https://example.com");
        assert_eq!(first.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        // The repeated user id and password are dropped; the second user id is numbered.
        let names: Vec<&str> = first.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["Alternate User ID 1", "Question", "Alternate Password 1"]
        );
        assert_eq!(first.fields[1].value, "blue");
        assert_eq!(first.fields[2].kind, FieldKind::Hidden);
        assert_eq!(
            batch.folders[first.meta.folder.expect("folder")].path,
            "Personal"
        );
    }

    #[test]
    fn folders_nest_and_a_row_with_no_login_is_a_note() {
        let batch = read(EXPORT).expect("batch");
        let second = &batch.logins[1];
        assert_eq!(
            batch.folders[second.meta.folder.expect("folder")].path,
            "folder2/folder3"
        );
        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].name, "note - 2023");
        assert_eq!(batch.notes[0].text.as_deref(), Some("This is a safe note"));
    }

    #[test]
    fn the_older_field_format_is_read() {
        let text = "Name,Url,Login,Pwd,Rf_fields\nSite,https://s.example,u,p,Field1:txt:value1,-no-name-:txt:anon,short:x,Ck:val:rck:z\n";
        let batch = read(text).expect("batch");
        let login = &batch.logins[0];
        let fields: Vec<(&str, &str)> = login
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(fields, [("Field1", "value1"), ("", "anon"), ("Ck", "val")]);
    }

    #[test]
    fn an_empty_last_row_is_dropped() {
        let batch =
            read("Name,Url,Login,Pwd\nA,https://a.example,u,p\n,,,x\n ,,,\n").expect("batch");
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.logins[1].name, "--");
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read("Name,Url\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "Name,RfFieldsV2\nx,\",,,,\"",
            "Name,Rf_fields\nx,:::",
            "Name,RfFieldsV2\nx,a,b,c,d,e,f,g",
        ] {
            let _ = read(text);
        }
    }
}
