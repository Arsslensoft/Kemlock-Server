// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/safari-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Safari and Apple Passwords CSV: `Title,URL,Username,Password,Notes,OTPAuth`. Older Safari
//! exports spell the address column `Url` and have no notes or `OTPAuth`.

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, read_table};
use crate::error::{ImportError, Result};
use crate::model::{Format, ImportBatch, Login};
use crate::util::{clean_notes, make_uris, nonblank, or_default};

/// Reads a Safari or Apple Passwords export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if !["Title", "Username", "Password", "URL", "Url"]
        .iter()
        .any(|column| table.has(column))
    {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::SafariCsv, ctx.limits);
    for record in table.records() {
        // `value.Url ?? value.URL`: a present `Url` column wins even when empty.
        let url = record
            .get("Url")
            .or_else(|| record.get("URL"))
            .unwrap_or("");
        b.login(Login {
            name: or_default(record.get("Title"), "--"),
            username: nonblank(record.get("Username")),
            password: nonblank(record.get("Password")),
            uris: make_uris([url]),
            totp: nonblank(record.get("OTPAuth")),
            notes: clean_notes(nonblank(record.get("Notes"))),
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

    const PASSWORDS: &str = include_str!("../tests/fixtures/safari/passwords.csv");
    const OLD: &str = include_str!("../tests/fixtures/safari/old.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_logins_with_their_one_time_password_links() {
        let batch = read(PASSWORDS).expect("batch");
        assert_eq!(batch.logins.len(), 2);
        let first = &batch.logins[0];
        assert_eq!(first.name, "Example (ada)");
        assert_eq!(first.uris[0].uri, "https://example.com");
        assert_eq!(first.username.as_deref(), Some("ada"));
        assert_eq!(first.password.as_deref(), Some("safari-pass"));
        assert_eq!(first.notes.as_deref(), Some("A note"));
        assert!(
            first
                .totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://totp/Example:ada")
        );
        assert_eq!(batch.logins[1].totp, None);
        assert_eq!(batch.logins[1].notes, None);
    }

    #[test]
    fn reads_the_older_export() {
        let batch = read(OLD).expect("batch");
        assert_eq!(batch.logins.len(), 1);
        assert_eq!(batch.logins[0].uris[0].uri, "https://example.com");
        assert_eq!(batch.logins[0].username.as_deref(), Some("example_user"));
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("Title,URL\n").err(), Some(ImportError::Empty));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in ["Title,URL\n\"x", "Title\n,\n,,,,,", "Title,Url\n\u{0}"] {
            let _ = read(text);
        }
    }
}
