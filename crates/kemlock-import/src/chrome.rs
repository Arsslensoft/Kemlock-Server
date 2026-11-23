// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/chrome-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Chrome, Edge and Google Password Manager CSV: `name,url,username,password,note`.
//!
//! An Android app's entry has an `android://<hash>@<package>/` address; it becomes
//! `androidapp://<package>`, and the package names the login when the name is empty.

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, read_table};
use crate::error::{ImportError, Result};
use crate::model::{Format, ImportBatch, Login};
use crate::util::{clean_notes, make_uris, nonblank, or_default};

/// The package name in `android://<base64>@<package>/`, by plain string operations (Bitwarden
/// avoids a regular expression here to keep adversarial input linear).
fn android_package(url: &str) -> Option<&str> {
    if !url.starts_with("android://") {
        return None;
    }
    let at = url.find('@')?;
    let rest = &url[at + 1..];
    match rest.find('/') {
        Some(slash) => Some(&rest[..slash]),
        None => Some(rest),
    }
}

/// `androidapp://<package>` for an `android://` address; any other address as it is.
fn normalise_android(url: &str) -> String {
    match android_package(url) {
        Some(package) => format!("androidapp://{package}"),
        None => url.to_string(),
    }
}

/// Reads a Chrome, Edge or Google Password Manager export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if !["name", "url", "username", "password"]
        .iter()
        .any(|column| table.has(column))
    {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::ChromeCsv, ctx.limits);
    for record in table.records() {
        let url = record.get("url").unwrap_or("");
        let mut name = record.get("name").unwrap_or("").to_string();
        if name.is_empty()
            && let Some(package) = android_package(url)
        {
            name = package.to_string();
        }
        b.login(Login {
            name: or_default(Some(name.as_str()), "--"),
            username: nonblank(record.get("username")),
            password: nonblank(record.get("password")),
            uris: make_uris([normalise_android(url).as_str()]),
            notes: clean_notes(nonblank(record.get("note"))),
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

    const PASSWORDS: &str = include_str!("../tests/fixtures/chrome/passwords.csv");
    const ANDROID: &str = include_str!("../tests/fixtures/chrome/android.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_logins() {
        let batch = read(PASSWORDS).expect("batch");
        assert_eq!(batch.format, Format::ChromeCsv);
        assert_eq!(batch.logins.len(), 4);
        let mail = &batch.logins[0];
        assert_eq!(mail.name, "Example Mail");
        assert_eq!(mail.uris[0].uri, "https://mail.example.com/login");
        assert_eq!(mail.username.as_deref(), Some("ada@example.com"));
        assert_eq!(mail.password.as_deref(), Some("correct-horse-1"));
        assert_eq!(mail.notes.as_deref(), Some("Recovery code on paper"));

        let bare = &batch.logins[1];
        assert_eq!(bare.uris[0].uri, "http://bare.example");
        assert_eq!(bare.username, None);
        assert_eq!(bare.notes, None);

        let quoted = &batch.logins[2];
        assert_eq!(quoted.name, "Quoted, Name");
        assert_eq!(quoted.password.as_deref(), Some("pass,word\"quoted\""));
        assert_eq!(quoted.notes.as_deref(), Some("line one\nline two"));
    }

    #[test]
    fn an_android_entry_is_named_by_its_package() {
        let batch = read(PASSWORDS).expect("batch");
        let app = &batch.logins[3];
        assert_eq!(app.name, "com.example.app");
        assert_eq!(app.uris[0].uri, "androidapp://com.example.app");

        let batch = read(ANDROID).expect("batch");
        assert_eq!(batch.logins[0].name, "com.xyz.example.app.android");
        assert_eq!(
            batch.logins[0].uris[0].uri,
            "androidapp://com.xyz.example.app.android"
        );
    }

    #[test]
    fn android_addresses_without_a_slash_or_an_at_sign() {
        assert_eq!(android_package("android://abc@com.x"), Some("com.x"));
        assert_eq!(android_package("android://abc"), None);
        assert_eq!(android_package("https://a@b/"), None);
        assert_eq!(normalise_android("https://a.b"), "https://a.b");
    }

    #[test]
    fn refuses_other_text_and_empty_files() {
        assert_eq!(read("").err(), Some(ImportError::Unsupported));
        assert_eq!(read("foo,bar\n1,2\n").err(), Some(ImportError::Unsupported));
        assert_eq!(
            read("name,url,username,password,note\n").err(),
            Some(ImportError::Empty)
        );
    }

    #[test]
    fn rows_over_the_limit_are_counted_not_read() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let batch = parse(PASSWORDS.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.logins.len(), 2);
        assert_eq!(batch.skipped_count(), 2);
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in [
            "name,url\n\"unterminated",
            "name,url,username,password\n,,,\n,,,",
            "\u{feff}name,url,username,password\nx,\u{0},y,z",
        ] {
            let _ = read(text);
        }
    }
}
