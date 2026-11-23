// Ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/firefox-csv-importer.ts, at commit
//   f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Firefox CSV: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,...`. The
//! `chrome://FirefoxAccounts` row is Firefox's own sync login and is left out. A login is named by
//! its address's host.

use crate::builder::Builder;
use crate::context::Context;
use crate::csv::{CsvOptions, read_table};
use crate::error::{ImportError, Result};
use crate::model::{Format, ImportBatch, Login, SkipReason};
use crate::util::{make_uris, name_from_url, nonblank, or_default};

/// Reads a Firefox export.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    let table = read_table(bytes, ctx, CsvOptions::default())?;
    if !["url", "hostname", "username", "password"]
        .iter()
        .any(|column| table.has(column))
    {
        return Err(ImportError::Unsupported);
    }
    let mut b = Builder::new(Format::FirefoxCsv, ctx.limits);
    for record in table.records() {
        if record.get("url") == Some("chrome://FirefoxAccounts") {
            b.skip(
                Some("Firefox Accounts credentials"),
                SkipReason::UnsupportedKind,
                Some("Firefox's own sync login"),
            );
            continue;
        }
        // `getValueOrDefault(value.url, getValueOrDefault(value.hostname))`
        let url = nonblank(record.get("url"))
            .or_else(|| nonblank(record.get("hostname")))
            .unwrap_or_default();
        b.login(Login {
            name: or_default(name_from_url(&url).as_deref(), "--"),
            username: nonblank(record.get("username")),
            password: nonblank(record.get("password")),
            uris: make_uris([url.as_str()]),
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

    const LOGINS: &str = include_str!("../tests/fixtures/firefox/logins.csv");

    fn read(text: &str) -> Result<ImportBatch> {
        let limits = Limits::default();
        parse(text.as_bytes(), &Context::new(&limits))
    }

    #[test]
    fn reads_logins_and_names_them_by_host() {
        let batch = read(LOGINS).expect("batch");
        assert_eq!(batch.logins.len(), 3);
        let first = &batch.logins[0];
        assert_eq!(first.name, "example.com");
        assert_eq!(first.uris[0].uri, "https://www.example.com");
        assert_eq!(first.username.as_deref(), Some("foo"));
        assert_eq!(first.password.as_deref(), Some("bar"));
        assert_eq!(batch.logins[1].name, "--");
        assert!(batch.logins[1].uris.is_empty());
        assert_eq!(batch.logins[2].name, "example.net");
        assert_eq!(batch.logins[2].uris[0].uri, "http://example.net");
    }

    #[test]
    fn the_firefox_accounts_row_is_listed_as_skipped() {
        let batch = read(LOGINS).expect("batch");
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::UnsupportedKind);
        assert!(
            batch
                .logins
                .iter()
                .all(|l| l.password.as_deref() != Some("{\"version\":1}"))
        );
    }

    #[test]
    fn the_hostname_column_stands_in_for_url() {
        let batch = read("hostname,username,password\nhttps://old.example,x,y\n").expect("batch");
        assert_eq!(batch.logins[0].name, "old.example");
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("a,b\n1,2").err(), Some(ImportError::Unsupported));
        assert_eq!(
            read("url,username,password\n").err(),
            Some(ImportError::Empty)
        );
    }

    #[test]
    fn damaged_input_does_not_panic() {
        for text in ["url\n\"x", "url,username\n,,,,", "url\n\u{0}\u{1}"] {
            let _ = read(text);
        }
    }
}
