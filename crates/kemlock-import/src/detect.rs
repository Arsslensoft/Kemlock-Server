//! Finding the format from the content, and the one-call entry points [`detect`], [`parse`] and
//! [`parse_as`]. The person picks no app: a KDBX file has its signature, a ZIP its file names, JSON
//! its top-level keys, and a CSV its header columns.

use std::fmt;

use serde_json::Value;

use crate::context::Context;
use crate::csv::{CsvOptions, Table};
use crate::error::{ImportError, Result};
use crate::limits::Limits;
use crate::model::{Format, ImportBatch};
use crate::protonpass::looks_like_pgp;
use crate::util::{decode_text, jarr, jbool};
use crate::zip::{Zip, looks_like_zip};

/// The format found, and whether opening it takes a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detected {
    /// The format.
    pub format: Format,
    /// Whether the export is encrypted, so the caller asks for a password (and, for KDBX, offers a
    /// key file). A Bitwarden export encrypted with an account key is reported as encrypted too;
    /// opening it fails with [`ImportError::AccountRestricted`].
    pub encrypted: bool,
}

fn found(format: Format, encrypted: bool) -> Result<Detected> {
    Ok(Detected { format, encrypted })
}

/// Which format `bytes` are, without decrypting anything. [`ImportError::Unsupported`] when it is
/// none, and the size errors when the input is over a limit.
pub fn detect(bytes: &[u8], limits: &Limits) -> Result<Detected> {
    // KDBX: two signatures; the second says which KeePass.
    if bytes.starts_with(&[0x03, 0xD9, 0xA2, 0x9A]) {
        limits.check_input(bytes)?;
        return match bytes.get(4..8) {
            Some([0x67, 0xFB, 0x4B, 0xB5]) => found(Format::Kdbx, true),
            _ => Err(ImportError::Unsupported),
        };
    }
    if looks_like_zip(bytes) {
        return detect_zip(bytes, limits);
    }
    limits.check_input(bytes)?;
    // A binary message is not valid UTF-8 (a text file that starts with a letter such as `é` also
    // starts with a byte that looks like a packet tag).
    if looks_like_pgp(bytes)
        && (bytes.trim_ascii_start().starts_with(b"-----BEGIN")
            || std::str::from_utf8(bytes).is_err())
    {
        return found(Format::ProtonPassPgp, true);
    }
    let text = decode_text(bytes);
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return detect_json(trimmed);
    }
    detect_csv(&text)
}

fn detect_zip(bytes: &[u8], limits: &Limits) -> Result<Detected> {
    let zip = Zip::open(bytes, limits)?;
    let names: Vec<&str> = zip.entries().iter().map(|e| e.name.as_str()).collect();
    let base = |name: &str| name.rsplit('/').next().unwrap_or(name).to_lowercase();
    if names.contains(&"export.data") {
        return found(Format::OnePasswordPux, false);
    }
    if names.iter().any(|&n| base(n).ends_with(".pgp")) {
        return found(Format::ProtonPassZip, true);
    }
    if names.iter().any(|&n| base(n) == "data.json") {
        return found(Format::ProtonPassZip, false);
    }
    let dashlane = [
        "credentials.csv",
        "ids.csv",
        "payments.csv",
        "personalinfo.csv",
        "securenotes.csv",
    ];
    if names.iter().any(|&n| dashlane.contains(&base(n).as_str())) {
        return found(Format::DashlaneZip, false);
    }
    Err(ImportError::Unsupported)
}

fn detect_json(text: &str) -> Result<Detected> {
    let root: Value = serde_json::from_str(text).map_err(|_| ImportError::Unsupported)?;
    if !root.is_object() {
        return Err(ImportError::Unsupported);
    }
    // Bitwarden's password-protected file has no `items`; an account-restricted one does.
    if jbool(&root, "passwordProtected") == Some(true) {
        return found(Format::BitwardenJson, true);
    }
    if root.get("records").is_some_and(Value::is_array) {
        return found(Format::KeeperJson, false);
    }
    if root.get("vaults").is_some_and(Value::is_object) {
        return found(
            Format::ProtonPassJson,
            jbool(&root, "encrypted") == Some(true),
        );
    }
    if root.get("items").is_some_and(Value::is_array) {
        let enpass = jarr(&root, "items")
            .iter()
            .take(5)
            .any(|item| item.get("template_type").is_some());
        if enpass {
            return found(Format::EnpassJson, false);
        }
        return found(
            Format::BitwardenJson,
            jbool(&root, "encrypted") == Some(true),
        );
    }
    Err(ImportError::Unsupported)
}

fn detect_csv(text: &str) -> Result<Detected> {
    // Only the header is needed.
    let table = Table::parse(text, CsvOptions::default(), 0);
    let h = &table.headers;
    if h.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let first_two = (h.first().map(String::as_str), h.get(1).map(String::as_str));

    let format = if (table.has_all(&["folder", "favorite", "type", "name"])
        && (table.has("login_uri") || table.has("login_username")))
        || (table.has("collections") && table.has("login_uri"))
    {
        Format::BitwardenCsv
    } else if (table.has("profilename") && table.has("profilelanguage"))
        || table.has_all(&["url", "username", "password", "extra", "name", "grouping"])
    {
        Format::LastPassCsv
    } else if table.has_all(&["url", "username", "password"])
        && (table.has("httpRealm") || table.has("guid"))
    {
        Format::FirefoxCsv
    } else if (table.has("OTPAuth") && table.has("Title"))
        || (table.has_all(&["Title", "Username", "Password"])
            && !table.headers.iter().any(|c| c.ends_with(')'))
            && (table.has("Url") || table.has("URL"))
            && !table.has("Type"))
    {
        Format::SafariCsv
    } else if table.has_all(&["Name", "Login", "Pwd"]) || table.has("RfFieldsV2") {
        Format::RoboFormCsv
    } else if table.has_all(&["name", "type", "folder"])
        && (table.has("additional_urls") || table.has("cardnumber") || table.has("custom_fields"))
    {
        Format::NordPassCsv
    } else if (table.has("UUID") && table.has("TITLE"))
        || (table.has("Title")
            && table.has("Type")
            && table.headers.iter().any(|c| c.ends_with(')')))
    {
        Format::OnePasswordCsv
    } else if (first_two.0 == Some("username") && table.has("password"))
        || first_two == (Some("type"), Some("account_name"))
        || first_two == (Some("type"), Some("number"))
        || first_two == (Some("type"), Some("title"))
        || first_two == (Some("title"), Some("note"))
    {
        Format::DashlaneCsv
    } else if table.has_all(&["name", "url", "username", "password"]) {
        Format::ChromeCsv
    } else {
        return Err(ImportError::Unsupported);
    };
    found(format, false)
}

/// What [`parse`] is given besides the bytes.
#[derive(Clone, Default)]
pub struct ImportOptions<'a> {
    /// The format to read as; `None` finds it from the content.
    pub format: Option<Format>,
    /// The password for an encrypted export.
    pub password: Option<&'a str>,
    /// A KDBX key file.
    pub key_file: Option<&'a [u8]>,
    /// The caps.
    pub limits: Limits,
}

// Not derived: the password and the key file stay out of logs.
impl fmt::Debug for ImportOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportOptions")
            .field("format", &self.format)
            .field("password", &self.password.map(|_| ".."))
            .field("key_file", &self.key_file.map(|_| ".."))
            .field("limits", &self.limits)
            .finish()
    }
}

/// Finds the format of `bytes` and reads it.
pub fn parse(bytes: &[u8], options: &ImportOptions<'_>) -> Result<ImportBatch> {
    let format = match options.format {
        Some(format) => format,
        None => detect(bytes, &options.limits)?.format,
    };
    let mut ctx = Context::new(&options.limits);
    ctx.password = options.password;
    ctx.key_file = options.key_file;
    parse_as(format, bytes, &ctx)
}

/// Reads `bytes` as `format`.
pub fn parse_as(format: Format, bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    match format {
        Format::ChromeCsv => crate::chrome::parse(bytes, ctx),
        Format::SafariCsv => crate::safari::parse(bytes, ctx),
        Format::FirefoxCsv => crate::firefox::parse(bytes, ctx),
        Format::BitwardenJson => crate::bitwarden::parse(bytes, ctx),
        Format::BitwardenCsv => crate::bitwarden_csv::parse(bytes, ctx),
        Format::LastPassCsv => crate::lastpass::parse(bytes, ctx),
        Format::OnePasswordPux => crate::onepassword::parse(bytes, ctx),
        Format::OnePasswordCsv => crate::onepassword_csv::parse(bytes, ctx),
        Format::DashlaneZip | Format::DashlaneCsv => crate::dashlane::parse(bytes, ctx),
        Format::NordPassCsv => crate::nordpass::parse(bytes, ctx),
        Format::KeeperJson => crate::keeper::parse(bytes, ctx),
        Format::ProtonPassJson | Format::ProtonPassZip | Format::ProtonPassPgp => {
            crate::protonpass::parse(bytes, ctx)
        }
        Format::Kdbx => crate::kdbx::parse(bytes, ctx),
        Format::EnpassJson => crate::enpass::parse(bytes, ctx),
        Format::RoboFormCsv => crate::roboform::parse(bytes, ctx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected(bytes: &[u8]) -> Result<Detected> {
        detect(bytes, &Limits::default())
    }

    fn format_of(text: &str) -> Option<Format> {
        detected(text.as_bytes()).ok().map(|d| d.format)
    }

    #[test]
    fn finds_each_csv_by_its_header() {
        let cases: [(&str, Format); 12] = [
            (
                include_str!("../tests/fixtures/chrome/passwords.csv"),
                Format::ChromeCsv,
            ),
            (
                include_str!("../tests/fixtures/safari/passwords.csv"),
                Format::SafariCsv,
            ),
            (
                include_str!("../tests/fixtures/safari/old.csv"),
                Format::SafariCsv,
            ),
            (
                include_str!("../tests/fixtures/firefox/logins.csv"),
                Format::FirefoxCsv,
            ),
            (
                include_str!("../tests/fixtures/bitwarden/export.csv"),
                Format::BitwardenCsv,
            ),
            (
                include_str!("../tests/fixtures/bitwarden/org.csv"),
                Format::BitwardenCsv,
            ),
            (
                include_str!("../tests/fixtures/lastpass/export.csv"),
                Format::LastPassCsv,
            ),
            (
                include_str!("../tests/fixtures/lastpass/formfill.csv"),
                Format::LastPassCsv,
            ),
            (
                include_str!("../tests/fixtures/nordpass/export.csv"),
                Format::NordPassCsv,
            ),
            (
                include_str!("../tests/fixtures/roboform/export.csv"),
                Format::RoboFormCsv,
            ),
            (
                include_str!("../tests/fixtures/onepassword/mac.csv"),
                Format::OnePasswordCsv,
            ),
            (
                include_str!("../tests/fixtures/onepassword/windows.csv"),
                Format::OnePasswordCsv,
            ),
        ];
        for (text, want) in cases {
            assert_eq!(format_of(text), Some(want), "{want:?}");
        }
    }

    #[test]
    fn finds_dashlane_csv_files_by_their_first_columns() {
        for text in [
            include_str!("../tests/fixtures/dashlane/credentials.csv"),
            include_str!("../tests/fixtures/dashlane/payments.csv"),
            include_str!("../tests/fixtures/dashlane/ids.csv"),
            include_str!("../tests/fixtures/dashlane/personalInfo.csv"),
            include_str!("../tests/fixtures/dashlane/securenotes.csv"),
        ] {
            assert_eq!(format_of(text), Some(Format::DashlaneCsv));
        }
    }

    #[test]
    fn finds_json_formats() {
        assert_eq!(
            format_of(include_str!("../tests/fixtures/bitwarden/export.json")),
            Some(Format::BitwardenJson)
        );
        assert_eq!(
            format_of(include_str!("../tests/fixtures/bitwarden/org.json")),
            Some(Format::BitwardenJson)
        );
        assert_eq!(
            format_of(include_str!("../tests/fixtures/keeper/export.json")),
            Some(Format::KeeperJson)
        );
        assert_eq!(
            format_of(include_str!("../tests/fixtures/enpass/export.json")),
            Some(Format::EnpassJson)
        );
        assert_eq!(
            format_of(include_str!("../tests/fixtures/protonpass/export.json")),
            Some(Format::ProtonPassJson)
        );
    }

    #[test]
    fn says_what_needs_a_password() {
        let protected = include_str!("../tests/fixtures/bitwarden/protected-pbkdf2.json");
        assert_eq!(
            detected(protected.as_bytes()),
            Ok(Detected {
                format: Format::BitwardenJson,
                encrypted: true
            })
        );
        let account = include_str!("../tests/fixtures/bitwarden/account-restricted.json");
        assert_eq!(detected(account.as_bytes()).map(|d| d.encrypted), Ok(true));
        let plain = include_str!("../tests/fixtures/bitwarden/export.json");
        assert_eq!(detected(plain.as_bytes()).map(|d| d.encrypted), Ok(false));
    }

    #[test]
    fn finds_binary_formats() {
        let pux = include_bytes!("../tests/fixtures/onepassword/sample.1pux");
        assert_eq!(detected(pux).map(|d| d.format), Ok(Format::OnePasswordPux));
        let dashlane = include_bytes!("../tests/fixtures/dashlane/export.zip");
        assert_eq!(
            detected(dashlane).map(|d| d.format),
            Ok(Format::DashlaneZip)
        );
        let kdbx = include_bytes!("../tests/fixtures/kdbx/v4-argon2d.kdbx");
        assert_eq!(
            detected(kdbx),
            Ok(Detected {
                format: Format::Kdbx,
                encrypted: true
            })
        );
        let pgp = include_bytes!("../tests/fixtures/protonpass/encrypted.pgp");
        assert_eq!(
            detected(pgp),
            Ok(Detected {
                format: Format::ProtonPassPgp,
                encrypted: true
            })
        );
        let armored = include_bytes!("../tests/fixtures/protonpass/encrypted.asc");
        assert_eq!(
            detected(armored).map(|d| d.format),
            Ok(Format::ProtonPassPgp)
        );
    }

    #[test]
    fn a_proton_zip_is_found_by_its_data_file() {
        let plain = crate::zip::build_stored_zip(&[("Proton Pass/data.json", b"{}".as_slice())]);
        assert_eq!(
            detected(&plain),
            Ok(Detected {
                format: Format::ProtonPassZip,
                encrypted: false
            })
        );
        let sealed = crate::zip::build_stored_zip(&[("Proton Pass/data.pgp", b"x".as_slice())]);
        assert_eq!(detected(&sealed).map(|d| d.encrypted), Ok(true));
        let other = crate::zip::build_stored_zip(&[("readme.txt", b"x".as_slice())]);
        assert_eq!(detected(&other), Err(ImportError::Unsupported));
    }

    #[test]
    fn unknown_and_damaged_input_is_unsupported() {
        for text in ["", "hello", "a,b\n1,2", "{}", "[1]", "{\"x\":1}", "{broken"] {
            assert_eq!(format_of(text), None, "{text}");
        }
        // KeePass 1 and a truncated KDBX header.
        assert_eq!(
            detected(&[0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5]),
            Err(ImportError::Unsupported)
        );
        assert_eq!(
            detected(&[0x03, 0xD9, 0xA2, 0x9A]),
            Err(ImportError::Unsupported)
        );
    }

    #[test]
    fn size_limits_apply_to_detection() {
        let limits = Limits::small();
        let big = vec![b'a'; limits.max_input_bytes + 1];
        assert!(matches!(
            detect(&big, &limits),
            Err(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn parse_finds_the_format_and_reads_it() {
        let csv = include_str!("../tests/fixtures/chrome/passwords.csv");
        let batch = parse(csv.as_bytes(), &ImportOptions::default()).expect("batch");
        assert_eq!(batch.format, Format::ChromeCsv);
        assert_eq!(batch.logins.len(), 4);

        let options = ImportOptions {
            format: Some(Format::FirefoxCsv),
            ..ImportOptions::default()
        };
        // Forced to another format, the file is read as that one (and refused when it doesn't fit).
        assert!(parse(b"a,b\n1,2", &options).is_err());

        let protected = include_str!("../tests/fixtures/bitwarden/protected-pbkdf2.json");
        let options = ImportOptions {
            password: Some("correct horse"),
            ..ImportOptions::default()
        };
        assert_eq!(
            parse(protected.as_bytes(), &options)
                .expect("batch")
                .logins
                .len(),
            1
        );
        assert_eq!(
            parse(protected.as_bytes(), &ImportOptions::default()).err(),
            Some(ImportError::PasswordRequired)
        );
    }

    #[test]
    fn every_format_is_wired_to_its_parser() {
        let limits = Limits::default();
        let ctx = Context::new(&limits);
        for format in Format::ALL {
            // Empty input is refused by every parser, none panics, and none is left a stub.
            let result = parse_as(format, b"", &ctx);
            assert!(result.is_err(), "{format:?}");
        }
    }
}
