//! What the import worker does, in plain Rust: nothing here knows about JavaScript, so the tests
//! drive it directly and `wasm.rs` is a thin skin over it.
//!
//! Every failure is a [`Code`], the name the page shows an error under; none says more than
//! `kemlock-import`'s own error does, and none carries a byte of the file.

use kemlock_import::bitwarden_export::{self, DEFAULT_KDF, Entropy, ExportKind};
use kemlock_import::bwcrypto::Kdf;
use kemlock_import::{Format, ImportError, ImportOptions, Limits};
use serde::Serialize;

/// Why an operation failed: `kemlock_import::ImportError`'s variant in kebab-case, plus
/// `Unavailable` when the random source the export needs failed. These are the codes of
/// `ImportErrorCode` in web/src/import/contract.ts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    TooLarge,
    LimitExceeded,
    Unsupported,
    Empty,
    Malformed,
    PasswordRequired,
    BadPassword,
    KdfOutOfBounds,
    AccountRestricted,
    UnsupportedEncryption,
    Unavailable,
}

impl Code {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Code::TooLarge => "too-large",
            Code::LimitExceeded => "limit-exceeded",
            Code::Unsupported => "unsupported",
            Code::Empty => "empty",
            Code::Malformed => "malformed",
            Code::PasswordRequired => "password-required",
            Code::BadPassword => "bad-password",
            Code::KdfOutOfBounds => "kdf-out-of-bounds",
            Code::AccountRestricted => "account-restricted",
            Code::UnsupportedEncryption => "unsupported-encryption",
            Code::Unavailable => "unavailable",
        }
    }
}

impl From<&ImportError> for Code {
    fn from(error: &ImportError) -> Code {
        match error {
            ImportError::TooLarge { .. } => Code::TooLarge,
            ImportError::LimitExceeded(_) => Code::LimitExceeded,
            ImportError::Unsupported => Code::Unsupported,
            ImportError::Empty => Code::Empty,
            ImportError::Malformed(_) => Code::Malformed,
            ImportError::PasswordRequired => Code::PasswordRequired,
            ImportError::BadPassword => Code::BadPassword,
            ImportError::KdfOutOfBounds => Code::KdfOutOfBounds,
            ImportError::AccountRestricted => Code::AccountRestricted,
            ImportError::UnsupportedEncryption(_) => Code::UnsupportedEncryption,
        }
    }
}

impl From<ImportError> for Code {
    fn from(error: ImportError) -> Code {
        Code::from(&error)
    }
}

/// The answer to [`detect`]: the format's name as the page knows it, and whether opening it takes
/// a password.
#[derive(Serialize)]
struct Detected {
    format: Format,
    encrypted: bool,
}

/// Which format `bytes` are, without decrypting anything: `{"format": "...", "encrypted": ...}`.
pub(crate) fn detect(bytes: &[u8]) -> Result<String, Code> {
    let found = kemlock_import::detect(bytes, &Limits::default())?;
    to_json(&Detected {
        format: found.format,
        encrypted: found.encrypted,
    })
}

/// The format a name stands for (`"bitwarden-json"`, kebab-case); anything else is refused.
fn format_of(name: &str) -> Result<Format, Code> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).map_err(|_| Code::Malformed)
}

/// Reads an export into the batch, as the crate's own JSON (snake_case fields, kebab-case enum
/// values, file bytes as standard base64). `format` is detected when absent; a blank password is
/// none.
pub(crate) fn parse(
    bytes: &[u8],
    format: Option<&str>,
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<String, Code> {
    let options = ImportOptions {
        format: format.map(format_of).transpose()?,
        password: password.filter(|p| !p.is_empty()),
        key_file: key_file.filter(|k| !k.is_empty()),
        limits: Limits::default(),
    };
    let batch = kemlock_import::parse(bytes, &options)?;
    to_json(&batch)
}

fn to_json<T: Serialize>(value: &T) -> Result<String, Code> {
    serde_json::to_string(value).map_err(|_| Code::Malformed)
}

/// Which export a name asks for.
fn kind_of(name: &str) -> Result<ExportKind, Code> {
    match name {
        "bitwarden-json" => Ok(ExportKind::Bitwarden),
        "kemlock-json" => Ok(ExportKind::Kemlock),
        _ => Err(Code::Unsupported),
    }
}

/// Writes a password-protected export of `items_json` (a JSON list of `{id, kind, data}`), with
/// the KDF `kdf` and random bytes from `fill`.
pub(crate) fn export_with(
    kind: &str,
    items_json: &str,
    password: &str,
    kdf: Kdf,
    fill: impl FnMut(&mut [u8]) -> bool,
) -> Result<Vec<u8>, Code> {
    let kind = kind_of(kind)?;
    let items = bitwarden_export::parse_items(items_json)?;
    let mut fill = fill;
    let mut failed = false;
    let entropy = Entropy::from_fn(|buf| failed |= !fill(buf));
    if failed {
        return Err(Code::Unavailable);
    }
    Ok(bitwarden_export::write_with(kind, &items, password, kdf, &entropy)?.into_bytes())
}

/// [`export_with`] with the default KDF and the operating system's random source (in the browser,
/// `crypto.getRandomValues`).
pub(crate) fn export_encrypted(
    kind: &str,
    items_json: &str,
    password: &str,
) -> Result<Vec<u8>, Code> {
    export_with(kind, items_json, password, DEFAULT_KDF, |buf| {
        getrandom::fill(buf).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CHROME: &str = include_str!("../../kemlock-import/tests/fixtures/chrome/passwords.csv");
    const PLAIN: &str = include_str!("../../kemlock-import/tests/fixtures/bitwarden/export.json");
    const PBKDF2: &str =
        include_str!("../../kemlock-import/tests/fixtures/bitwarden/protected-pbkdf2.json");
    const ACCOUNT: &str =
        include_str!("../../kemlock-import/tests/fixtures/bitwarden/account-restricted.json");
    const KDBX: &[u8] = include_bytes!("../../kemlock-import/tests/fixtures/kdbx/v3-aes.kdbx");
    const KDBX_V4: &[u8] =
        include_bytes!("../../kemlock-import/tests/fixtures/kdbx/v4-argon2d.kdbx");
    const KEY_FILE: &[u8] = include_bytes!("../../kemlock-import/tests/fixtures/kdbx/fixture.keyx");
    const PASSWORD: &str = "correct horse";

    /// Small, so the tests stay quick: the least Argon2id an import accepts.
    const FAST: Kdf = Kdf::Argon2id {
        iterations: 2,
        memory_mib: 16,
        parallelism: 1,
    };

    fn counting(buf: &mut [u8]) -> bool {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("small");
        }
        true
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("JSON")
    }

    #[test]
    fn codes_are_the_names_the_page_knows() {
        let all = [
            (Code::TooLarge, "too-large"),
            (Code::LimitExceeded, "limit-exceeded"),
            (Code::Unsupported, "unsupported"),
            (Code::Empty, "empty"),
            (Code::Malformed, "malformed"),
            (Code::PasswordRequired, "password-required"),
            (Code::BadPassword, "bad-password"),
            (Code::KdfOutOfBounds, "kdf-out-of-bounds"),
            (Code::AccountRestricted, "account-restricted"),
            (Code::UnsupportedEncryption, "unsupported-encryption"),
            (Code::Unavailable, "unavailable"),
        ];
        for (code, name) in all {
            assert_eq!(code.as_str(), name);
        }
        assert_eq!(Code::from(ImportError::malformed("x")), Code::Malformed);
        assert_eq!(
            Code::from(&ImportError::TooLarge { limit: 1 }),
            Code::TooLarge
        );
        assert_eq!(
            Code::from(ImportError::UnsupportedEncryption("x".into())),
            Code::UnsupportedEncryption
        );
        assert_eq!(
            Code::from(ImportError::LimitExceeded("x")),
            Code::LimitExceeded
        );
    }

    #[test]
    fn detects_the_format_and_whether_it_needs_a_password() {
        let found = json(&detect(CHROME.as_bytes()).expect("detect"));
        assert_eq!(found["format"], "chrome-csv");
        assert_eq!(found["encrypted"], false);
        let found = json(&detect(PBKDF2.as_bytes()).expect("detect"));
        assert_eq!(found["format"], "bitwarden-json");
        assert_eq!(found["encrypted"], true);
        let found = json(&detect(KDBX).expect("detect"));
        assert_eq!(found["format"], "kdbx");
        assert_eq!(found["encrypted"], true);
        assert_eq!(detect(b"not an export at all"), Err(Code::Unsupported));
        assert_eq!(detect(b""), Err(Code::Unsupported));
    }

    #[test]
    fn parses_into_the_batch_the_page_reads() {
        let batch = json(&parse(CHROME.as_bytes(), None, None, None).expect("parse"));
        assert_eq!(batch["format"], "chrome-csv");
        assert_eq!(batch["logins"][0]["name"], "Example Mail");
        assert_eq!(batch["logins"][0]["username"], "ada@example.com");
        // snake_case fields, as web/src/import/contract.ts has them.
        assert!(batch["logins"][0]["meta"]["created_ms"].is_null());
        assert!(batch["logins"][0]["previous_passwords"].is_array());
        assert!(batch["ssh_keys"].is_array() && batch["skipped"].is_array());

        // The format can be named, and must be a format.
        let named =
            json(&parse(PLAIN.as_bytes(), Some("bitwarden-json"), None, None).expect("parse"));
        assert_eq!(named["format"], "bitwarden-json");
        assert_eq!(named["logins"][0]["uris"][1]["match_rule"], "exact");
        assert_eq!(
            parse(PLAIN.as_bytes(), Some("not-a-format"), None, None),
            Err(Code::Malformed)
        );
        assert_eq!(
            parse(PLAIN.as_bytes(), Some("BitwardenJson"), None, None),
            Err(Code::Malformed)
        );
    }

    #[test]
    fn an_encrypted_export_asks_for_its_password_and_names_a_wrong_one() {
        for none in [None, Some("")] {
            assert_eq!(
                parse(PBKDF2.as_bytes(), None, none, None),
                Err(Code::PasswordRequired)
            );
        }
        assert_eq!(
            parse(PBKDF2.as_bytes(), None, Some("wrong"), None),
            Err(Code::BadPassword)
        );
        let batch = json(&parse(PBKDF2.as_bytes(), None, Some(PASSWORD), None).expect("parse"));
        assert_eq!(batch["format"], "bitwarden-json");
        assert!(!batch["logins"].as_array().expect("logins").is_empty());
    }

    #[test]
    fn says_why_a_file_can_not_be_read() {
        assert_eq!(
            parse(ACCOUNT.as_bytes(), None, Some(PASSWORD), None),
            Err(Code::AccountRestricted)
        );
        assert_eq!(parse(b"", None, None, None), Err(Code::Unsupported));
        assert_eq!(
            parse(b"name,url,username,password,note\n", None, None, None),
            Err(Code::Empty)
        );
        // A KDBX file with the wrong password.
        assert_eq!(
            parse(KDBX, None, Some("wrong"), None),
            Err(Code::BadPassword)
        );
        let huge = vec![b'a'; 33 * 1024 * 1024];
        assert_eq!(detect(&huge), Err(Code::TooLarge));
    }

    #[test]
    fn opens_a_kdbx_file_with_its_password_and_key_file() {
        let batch = json(&parse(KDBX, None, Some(PASSWORD), None).expect("parse"));
        assert_eq!(batch["format"], "kdbx");
        assert!(!batch["logins"].as_array().expect("logins").is_empty());
        // The version 4 file needs both, and a key file is optional input: a blank one is none.
        let both = parse(KDBX_V4, None, Some(PASSWORD), Some(KEY_FILE)).expect("parse");
        assert_eq!(json(&both)["format"], "kdbx");
        assert!(parse(KDBX_V4, None, Some(PASSWORD), None).is_err());
        assert_eq!(
            parse(KDBX_V4, None, Some(PASSWORD), Some(&[])),
            parse(KDBX_V4, None, Some(PASSWORD), None)
        );
    }

    #[test]
    fn exports_read_back_through_parse() {
        let items = r#"[
            {"id":"11111111-1111-4111-8111-111111111111","kind":"login",
             "data":{"name":"Mail","username":"ada","password":"pw","uris":[{"uri":"https://mail.example"}]}},
            {"id":"22222222-2222-4222-8222-222222222222","kind":"note",
             "data":{"name":"Wifi","text":"on the fridge"}}
        ]"#;
        for kind in ["bitwarden-json", "kemlock-json"] {
            let bytes = export_with(kind, items, PASSWORD, FAST, counting).expect("export");
            let text = String::from_utf8(bytes.clone()).expect("UTF-8");
            assert!(text.starts_with("{\n  \"encrypted\": true,"));
            let found = json(&detect(&bytes).expect("detect"));
            assert_eq!(found["format"], "bitwarden-json");
            assert_eq!(found["encrypted"], true);
            let batch = json(&parse(&bytes, None, Some(PASSWORD), None).expect("parse"));
            assert_eq!(batch["logins"][0]["name"], "Mail");
            assert_eq!(batch["logins"][0]["password"], "pw");
            assert_eq!(batch["notes"][0]["text"], "on the fridge");
            assert_eq!(
                parse(&bytes, None, Some("wrong"), None),
                Err(Code::BadPassword)
            );
        }
    }

    #[test]
    fn an_export_refuses_what_it_can_not_write() {
        let none = |_: &mut [u8]| true;
        assert_eq!(
            export_with("csv", "[]", PASSWORD, FAST, none),
            Err(Code::Unsupported)
        );
        assert_eq!(
            export_with("bitwarden-json", "{}", PASSWORD, FAST, none),
            Err(Code::Malformed)
        );
        assert_eq!(
            export_with("bitwarden-json", "[]", "", FAST, none),
            Err(Code::PasswordRequired)
        );
        assert_eq!(
            export_with(
                "bitwarden-json",
                "[]",
                PASSWORD,
                Kdf::Argon2id {
                    iterations: 1,
                    memory_mib: 16,
                    parallelism: 1
                },
                none
            ),
            Err(Code::KdfOutOfBounds)
        );
        // A random source that fails is "unavailable", and nothing is written.
        assert_eq!(
            export_with("bitwarden-json", "[]", PASSWORD, FAST, |_| false),
            Err(Code::Unavailable)
        );
    }

    #[test]
    fn every_export_draws_fresh_random_bytes() {
        let calls = std::cell::Cell::new(0u8);
        let count = |buf: &mut [u8]| {
            calls.set(calls.get() + 1);
            buf.fill(calls.get());
            true
        };
        export_with("bitwarden-json", "[]", PASSWORD, FAST, count).expect("export");
        // The salt, the validation GUID and both IVs.
        assert_eq!(calls.get(), 4);
        let a = export_with("bitwarden-json", "[]", PASSWORD, FAST, |b| {
            b.fill(1);
            true
        })
        .expect("export");
        let b = export_with("bitwarden-json", "[]", PASSWORD, FAST, |b| {
            b.fill(2);
            true
        })
        .expect("export");
        assert_ne!(a, b);
    }

    #[test]
    fn the_default_export_uses_the_operating_systems_random_source() {
        // Natively `getrandom` reads the OS; in the browser it is `crypto.getRandomValues`.
        let one = export_encrypted("kemlock-json", "[]", PASSWORD).expect("export");
        let two = export_encrypted("kemlock-json", "[]", PASSWORD).expect("export");
        assert_ne!(one, two, "a fresh salt and IVs every time");
        let text = String::from_utf8(one).expect("UTF-8");
        assert!(text.contains("\"kdfType\": 1,\n  \"kdfIterations\": 3,\n  \"kdfMemory\": 64,\n  \"kdfParallelism\": 4,"));
    }
}
