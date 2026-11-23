//! WebAssembly tests: they run in node (`wasm-pack test --node crates/kemlock-import-wasm`), through
//! the same functions the worker calls, on `kemlock-import`'s fixtures.

use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{ops, wasm};
use kemlock_import::bwcrypto::Kdf;

const CHROME: &str = include_str!("../../kemlock-import/tests/fixtures/chrome/passwords.csv");
const PBKDF2: &str =
    include_str!("../../kemlock-import/tests/fixtures/bitwarden/protected-pbkdf2.json");
const KDBX: &[u8] = include_bytes!("../../kemlock-import/tests/fixtures/kdbx/v3-aes.kdbx");
const PASSWORD: &str = "correct horse";

/// The `message` of a thrown error: the code the page shows.
fn message(error: JsError) -> String {
    let value = JsValue::from(error);
    js_sys::Reflect::get(&value, &JsValue::from_str("message"))
        .ok()
        .and_then(|m| m.as_string())
        .unwrap_or_default()
}

fn error_of<T>(result: Result<T, JsError>) -> String {
    match result {
        Ok(_) => String::from("no error"),
        Err(error) => message(error),
    }
}

fn parsed(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("JSON")
}

#[wasm_bindgen_test]
fn detect_names_the_format_and_whether_it_needs_a_password() {
    let found = parsed(&wasm::detect(CHROME.as_bytes()).expect("detect"));
    assert_eq!(found["format"], "chrome-csv");
    assert_eq!(found["encrypted"], false);
    let found = parsed(&wasm::detect(PBKDF2.as_bytes()).expect("detect"));
    assert_eq!(found["format"], "bitwarden-json");
    assert_eq!(found["encrypted"], true);
    let found = parsed(&wasm::detect(KDBX).expect("detect"));
    assert_eq!(found["format"], "kdbx");
    assert_eq!(error_of(wasm::detect(b"nothing known")), "unsupported");
}

#[wasm_bindgen_test]
fn parse_returns_the_batch_and_names_what_went_wrong() {
    let batch = parsed(&wasm::parse(CHROME.as_bytes(), None, None, None).expect("parse"));
    assert_eq!(batch["logins"][0]["name"], "Example Mail");

    let open = wasm::parse(
        PBKDF2.as_bytes(),
        Some("bitwarden-json".to_string()),
        Some(PASSWORD.to_string()),
        None,
    );
    assert_eq!(parsed(&open.expect("parse"))["format"], "bitwarden-json");

    assert_eq!(
        error_of(wasm::parse(PBKDF2.as_bytes(), None, None, None)),
        "password-required"
    );
    assert_eq!(
        error_of(wasm::parse(
            PBKDF2.as_bytes(),
            None,
            Some("wrong".to_string()),
            None
        )),
        "bad-password"
    );
    assert_eq!(
        error_of(wasm::parse(
            CHROME.as_bytes(),
            Some("no-such-format".to_string()),
            None,
            None
        )),
        "malformed"
    );
    // A KDBX file opens with its password.
    let kdbx = wasm::parse(KDBX, None, Some(PASSWORD.to_string()), None);
    assert_eq!(parsed(&kdbx.expect("parse"))["format"], "kdbx");
}

#[wasm_bindgen_test]
fn an_export_is_written_with_the_browsers_random_source_and_reads_back() {
    // The smallest Argon2id an import accepts, so the test stays quick: `exportEncrypted` itself
    // uses the 64 MiB default.
    let fast = Kdf::Argon2id {
        iterations: 2,
        memory_mib: 16,
        parallelism: 1,
    };
    let items = r#"[{"id":"11111111-1111-4111-8111-111111111111","kind":"login",
        "data":{"name":"Mail","username":"ada","password":"pw"}}]"#;
    let fill = |buf: &mut [u8]| getrandom::fill(buf).is_ok();
    let one = ops::export_with("bitwarden-json", items, PASSWORD, fast, fill).expect("export");
    let two = ops::export_with("bitwarden-json", items, PASSWORD, fast, fill).expect("export");
    assert_ne!(one, two, "a fresh salt and IVs every time");

    let batch = parsed(
        &wasm::parse(&one, None, Some(PASSWORD.to_string()), None).expect("the export reads back"),
    );
    assert_eq!(batch["logins"][0]["password"], "pw");
}

#[wasm_bindgen_test]
fn export_names_what_it_refuses() {
    assert_eq!(
        error_of(wasm::export_encrypted(
            "csv",
            "[]".to_string(),
            PASSWORD.to_string()
        )),
        "unsupported"
    );
    assert_eq!(
        error_of(wasm::export_encrypted(
            "bitwarden-json",
            "{}".to_string(),
            PASSWORD.to_string()
        )),
        "malformed"
    );
    assert_eq!(
        error_of(wasm::export_encrypted(
            "bitwarden-json",
            "[]".to_string(),
            String::new()
        )),
        "password-required"
    );
}
