//! The JavaScript skin over [`ops`]: three functions the import worker calls.
//!
//! Every failure is a `JsError` whose message is an `ImportErrorCode` of
//! web/src/import/contract.ts and nothing else. The password and the items an export is made from
//! are copied into this module's memory by the call; they are wiped when it ends.

// wasm-bindgen's generated glue is `unsafe`; nothing written by hand in this crate is.
#![allow(unsafe_code)]
// The exports are reached from JavaScript, not through the crate root.
#![allow(unreachable_pub)]

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::ops::{self, Code};

fn fail(code: Code) -> JsError {
    JsError::new(code.as_str())
}

/// Which format `bytes` are, without decrypting anything: `{"format": "...", "encrypted": ...}`.
/// Fails with `unsupported` when it is none, and with `too-large` over the size limit.
#[wasm_bindgen]
pub fn detect(bytes: &[u8]) -> Result<String, JsError> {
    ops::detect(bytes).map_err(fail)
}

/// Reads an export and returns the `ImportBatch` as JSON. `format` (kebab-case, `bitwarden-json`)
/// is detected when absent; `password` opens an encrypted export; `key_file` is a KDBX key file.
#[wasm_bindgen]
pub fn parse(
    bytes: &[u8],
    format: Option<String>,
    mut password: Option<String>,
    key_file: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let result = ops::parse(
        bytes,
        format.as_deref(),
        password.as_deref(),
        key_file.as_deref(),
    );
    if let Some(password) = password.as_mut() {
        password.zeroize();
    }
    if let Some(mut key_file) = key_file {
        key_file.zeroize();
    }
    result.map_err(fail)
}

/// Writes a password-protected export: `kind` is `bitwarden-json` or `kemlock-json`, `items_json`
/// a JSON list of `{ id, kind, data }`. Returns the file's bytes.
#[wasm_bindgen(js_name = exportEncrypted)]
pub fn export_encrypted(
    kind: &str,
    mut items_json: String,
    mut password: String,
) -> Result<Vec<u8>, JsError> {
    let result = ops::export_encrypted(kind, &items_json, &password);
    items_json.zeroize();
    password.zeroize();
    result.map_err(fail)
}
