#![no_main]
//! Fuzzes Bitwarden `EncString` parsing and opening, with a fixed key.

use kemlock_import::bwcrypto::{ExportKey, decrypt_enc_string};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = ExportKey::new([1; 32], [2; 32]);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decrypt_enc_string(text, &key);
    }
});
