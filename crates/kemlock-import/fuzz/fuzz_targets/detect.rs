#![no_main]
//! Fuzzes format detection and the one-call `parse`.

use kemlock_import::{ImportOptions, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::small();
    let _ = kemlock_import::detect(data, &limits);
    let options = ImportOptions {
        password: Some("fuzz"),
        key_file: Some(b"fuzz"),
        limits,
        ..ImportOptions::default()
    };
    let _ = kemlock_import::parse(data, &options);
});
