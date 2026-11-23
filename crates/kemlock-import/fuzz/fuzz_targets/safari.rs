#![no_main]
//! Fuzzes `kemlock_import::safari::parse`: any bytes, with a password and a key file, small limits.

use kemlock_import::{Context, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::small();
    let ctx = Context::new(&limits)
        .with_password("fuzz")
        .with_key_file(b"fuzz");
    let _ = kemlock_import::safari::parse(data, &ctx);
});
