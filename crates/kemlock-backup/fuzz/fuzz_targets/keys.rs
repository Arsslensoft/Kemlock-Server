//! The age recipient and identity an operator pastes into the settings or an identity file.

#![no_main]

use kemlock_backup::{parse_identity, parse_recipient};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_recipient(text);
        let _ = parse_identity(text);
    }
});
