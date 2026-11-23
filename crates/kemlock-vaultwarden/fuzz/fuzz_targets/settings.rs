//! The text of Vaultwarden's `config.json`.

#![no_main]

use kemlock_vaultwarden::settings::map_settings;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = map_settings(Some(text));
    }
});
