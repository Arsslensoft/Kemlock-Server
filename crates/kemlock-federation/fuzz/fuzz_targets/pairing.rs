//! Pairing: the code as a person types it, and the first pairing message.

#![no_main]

use kemlock_federation::identity::LocalIdentity;
use kemlock_federation::pairing::{PairingCode, respond};
use kemlock_federation::testing::identity;
use kemlock_federation::{Suite, unix_now};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn local() -> &'static LocalIdentity {
    static LOCAL: OnceLock<LocalIdentity> = OnceLock::new();
    LOCAL.get_or_init(|| identity(1, unix_now(), &Suite::IMPLEMENTED))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(code) = PairingCode::parse(text) {
            // A code that parses shows as three groups of four.
            assert_eq!(code.display().len(), 14);
        }
    }
    let _ = respond(PairingCode::generate(), local(), data);
});
