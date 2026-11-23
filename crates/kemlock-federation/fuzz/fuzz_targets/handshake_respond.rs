//! The responder's whole first-message path: whatever arrives as a hello is refused, never a
//! panic. (A random message is never from a paired peer.)

#![no_main]

use kemlock_federation::handshake::{NonceCache, respond};
use kemlock_federation::identity::LocalIdentity;
use kemlock_federation::testing::{directory, identity};
use kemlock_federation::{Padding, Suite, unix_now};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct Parties {
    local: LocalIdentity,
    peer: LocalIdentity,
}

fn parties() -> &'static Parties {
    static PARTIES: OnceLock<Parties> = OnceLock::new();
    PARTIES.get_or_init(|| {
        let now = unix_now();
        Parties {
            local: identity(1, now, &Suite::IMPLEMENTED),
            peer: identity(2, now, &Suite::IMPLEMENTED),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let p = parties();
    let keys = directory(&[&p.peer]);
    let outcome = respond(
        &p.local,
        &keys,
        &mut NonceCache::new(),
        data,
        unix_now(),
        Padding::Off,
    );
    assert!(outcome.is_err(), "a fuzzed hello must not be accepted");
});
