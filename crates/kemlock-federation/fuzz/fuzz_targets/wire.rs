//! Change keys and their packed lists.

#![no_main]

use kemlock_federation::wire::{ChangeKey, pack_keys, unpack_keys};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(keys) = unpack_keys(data) {
        assert_eq!(pack_keys(&keys), data);
    }
    let _ = ChangeKey::from_bytes(data);
});
