//! A stored cipher, as an item's ciphertext holds it, rendered for a sync.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| kemlock_api_bw::fuzzing::stored_cipher(data));
