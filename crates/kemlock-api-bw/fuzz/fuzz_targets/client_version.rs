//! The `Bitwarden-Client-Version` header.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| kemlock_api_bw::fuzzing::client_version(data));
