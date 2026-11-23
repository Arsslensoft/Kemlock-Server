//! Bitwarden `EncString`s in every field of a cipher: kept byte for byte, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| kemlock_api_bw::fuzzing::enc_string(data));
