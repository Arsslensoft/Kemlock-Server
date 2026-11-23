//! A cipher request body: parsed, checked as an import, applied and served back.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| kemlock_api_bw::fuzzing::cipher_request(data));
