//! The deterministic CBOR decoder: never panics, and what it accepts re-encodes to its input.

#![no_main]

use kemlock_federation::cbor::Value;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = Value::decode(data) {
        assert_eq!(
            value.encode(),
            data,
            "a decoded value must re-encode to its input"
        );
    }
});
