//! The signed descriptor: the envelope, the body, and verification of whatever parses.

#![no_main]

use kemlock_federation::descriptor::{Descriptor, SignedDescriptor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = SignedDescriptor::parse(data) {
        // A random envelope never verifies, but verifying it must not panic.
        let _ = signed.verify(1_800_000_000, None);
        let _ = signed.to_bytes();
    }
    let _ = Descriptor::from_body(data);
});
