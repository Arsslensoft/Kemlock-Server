//! The manifest inside an archive: what parses writes back out and parses to the same manifest.

#![no_main]

use kemlock_backup::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = Manifest::from_json(data) {
        let _ = manifest.total_rows();
        let written = manifest.to_json().expect("a manifest serialises");
        let again = Manifest::from_json(&written).expect("what was written reads back");
        assert_eq!(again, manifest);
    }
});
