#![no_main]
//! Fuzzes the ZIP reader: the directory, then every entry, under small limits.

use kemlock_import::{Limits, zip::Zip};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::small();
    if let Ok(mut zip) = Zip::open(data, &limits) {
        for index in 0..zip.entries().len() {
            let _ = zip.read(index);
        }
    }
});
