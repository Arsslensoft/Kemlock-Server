#![no_main]
//! Fuzzes the CSV reader.

use kemlock_import::csv::{CsvOptions, Table, split_row};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for backslash_escape in [false, true] {
        let table = Table::parse(&text, CsvOptions { backslash_escape }, 100);
        for record in table.records() {
            let _ = record.get("name");
            let _ = record.extra();
        }
    }
    let _ = split_row(&text);
});
