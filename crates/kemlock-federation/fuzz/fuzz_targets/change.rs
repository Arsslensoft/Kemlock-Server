//! Change records: the body, and the signed envelope against an empty directory of keys.

#![no_main]

use kemlock_federation::change::{self, ChangeRecord};
use kemlock_federation::testing::directory;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = ChangeRecord::from_body(data) {
        assert_eq!(record.to_body(), data, "a record re-encodes to its input");
        let _ = record.to_item();
    }
    let none = directory(&[]);
    assert!(
        change::open(data, &none).is_err(),
        "no key is held, so nothing opens"
    );
});
