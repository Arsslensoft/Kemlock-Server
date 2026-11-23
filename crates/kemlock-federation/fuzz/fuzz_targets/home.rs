//! Promotion records and home records.

#![no_main]

use kemlock_federation::home::{HomeRecord, PromotionRecord};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = PromotionRecord::from_body(data) {
        assert_eq!(
            record.to_body(),
            data,
            "a promotion re-encodes to its input"
        );
    }
    if let Ok(record) = HomeRecord::from_body(data) {
        assert_eq!(
            record.to_body(),
            data,
            "a home record re-encodes to its input"
        );
    }
});
