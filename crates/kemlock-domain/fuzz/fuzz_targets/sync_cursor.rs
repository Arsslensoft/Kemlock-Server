//! The sync cursor a client sends back, in both versions. What parses writes back out and parses
//! to the same cursor, and a version 2 cursor is canonical: it writes out as the bytes it came
//! from, so one cursor has one spelling.

#![no_main]

use kemlock_domain::{SyncCursor, VersionVector};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = VersionVector::from_cursor_bytes(data);
    let Ok(cursor) = SyncCursor::from_cursor_bytes(data) else {
        return;
    };
    let written = cursor.to_cursor_bytes();
    assert_eq!(
        SyncCursor::from_cursor_bytes(&written).as_ref(),
        Ok(&cursor),
        "a cursor changes when it is written and read"
    );
    if data.first() == Some(&SyncCursor::CURSOR_VERSION) {
        assert_eq!(written, data, "a version 2 cursor has one spelling");
    }
    let _ = cursor.merged();
});
