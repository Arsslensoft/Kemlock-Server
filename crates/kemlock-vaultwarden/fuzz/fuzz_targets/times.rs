//! The dates in a Vaultwarden database and in cipher JSON, and the sizes printed beside them.

#![no_main]

use kemlock_vaultwarden::vwtime::{
    display_size, format_date, parse_db_time, to_utc, validate_and_format_date,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut eight = [0u8; 8];
    for (to, from) in eight.iter_mut().zip(data) {
        *to = *from;
    }
    let _ = display_size(i64::from_le_bytes(eight));

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(time) = parse_db_time(text) {
        let printed = format_date(time);
        assert!(
            parse_db_time(&printed).is_some(),
            "a date prints as one that reads back"
        );
        let _ = to_utc(time);
    }
    let once = validate_and_format_date(text);
    assert_eq!(
        validate_and_format_date(&once),
        once,
        "formatting a date twice changes nothing"
    );
});
