//! One item on the wire: what parses writes back out and parses again as the same item, and is
//! turned into a write without a panic.

#![no_main]

use kemlock_api_kem::dto::ItemDto;
use kemlock_domain::Revision;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(dto) = serde_json::from_slice::<ItemDto>(data) else {
        return;
    };
    let written = serde_json::to_vec(&dto).expect("an item DTO serialises");
    let again: ItemDto = serde_json::from_slice(&written).expect("what was written reads back");
    assert_eq!(again, dto, "an item changes when it is written and read");
    let _ = dto.clone().into_write(None);
    let _ = dto.into_write(Some(Revision(1)));
});
