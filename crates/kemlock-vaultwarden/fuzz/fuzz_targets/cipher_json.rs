//! A Vaultwarden `ciphers` row as the import reads it: the columns are text the old server's
//! users wrote, made into the JSON a client is served. The input is the cipher type, then the
//! name, notes, fields, password history, key and data columns, one per line (the data is the
//! rest). A type Vaultwarden doesn't serve gives nothing, and every other row gives JSON.

#![no_main]

use kemlock_vaultwarden::cipher_json::{
    CipherParts, ViewerState, apply_viewer, base_json, lcase_keys, type_key,
};
use kemlock_vaultwarden::vwtime::parse_db_time;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(value) = serde_json::from_str(text) {
        let _ = lcase_keys(value);
    }

    let stamp = parse_db_time("2026-11-07 10:00:00.123456").expect("a valid time");
    let mut columns = text.splitn(7, '\n');
    let mut next = || columns.next().unwrap_or("");
    let atype = next().trim().parse::<i64>().unwrap_or(1);
    let (name, notes, fields, history, key) = (next(), next(), next(), next(), next());
    let parts = CipherParts {
        id: "cipher",
        created_at: stamp,
        updated_at: stamp,
        deleted_at: None,
        organization_uuid: None,
        key: Some(key),
        atype,
        name,
        notes: Some(notes),
        fields: Some(fields),
        data: next(),
        password_history: Some(history),
        reprompt: Some(0),
    };
    let json = base_json(&parts, &[]);
    assert_eq!(
        json.is_some(),
        type_key(atype).is_some(),
        "only a cipher type Vaultwarden serves has JSON"
    );
    if let Some(mut json) = json {
        apply_viewer(&mut json, &ViewerState::default());
        let _ = json.to_string();
    }
});
