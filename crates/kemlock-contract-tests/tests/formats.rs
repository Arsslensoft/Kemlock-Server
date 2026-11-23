//! The strings Kemlock writes into Vaultwarden items, `formats.json` and `vault-items.json`,
//! written through `POST` and `PUT /api/ciphers` and read back through `/api/sync` byte for byte.
//!
//! Kemlock's phones that move, and phones on other versions, read these strings
//! (`kemlock/mobile/test/features/sync/vaultwarden/formats_test.dart:2` and
//! `items_formats_test.dart:2`: "phones running other versions read them, so a later version ..."),
//! and the design says: "Staying on Vaultwarden ... What it writes stays byte for byte as
//! `formats.json` and `vault-items.json` pin it".
//!
//! Each string is sent two ways. Wrapped, it is the "ciphertext" of an encrypted string, which is
//! what a real client sends: the server never sees the text itself. Bare, it is the field's value
//! as it is: a server that stores `fields` as JSON must not change a quote, a line end, a
//! non-breaking space or an emoji either (Vaultwarden does not check an encrypted string's shape
//! in `fields`, so this is how it behaves too).

use kemlock_contract_tests::account::{as_write, login_cipher};
use kemlock_contract_tests::enc::{enc, enc_bytes};
use kemlock_contract_tests::{fixtures, fresh_session};
use serde_json::{Value, json};

/// Every string of the fixture but its `about` note, with its path.
fn leaves(file: &str) -> Vec<(String, String)> {
    fixtures::strings(&fixtures::json(file))
        .into_iter()
        .filter(|(path, _)| path != "$.about")
        .collect()
}

fn field(name: &str, value: Value) -> Value {
    json!({"type": 1, "name": enc(name), "value": value, "linkedId": null})
}

/// The fields for `leaves`, in the order `order` gives, as a client sends them.
fn fields_for(leaves: &[(String, String)], order: &[usize], wrapped: bool) -> Vec<Value> {
    order
        .iter()
        .map(|&i| {
            let (path, text) = &leaves[i];
            let value = if wrapped {
                json!(enc_bytes(text.as_bytes()))
            } else {
                json!(text)
            };
            field(path, value)
        })
        .collect()
}

fn assert_fields(what: &str, expected: &[Value], paths: &[&str], got: &Value) {
    let list = got
        .as_array()
        .unwrap_or_else(|| panic!("{what}: fields is a list, got {got}"));
    assert_eq!(
        list.len(),
        expected.len(),
        "{what}: the same number of fields comes back"
    );
    for (i, (want, path)) in expected.iter().zip(paths).enumerate() {
        assert_eq!(
            &list[i], want,
            "{what}: field {i} (the fixture's {path}) must come back byte for byte; Vaultwarden \
             stores `fields` exactly as they were sent"
        );
    }
}

async fn write_and_read_back(file: &str, wrapped: bool) {
    let all = leaves(file);
    assert!(
        all.len() > 8,
        "{file} holds a good number of strings, found {}",
        all.len()
    );
    let forward: Vec<usize> = (0..all.len()).collect();
    let reverse: Vec<usize> = (0..all.len()).rev().collect();
    let forward_paths: Vec<&str> = forward.iter().map(|&i| all[i].0.as_str()).collect();
    let reverse_paths: Vec<&str> = reverse.iter().map(|&i| all[i].0.as_str()).collect();
    let mode = if wrapped { "wrapped" } else { "bare" };
    let what = format!("{file} ({mode})");

    // A short string for the notes, as the apps put one there: the home note's text
    let short: Vec<&(String, String)> = all.iter().filter(|(_, text)| text.len() < 3000).collect();
    let note = |i: usize| {
        let text = &short[i % short.len()].1;
        if wrapped {
            json!(enc_bytes(text.as_bytes()))
        } else {
            json!(text)
        }
    };

    let s = fresh_session().await;
    let mut body = login_cipher(&s.user_id, "Kemlock formats");
    let fields = fields_for(&all, &forward, wrapped);
    body["fields"] = json!(fields);
    body["notes"] = note(0);

    // POST, then /api/sync
    let made = s.create_cipher(&body).await;
    assert_fields(
        &format!("{what}, POST answer"),
        &fields,
        &forward_paths,
        &made["fields"],
    );
    assert_eq!(
        made["notes"], body["notes"],
        "{what}: notes come back from POST byte for byte"
    );
    let id = made["id"].as_str().expect("an id").to_owned();
    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    assert_fields(
        &format!("{what}, /api/sync after POST"),
        &fields,
        &forward_paths,
        &synced["fields"],
    );
    assert_eq!(
        synced["notes"], body["notes"],
        "{what}: notes come back from /api/sync byte for byte"
    );

    // PUT with the fields the other way round and another note, then /api/sync
    let reversed = fields_for(&all, &reverse, wrapped);
    let mut update = as_write(&synced, &s.user_id);
    update["fields"] = json!(reversed);
    update["notes"] = note(1);
    update["lastKnownRevisionDate"] = synced["revisionDate"].clone();
    let reply = s.update_cipher(&id, &update).await;
    let put = reply.ok_json(&format!("{what}, PUT"));
    assert_fields(
        &format!("{what}, PUT answer"),
        &reversed,
        &reverse_paths,
        &put["fields"],
    );
    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    assert_fields(
        &format!("{what}, /api/sync after PUT"),
        &reversed,
        &reverse_paths,
        &synced["fields"],
    );
    assert_eq!(
        synced["notes"], update["notes"],
        "{what}: notes come back after PUT byte for byte"
    );
}

#[tokio::test]
async fn formats_json_strings_come_back_byte_for_byte_wrapped() {
    write_and_read_back("formats.json", true).await;
}

#[tokio::test]
async fn formats_json_strings_come_back_byte_for_byte_bare() {
    write_and_read_back("formats.json", false).await;
}

#[tokio::test]
async fn vault_items_json_strings_come_back_byte_for_byte_wrapped() {
    write_and_read_back("vault-items.json", true).await;
}

#[tokio::test]
async fn vault_items_json_strings_come_back_byte_for_byte_bare() {
    write_and_read_back("vault-items.json", false).await;
}

#[tokio::test]
async fn the_hidden_kemlock_field_of_a_login_survives_as_the_app_writes_it() {
    // The plain home of a Login: a hidden field named `Kemlock` whose value is the entry's
    // `PlainField` (`formats.json` `plainOwn`, `vw_codec.dart:441-444`, 495-499), beside a field of
    // another app that must stay (`api_test.dart:260-263`, "keep me"). A PUT that changes only the
    // totp must leave both fields as they were (`vw_codec.dart:644-655` writes `login.totp`).
    let formats = fixtures::json("formats.json");
    let plain = formats["plainOwn"].as_str().expect("plainOwn").to_owned();
    let s = fresh_session().await;
    let mut body = login_cipher(&s.user_id, "GitHub");
    body["fields"] = json!([
        {"type": 1, "name": enc("Kemlock"), "value": enc_bytes(plain.as_bytes()), "linkedId": null},
        {"type": 0, "name": enc("Other app"), "value": enc("keep me"), "linkedId": null},
    ]);
    let made = s.create_cipher(&body).await;
    let id = made["id"].as_str().expect("an id").to_owned();

    let mut update = as_write(&made, &s.user_id);
    update["login"]["totp"] = json!(enc("otpauth://totp/GitHub:me?secret=KRSXG5A"));
    update["lastKnownRevisionDate"] = made["revisionDate"].clone();
    s.update_cipher(&id, &update).await.ok_json("PUT");
    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    assert_eq!(
        synced["fields"], body["fields"],
        "both fields are kept byte for byte"
    );
    assert_eq!(synced["login"]["totp"], update["login"]["totp"]);
}
