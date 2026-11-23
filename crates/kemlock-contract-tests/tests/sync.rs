//! The revision date, `/api/sync`, folders and ciphers: what the apps read and write.
//!
//! Citations: `kemlock/` is the Kemlock app (`mobile/...`), `amethyst/` is
//! `apps/vault-net/tests/vaultwarden.rs`, `spec-protocol.md` is
//! `amethystora-plans/vault-sync/spec-protocol.md`.

use kemlock_contract_tests::account::{as_write, login_cipher, note_cipher, ssh_cipher};
use kemlock_contract_tests::enc::enc;
use kemlock_contract_tests::shape::{Mode, assert_shape, assert_single_spelling};
use kemlock_contract_tests::util::{key_of, message_of};
use kemlock_contract_tests::{Kdf, Session, client, fixtures, fresh_session};
use serde_json::{Value, json};
use std::time::Duration;

/// Time for the clock to move: the revision date has a resolution of a millisecond.
async fn pause() {
    tokio::time::sleep(Duration::from_millis(40)).await;
}

/// Reads the revision date and requires that it passed `before`.
async fn moved(session: &Session, before: &mut i64, what: &str) {
    let now = session.revision_date().await;
    assert!(
        now > *before,
        "{what} must move the account's revision date (it was {before}, it is {now}): both apps \
         read it before /api/sync and stop when it hasn't moved (design, routes table: \"Epoch ms, \
         moved by every change\"; kemlock vw_api.dart:331-337; amethyst spec-protocol.md:433)",
        before = *before
    );
    *before = now;
}

fn cipher_ids(sync: &Value) -> Vec<String> {
    sync["ciphers"]
        .as_array()
        .map(|ciphers| {
            ciphers
                .iter()
                .filter_map(|cipher| cipher["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

// ─── The revision date ──────────────────────────────────────────────────────

#[tokio::test]
async fn the_revision_date_is_epoch_milliseconds_and_moves_on_every_change() {
    // kemlock api_test.dart:249-274 (`greaterThan(before)` after a create), vw_api.dart:331-337
    // (a bare number); amethyst spec-protocol.md:433; design: "Epoch ms, moved by every
    // change, attachments included" (attachments: tests/attachments.rs).
    let s = fresh_session().await;
    let unsigned = s
        .http
        .send(s.http.call("GET", "/api/accounts/revision-date"))
        .await;
    assert_eq!(
        unsigned.status,
        401,
        "revision-date asks for a token: {}",
        unsigned.text()
    );

    let reply = s.get("/api/accounts/revision-date").await;
    assert!(
        reply.json().is_i64() || reply.json().is_u64(),
        "revision-date is a bare JSON integer, as Vaultwarden's is; got {}",
        reply.text()
    );
    let mut last = s.revision_date().await;
    assert!(
        last > 1_600_000_000_000,
        "revision-date is milliseconds since the epoch (Vaultwarden's), not seconds; got {last}"
    );

    pause().await;
    let folder = s.create_folder("A folder").await;
    moved(&s, &mut last, "creating a folder").await;
    let folder_id = folder["id"].as_str().expect("a folder id").to_owned();

    pause().await;
    s.put(
        &format!("/api/folders/{folder_id}"),
        &json!({"name": enc("Renamed")}),
    )
    .await
    .ok_json("PUT /api/folders/{id}");
    moved(&s, &mut last, "renaming a folder").await;

    pause().await;
    let created = s.create_cipher(&login_cipher(&s.user_id, "An item")).await;
    moved(&s, &mut last, "creating an item").await;
    let id = created["id"].as_str().expect("a cipher id").to_owned();

    pause().await;
    let mut update = as_write(&created, &s.user_id);
    update["lastKnownRevisionDate"] = created["revisionDate"].clone();
    update["login"]["totp"] = json!(enc("JBSWY3DPEHPK3PXP"));
    s.update_cipher(&id, &update)
        .await
        .ok_json("PUT /api/ciphers/{id}");
    moved(&s, &mut last, "changing an item").await;

    pause().await;
    s.put_empty(&format!("/api/ciphers/{id}/delete"))
        .await
        .ok_json("PUT delete");
    moved(&s, &mut last, "moving an item to the trash").await;

    pause().await;
    s.put_empty(&format!("/api/ciphers/{id}/restore"))
        .await
        .ok_json("PUT restore");
    moved(&s, &mut last, "restoring an item from the trash").await;

    pause().await;
    let reply = s.delete(&format!("/api/ciphers/{id}")).await;
    assert!(
        reply.is_success(),
        "DELETE /api/ciphers/{{id}}: {} {}",
        reply.status,
        reply.text()
    );
    moved(&s, &mut last, "deleting an item for good").await;

    pause().await;
    let reply = s.delete(&format!("/api/folders/{folder_id}")).await;
    assert!(
        reply.is_success(),
        "DELETE /api/folders/{{id}}: {} {}",
        reply.status,
        reply.text()
    );
    moved(&s, &mut last, "deleting a folder").await;
}

// ─── The shape of /api/sync ─────────────────────────────────────────────────

#[tokio::test]
async fn sync_has_the_keys_types_and_casing_of_vaultwardens_recorded_answer() {
    // The design's contract: "`account-pbkdf2.json` and `account-argon2id.json`: prelogin, token
    // and `/api/sync` answers from Vaultwarden 1.37.5, with items the Bitwarden CLI 2026.6.0 made.
    // The server's answers match their keys, types and casing." Each fixture's own items are sent
    // as writes, so what comes back is the same items under this server's hand. The values must
    // come back byte for byte too (kemlock vw_codec.dart reads `name`, `notes`, `fields` and
    // `login` as they are; amethyst spec-protocol.md:439-456 reads `profile`, `folders`, `ciphers`).
    let cases = [
        ("account-pbkdf2.json", Kdf::cheap_pbkdf2()),
        ("account-argon2id.json", Kdf::cheap_argon2id()),
    ];
    for (fixture, kdf) in cases {
        let recorded = fixtures::account(fixture);
        let http = client();
        let account = http.register_ok(kdf).await;
        let s = http.login(&account).await;

        let folder_name = recorded["sync"]["folders"][0]["name"].clone();
        let folder = s
            .post("/api/folders", &json!({"name": folder_name}))
            .await
            .ok_json("POST /api/folders");
        assert_shape(
            &format!("POST /api/folders ({fixture})"),
            &recorded["sync"]["folders"][0],
            &folder,
            Mode::Exact,
        );
        assert_eq!(
            folder["name"], folder_name,
            "the folder's name comes back byte for byte"
        );

        let mut sent: Vec<(Value, String)> = Vec::new();
        for item in recorded["sync"]["ciphers"]
            .as_array()
            .expect("recorded ciphers")
        {
            let mut body = as_write(item, &s.user_id);
            body["folderId"] = folder["id"].clone();
            let made = s.create_cipher(&body).await;
            assert_shape(
                &format!("POST /api/ciphers ({fixture})"),
                &json!([item]),
                &json!([made]),
                Mode::Exact,
            );
            sent.push((item.clone(), made["id"].as_str().expect("an id").to_owned()));
        }

        let sync = s.sync().await;
        assert_single_spelling("/api/sync", &sync);
        assert_eq!(sync["object"], "sync", "the sync says object: \"sync\"");
        for key in recorded["sync"]
            .as_object()
            .expect("a recorded sync")
            .keys()
        {
            assert!(
                key_of(&sync, key).is_some() && sync.get(key).is_some(),
                "/api/sync has the key {key} spelled as Vaultwarden spells it; got keys {:?}",
                sync.as_object().map(|o| o.keys().collect::<Vec<_>>())
            );
        }
        assert_shape(
            &format!("profile ({fixture})"),
            &recorded["sync"]["profile"],
            &sync["profile"],
            Mode::Exact,
        );
        let folders = sync["folders"].as_array().expect("folders");
        assert_eq!(folders.len(), 1, "the one folder made above");
        assert_shape(
            &format!("folders ({fixture})"),
            &recorded["sync"]["folders"][0],
            &folders[0],
            Mode::Exact,
        );
        let recorded_ciphers = recorded["sync"]["ciphers"]
            .as_array()
            .expect("recorded ciphers");
        for cipher in sync["ciphers"].as_array().expect("ciphers") {
            let kind = cipher["type"].as_i64();
            let candidates: Vec<Value> = recorded_ciphers
                .iter()
                .filter(|item| item["type"].as_i64() == kind)
                .cloned()
                .collect();
            assert!(
                !candidates.is_empty(),
                "the fixture has no item of type {kind:?}"
            );
            assert_shape(
                &format!("a cipher of type {kind:?} in /api/sync ({fixture})"),
                &Value::Array(candidates),
                &json!([cipher]),
                Mode::Exact,
            );
        }

        // The profile is this account's
        let profile = &sync["profile"];
        assert_eq!(profile["id"], json!(s.user_id));
        assert_eq!(profile["email"], json!(account.email));
        assert_eq!(
            profile["key"],
            json!(account.user_key),
            "profile.key is the user key as registered"
        );
        assert_eq!(profile["privateKey"], json!(account.private_key));
        assert_eq!(
            profile["premium"],
            json!(true),
            "Vaultwarden makes every account premium (the fixture's profile says so), which \
             Bitwarden's apps need for attachments and codes"
        );

        // Amethystora stops syncing when /api/sync shows a new `profile.key`, a `7.` string,
        // `signatureKeyPair`, `securityState` or `v2UpgradeToken` (design, "Compatibility";
        // spec-protocol.md:400-410): the post-quantum keys never appear on this API
        let keys = &profile["accountKeys"];
        assert!(
            key_of(keys, "signatureKeyPair").is_none_or(Value::is_null),
            "{keys}"
        );
        assert!(
            key_of(keys, "securityState").is_none_or(Value::is_null),
            "{keys}"
        );
        for name in ["key", "privateKey"] {
            assert!(
                !profile[name].as_str().unwrap_or_default().starts_with("7."),
                "profile.{name} stays a type 2 string, never a `7.` one"
            );
        }
        if let Some(decryption) = key_of(&sync, "userDecryption") {
            assert!(
                key_of(decryption, "v2UpgradeToken").is_none_or(Value::is_null),
                "userDecryption.v2UpgradeToken stays null: {decryption}"
            );
        }

        // The values come back as they went
        for (item, id) in &sent {
            let found = sync["ciphers"]
                .as_array()
                .and_then(|all| all.iter().find(|c| c["id"] == json!(id)))
                .unwrap_or_else(|| panic!("the item {id} is in /api/sync"));
            for name in ["name", "notes", "favorite", "reprompt", "fields", "key"] {
                assert_eq!(
                    found[name], item[name],
                    "{fixture}: {name} comes back byte for byte"
                );
            }
            assert_eq!(found["folderId"], folder["id"]);
            assert!(found["deletedDate"].is_null());
            for name in ["username", "password", "totp", "uris"] {
                assert_eq!(
                    found["login"][name], item["login"][name],
                    "{fixture}: login.{name} comes back byte for byte"
                );
            }
        }
    }
}

#[tokio::test]
async fn sync_carries_no_data_partial_data_or_new_encryption_fields_on_a_cipher() {
    // design, routes table: "no `data`, `partialData` or V2 key fields". Vaultwarden sends no
    // `data` (amethyst vaultwarden.rs:198-205: "Vaultwarden does not send data"; spec-protocol.md:
    // 482), and Amethystora reads a `data` with a `format_version` as a sign of the new
    // encryption and stops.
    let s = fresh_session().await;
    s.create_cipher(&login_cipher(&s.user_id, "A login")).await;
    s.create_cipher(&note_cipher(&s.user_id, "A note")).await;
    s.create_cipher(&ssh_cipher(&s.user_id, "A key")).await;
    let sync = s.sync().await;
    for cipher in sync["ciphers"].as_array().expect("ciphers") {
        for name in ["data", "partialData", "format_version"] {
            assert!(
                key_of(cipher, name).is_none(),
                "a cipher in /api/sync has no `{name}`: {cipher}"
            );
        }
        for name in ["key", "name", "notes"] {
            let text = cipher[name].as_str().unwrap_or("2.");
            assert!(
                !text.starts_with("7."),
                "{name} of a cipher is never a `7.` string"
            );
        }
    }
}

// ─── SSH key items ──────────────────────────────────────────────────────────

#[tokio::test]
async fn ssh_key_items_are_in_sync_only_from_client_version_2024_12_0() {
    // kemlock vw_api.dart:339-353 ("Vaultwarden leaves SSH key items out for clients that say they
    // are older than Bitwarden's 2024.12.0, so this asks as that version at least"),
    // vw_items.dart:44; amethyst vaultwarden.rs:253-270 (6. "An SSH key item is missing from /sync
    // without the version header, and there with it"), spec-protocol.md:150 and 909.
    let s = fresh_session().await;
    let note = s.create_cipher(&note_cipher(&s.user_id, "A note")).await;
    let ssh_body = ssh_cipher(&s.user_id, "A key");
    let ssh = s.create_cipher(&ssh_body).await;
    let note_id = note["id"].as_str().expect("an id").to_owned();
    let ssh_id = ssh["id"].as_str().expect("an id").to_owned();

    for version in [
        None,
        Some("2023.1.0"),
        Some("2024.11.0"),
        Some("1.1.0"),
        Some("banana"),
    ] {
        let reply = s.sync_as(version).await;
        let ids = cipher_ids(&reply.ok_json("sync"));
        assert!(
            ids.contains(&note_id),
            "a client of version {version:?} still gets its notes"
        );
        assert!(
            !ids.contains(&ssh_id),
            "a client of version {version:?} (or none) must not get SSH key items: Vaultwarden \
             leaves them out below Bitwarden-Client-Version 2024.12.0"
        );
    }
    for version in ["2024.12.0", "2024.12.1", "2025.12.0", "2026.6.0"] {
        let sync = s.sync_as(Some(version)).await.ok_json("sync");
        let ids = cipher_ids(&sync);
        assert!(
            ids.contains(&ssh_id),
            "a client of version {version} gets SSH key items, as from Vaultwarden"
        );
        let item = sync["ciphers"]
            .as_array()
            .and_then(|all| all.iter().find(|c| c["id"] == json!(ssh_id)))
            .expect("the ssh item");
        assert_eq!(item["type"], json!(5));
        assert_eq!(
            item["sshKey"], ssh_body["sshKey"],
            "sshKey keeps its three values byte for byte (vw_codec.dart:559-564)"
        );
        assert!(item["login"].is_null() && item["secureNote"].is_null());
    }
}

// ─── Writing ciphers ────────────────────────────────────────────────────────

#[tokio::test]
async fn encrypted_for_is_required_and_must_be_the_users_own_id() {
    // amethyst vaultwarden.rs:186-197 (1.), spec-protocol.md:904 and 621: "`POST /ciphers`
    // without `encryptedFor` fails; with the wrong id gives 422". Kemlock sends it on every write
    // (vw_codec.dart:468, 672, 710).
    let s = fresh_session().await;
    let mut body = login_cipher(&s.user_id, "One");
    body.as_object_mut()
        .expect("an object")
        .remove("encryptedFor");
    let missing = s.post("/api/ciphers", &body).await;
    assert!(
        !missing.is_success(),
        "Vaultwarden fails a create without encryptedFor; got {} {}",
        missing.status,
        missing.text()
    );
    body["encryptedFor"] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    let wrong = s.post("/api/ciphers", &body).await;
    assert_eq!(
        wrong.status,
        422,
        "an encryptedFor that is another account's id is a 422; got {}",
        wrong.text()
    );
    body["encryptedFor"] = json!(s.user_id);
    let right = s.post("/api/ciphers", &body).await;
    assert_eq!(
        right.status,
        200,
        "the user's own id is taken: {}",
        right.text()
    );
}

#[tokio::test]
async fn a_body_with_data_is_ignored_and_the_answer_has_none() {
    // amethyst vaultwarden.rs:198-205 (2.): "A body with `data` is ignored: the structured fields
    // stand", "Vaultwarden does not send data"; spec-protocol.md:905 and 623.
    let s = fresh_session().await;
    let mut body = login_cipher(&s.user_id, "Two");
    body["data"] = json!("{\"name\":\"2.stale|stale|stale\",\"username\":null}");
    let made = s.create_cipher(&body).await;
    assert_eq!(
        made["name"], body["name"],
        "the structured name stands, not the one in `data`"
    );
    assert!(
        made.get("data").is_none_or(Value::is_null),
        "no `data` in the answer: {made}"
    );
    let synced = s
        .synced_cipher(made["id"].as_str().expect("an id"))
        .await
        .expect("in sync");
    assert_eq!(synced["name"], body["name"]);
    assert!(synced.get("data").is_none_or(Value::is_null));
}

#[tokio::test]
async fn a_stale_last_known_revision_date_is_a_400_that_says_out_of_date() {
    // amethyst vaultwarden.rs:206-217 (3.): "A stale `lastKnownRevisionDate` is a 400, the returned
    // one a 200"; kemlock vw_api.dart:723-730 reads a 400 whose message contains `out of date` as
    // `outOfDate` (api_test.dart:302-309); spec-protocol.md:906 and 655-664.
    let s = fresh_session().await;
    let created = s.create_cipher(&login_cipher(&s.user_id, "Stale")).await;
    let id = created["id"].as_str().expect("an id").to_owned();

    let mut stale = as_write(&created, &s.user_id);
    stale["lastKnownRevisionDate"] = json!("2001-01-01T00:00:00Z");
    stale["login"]["password"] = json!(enc("changed"));
    let refused = s.update_cipher(&id, &stale).await;
    assert_eq!(
        refused.status,
        400,
        "a write based on a copy from 2001 is a 400, as Vaultwarden's is; got {}",
        refused.text()
    );
    let message = message_of(&refused.json()).unwrap_or_default();
    assert!(
        message.contains("out of date"),
        "Vaultwarden's message says the client copy is out of date, and the app matches the words \
         `out of date` (vw_api.dart:727); got {message:?} in {}",
        refused.text()
    );

    let mut fresh = as_write(&created, &s.user_id);
    fresh["lastKnownRevisionDate"] = created["revisionDate"].clone();
    fresh["login"]["password"] = json!(enc("changed"));
    let updated = s.update_cipher(&id, &fresh).await;
    assert_eq!(
        updated.status,
        200,
        "the returned revisionDate is taken: {}",
        updated.text()
    );
}

#[tokio::test]
async fn an_item_comes_back_from_an_update_with_every_value_kept_and_the_revision_is_checked() {
    // kemlock api_test.dart:244-310, "keeps every value of an item through an update, and checks
    // the revision": the app sends back what the server gave with one value changed, more than a
    // second after the copy it read, then a second write from the old copy is refused.
    let s = fresh_session().await;
    let folder = s.create_folder("Kemlock").await;
    let before = s.revision_date().await;
    let mut body = login_cipher(&s.user_id, "GitHub");
    body["folderId"] = folder["id"].clone();
    body["favorite"] = json!(true);
    pause().await;
    let created = s.create_cipher(&body).await;
    assert!(
        s.revision_date().await > before,
        "creating an item moves the revision date"
    );

    let id = created["id"].as_str().expect("an id").to_owned();
    let item = s
        .synced_cipher(&id)
        .await
        .expect("the item is in /api/sync");
    assert_eq!(item["folderId"], folder["id"]);
    assert!(item["deletedDate"].is_null());

    // The check allows a second, so the update comes more than one after the copy
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let mut changed = as_write(&item, &s.user_id);
    changed["login"]["totp"] = json!(enc("otpauth://totp/GitHub:me?secret=KRSXG5A"));
    changed["lastKnownRevisionDate"] = item["revisionDate"].clone();
    let reply = s.update_cipher(&id, &changed).await;
    let updated = reply.ok_json("the update");
    for name in [
        "name", "notes", "favorite", "folderId", "fields", "reprompt", "key",
    ] {
        assert_eq!(
            updated[name], item[name],
            "{name} is kept by an update that doesn't touch it"
        );
    }
    assert_eq!(updated["login"]["password"], item["login"]["password"]);
    assert_eq!(updated["login"]["uris"], item["login"]["uris"]);
    assert_eq!(
        updated["login"]["totp"], changed["login"]["totp"],
        "the value that was changed is the one stored"
    );

    // A second write from the copy read before the first is refused
    let again = s.update_cipher(&id, &changed).await;
    assert_eq!(
        again.status,
        400,
        "a write from the old copy: {}",
        again.text()
    );
    assert!(
        message_of(&again.json())
            .unwrap_or_default()
            .contains("out of date"),
        "the 400 says the copy is out of date: {}",
        again.text()
    );
}

#[tokio::test]
async fn a_cipher_by_id_is_the_cipher_as_sync_shows_it() {
    // design, routes table: "`GET /api/ciphers/{id}` ... The cipher as `/api/sync` shows it"; used
    // by Amethystora to check a conflict (spec-protocol.md:582 and 664, vaultwarden.rs:674-678).
    let s = fresh_session().await;
    let created = s.create_cipher(&login_cipher(&s.user_id, "By id")).await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let fetched = s.get_cipher(&id).await.ok_json("GET /api/ciphers/{id}");
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert_single_spelling("GET /api/ciphers/{id}", &fetched);
    assert_eq!(
        fetched, synced,
        "GET /api/ciphers/{{id}} answers with the same JSON as /api/sync"
    );

    let missing = s.get_cipher("11111111-2222-4333-8444-555555555555").await;
    // Vaultwarden 1.37.5 api/core/ciphers.rs, `get_cipher`: a cipher that isn't there is
    // `err!("Cipher doesn't exist")`, and `err!` answers 400 (error.rs: `Error` starts at
    // BAD_REQUEST, only `err_code!` picks another status).
    assert_eq!(
        missing.status,
        400,
        "a cipher that isn't there is a 400, as Vaultwarden's `err!` has it: {}",
        missing.text()
    );
    assert_eq!(missing.json()["message"], "Cipher doesn't exist");
}

#[tokio::test]
async fn trash_restore_and_the_two_permanent_deletes() {
    // `PUT .../delete` and `.../restore` go to the trash and back (kemlock vw_api.dart:370-377,
    // api_test.dart:312-329; amethyst vaultwarden.rs:218-225 (4.), spec-protocol.md:907 and 579-581);
    // design: "`DELETE` stays permanent". The same spec warns that `POST /ciphers/{id}/delete` is
    // permanent too: "only the verb separates trash from destruction".
    let s = fresh_session().await;
    let created = s.create_cipher(&note_cipher(&s.user_id, "note")).await;
    let id = created["id"].as_str().expect("an id").to_owned();

    s.put_empty(&format!("/api/ciphers/{id}/delete"))
        .await
        .ok_json("PUT delete");
    let trashed = s
        .synced_cipher(&id)
        .await
        .expect("a trashed item is still in /api/sync");
    assert!(
        trashed["deletedDate"].is_string(),
        "PUT /delete leaves the item with a deletedDate; got {}",
        trashed["deletedDate"]
    );
    let restored = s
        .put_empty(&format!("/api/ciphers/{id}/restore"))
        .await
        .ok_json("PUT restore");
    assert!(
        restored["deletedDate"].is_null(),
        "PUT /restore answers with the item restored"
    );
    assert_eq!(restored["id"], json!(id));
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert!(synced["deletedDate"].is_null(), "and /api/sync agrees");

    let reply = s.delete(&format!("/api/ciphers/{id}")).await;
    assert!(
        reply.is_success(),
        "DELETE: {} {}",
        reply.status,
        reply.text()
    );
    assert!(
        s.synced_cipher(&id).await.is_none(),
        "DELETE is permanent: the item is gone"
    );
    // The permanent delete is gone for good: `get_cipher` (api/core/ciphers.rs) answers a cipher
    // that isn't there with `err!("Cipher doesn't exist")`, which is a 400, not a 404.
    let gone = s.get_cipher(&id).await;
    assert_eq!(gone.status, 400, "a deleted cipher by id: {}", gone.text());
    assert_eq!(gone.json()["message"], "Cipher doesn't exist");

    let other = s.create_cipher(&note_cipher(&s.user_id, "another")).await;
    let other_id = other["id"].as_str().expect("an id").to_owned();
    let reply = s
        .post(&format!("/api/ciphers/{other_id}/delete"), &json!({}))
        .await;
    assert!(
        reply.is_success(),
        "POST /delete: {} {}",
        reply.status,
        reply.text()
    );
    assert!(
        s.synced_cipher(&other_id).await.is_none(),
        "Vaultwarden's POST /ciphers/{{id}}/delete is a permanent delete, not a move to the trash"
    );
}

#[tokio::test]
async fn passkeys_and_every_value_the_app_does_not_read_survive_a_put_byte_for_byte() {
    // amethyst vaultwarden.rs:226-252 (5.): "A passkey and every field this client does not read
    // survive a PUT that changes the password, byte for byte"; spec-protocol.md:908 and 647-650;
    // kemlock vw_items.dart:262-283 (the `fido2Credentials` it writes, once) and the design:
    // "Keep `fido2Credentials` byte for byte through every `PUT`", "Store `bw` cipher JSON byte for
    // byte, unknown keys too".
    let s = fresh_session().await;
    let passkey = json!([{
        "credentialId": enc("credential-id"),
        "keyType": enc("public-key"),
        "keyAlgorithm": enc("ECDSA"),
        "keyCurve": enc("P-256"),
        "keyValue": enc("key-material"),
        "rpId": enc("example.test"),
        "rpName": null,
        "userHandle": enc("handle"),
        "userName": null,
        "userDisplayName": null,
        "counter": enc("0"),
        "discoverable": enc("true"),
        "creationDate": "2026-01-01T00:00:00Z",
    }]);
    let mut body = login_cipher(&s.user_id, "With a passkey");
    body["login"]["fido2Credentials"] = passkey.clone();
    body["login"]["aFutureKey"] = json!({"kept": true, "list": [1, 2, 3]});
    body["login"]["autofillOnPageLoad"] = json!(true);
    body["favorite"] = json!(true);
    body["fields"] = json!([
        {"type": 0, "name": enc("note to self"), "value": enc("keep me"), "linkedId": null},
        {"type": 2, "name": enc("a flag"), "value": enc("true"), "linkedId": null},
        {"type": 3, "name": enc("linked"), "value": null, "linkedId": 100},
    ]);
    body["passwordHistory"] = json!([
        {"password": enc("older"), "lastUsedDate": "2026-01-01T00:00:00Z"},
    ]);
    let made = s.create_cipher(&body).await;
    let id = made["id"].as_str().expect("an id").to_owned();

    let sent = &body["login"]["fido2Credentials"][0];
    let kept = &made["login"]["fido2Credentials"][0];
    for name in [
        "credentialId",
        "keyType",
        "keyAlgorithm",
        "keyCurve",
        "keyValue",
        "rpId",
        "rpName",
        "userHandle",
        "userName",
        "userDisplayName",
        "counter",
        "discoverable",
    ] {
        assert_eq!(
            kept[name], sent[name],
            "fido2Credentials[0].{name} comes back as it went"
        );
    }
    assert!(
        kept["creationDate"].is_string(),
        "creationDate stays a plain string"
    );
    assert_eq!(
        made["login"]["aFutureKey"], body["login"]["aFutureKey"],
        "unknown keys of `login` are kept"
    );
    assert_eq!(made["login"]["autofillOnPageLoad"], json!(true));
    assert_eq!(made["fields"], body["fields"]);
    assert_eq!(made["favorite"], json!(true));
    assert_eq!(
        made["passwordHistory"][0]["password"],
        body["passwordHistory"][0]["password"]
    );

    // A PUT that changes the password and sends the rest as the server gave it
    let mut update = as_write(&made, &s.user_id);
    update["lastKnownRevisionDate"] = made["revisionDate"].clone();
    update["login"]["password"] = json!(enc("pw1 third"));
    let reply = s.update_cipher(&id, &update).await;
    let third = reply.ok_json("the PUT that changes the password");
    assert_eq!(third["login"]["password"], update["login"]["password"]);
    let stored = s.synced_cipher(&id).await.expect("in sync");
    assert_eq!(
        stored["login"]["fido2Credentials"], made["login"]["fido2Credentials"],
        "the passkey came back as it went, byte for byte, through a PUT that changed the password"
    );
    assert_eq!(stored["login"]["aFutureKey"], made["login"]["aFutureKey"]);
    assert_eq!(stored["login"]["autofillOnPageLoad"], json!(true));
    assert_eq!(stored["fields"], made["fields"]);
    assert_eq!(stored["favorite"], json!(true));
    assert_eq!(
        stored["key"], made["key"],
        "the item key is kept (vaultwarden.rs:213)"
    );
    assert_eq!(
        stored["passwordHistory"][0]["password"],
        body["passwordHistory"][0]["password"]
    );
    assert_eq!(stored["login"]["password"], update["login"]["password"]);
}
