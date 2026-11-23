//! Attachments: the v2 upload, the download without a bearer token, and the permanent delete.
//!
//! Citations: `kemlock/` is the Kemlock app (`mobile/lib/features/sync/vaultwarden/vw_api.dart`
//! unless said), `amethyst/` is `apps/vault-net/tests/vaultwarden.rs`, `spec-attachments.md` is
//! `amethystora-plans/vault-sync/spec-attachments.md` (its appendix, line 498, lists the facts a
//! test should pin).

use kemlock_contract_tests::account::{as_write, login_cipher};
use kemlock_contract_tests::files::{attach, open_slot, some_data, upload};
use kemlock_contract_tests::util::{authority, is_jwt, message_of};
use kemlock_contract_tests::{Reply, Session, fresh_session};
use serde_json::{Value, json};
use std::time::Duration;

async fn pause() {
    tokio::time::sleep(Duration::from_millis(40)).await;
}

fn is_attachment_id(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The listing of a cipher's attachments, empty when it has none (`null` or `[]`).
fn attachments_of(cipher: &Value) -> Vec<Value> {
    cipher["attachments"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// `GET /api/ciphers/{id}/attachment/{aid}`: the attachment and the address its data is at.
async fn address_of(s: &Session, cipher_id: &str, attachment_id: &str) -> (Value, String) {
    let reply = s
        .get(&format!(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}"
        ))
        .await;
    let info = reply.ok_json("GET /api/ciphers/{id}/attachment/{aid}");
    let url = info["url"]
        .as_str()
        .unwrap_or_else(|| panic!("the attachment has a url: {info}"))
        .to_owned();
    (info, url)
}

/// What the apps do with the address: no bearer token (`vw_api.dart:470-476`, `downloadAttachment`;
/// amethyst vaultwarden.rs:600-606).
async fn fetch(s: &Session, url: &str) -> Reply {
    s.http
        .send(
            s.http
                .bare("GET", url)
                .header("Accept", "application/octet-stream")
                .header("Bitwarden-Client-Name", "kemlock")
                .header("Bitwarden-Client-Version", &s.version),
        )
        .await
}

fn token_of(url: &str) -> String {
    let query = url.split_once('?').map_or("", |(_, query)| query);
    let pairs: Vec<&str> = query.split('&').collect();
    assert_eq!(
        pairs.len(),
        1,
        "the download address has one query value, `token` (design, routes table); got {url}"
    );
    pairs[0]
        .strip_prefix("token=")
        .unwrap_or_else(|| panic!("the one query value is `token`: {url}"))
        .to_owned()
}

#[tokio::test]
async fn the_v2_upload_is_two_calls_and_the_slot_is_listed_before_any_data() {
    // kemlock vw_api.dart:386-414 (`startAttachmentUpload`: `attachmentId`, `fileUploadType`,
    // `url`, `cipherResponse`) and 421-448 (`uploadAttachment`: type 0 and an address on the
    // server's own host, else nothing is sent); amethyst vaultwarden.rs:669-690 and
    // spec-attachments.md:502-503 (1., 2.): `object` `attachment-fileUpload`, `fileUploadType` 0,
    // a relative `url`, `attachmentId`, the cipher under `cipherResponse`; the cipher already lists
    // the attachment; "the cipher's date has not moved (Vaultwarden bumps the account's only)".
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "With a file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let data = some_data(81);

    let before = s.revision_date().await;
    pause().await;
    let reply = open_slot(&s, &id, data.len(), created["revisionDate"].as_str()).await;
    let slot = reply.ok_json("POST attachment/v2");
    assert_eq!(slot["object"], "attachment-fileUpload", "{slot}");
    assert_eq!(
        slot["fileUploadType"], 0,
        "fileUploadType is 0, the bytes go to this server's own API; the apps send nothing to any \
         other type (vw_api.dart:429); got {slot}"
    );
    let attachment_id = slot["attachmentId"]
        .as_str()
        .expect("an attachmentId")
        .to_owned();
    assert!(
        is_attachment_id(&attachment_id),
        "attachment ids are letters and digits, as the apps check before putting one in a path \
         (design: \"attachment ids of letters and digits\"; spec-attachments.md:32); got {attachment_id:?}"
    );
    let url = slot["url"].as_str().expect("a url");
    assert!(
        url.starts_with('/') || authority(url) == authority(s.http.base()),
        "the upload url is relative or on the server's own host, or the apps refuse to send the \
         data (vw_api.dart:429, `sameServer`); got {url}"
    );
    assert!(
        attachments_of(&slot["cipherResponse"])
            .iter()
            .any(|a| a["id"] == json!(attachment_id)),
        "cipherResponse is the cipher with the new attachment in `attachments`: {slot}"
    );

    // The slot is on the cipher before any data, and the cipher's date has not moved
    let listed = s.get_cipher(&id).await.ok_json("GET cipher");
    assert!(
        attachments_of(&listed)
            .iter()
            .any(|a| a["id"] == json!(attachment_id))
    );
    assert_eq!(
        listed["revisionDate"], created["revisionDate"],
        "Vaultwarden does not move the cipher's revisionDate for an attachment, only the \
         account's (amethyst vaultwarden.rs:677-681; spec-attachments.md:48)"
    );

    // Step two: one `data` part
    let uploaded = upload(&s, &id, &attachment_id, &data).await;
    assert_eq!(uploaded.status, 200, "the upload: {}", uploaded.text());
    pause().await;
    assert!(
        s.revision_date().await > before,
        "adding an attachment moves the account's revision date (design, routes table: \"moved by \
         every change, attachments included\")"
    );

    // The listing: the encrypted size, as text
    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    let list = attachments_of(&synced);
    assert_eq!(list.len(), 1, "one attachment: {synced}");
    let entry = &list[0];
    assert_eq!(entry["object"], "attachment");
    assert_eq!(entry["id"], json!(attachment_id));
    for name in ["url", "fileName", "key", "size", "sizeName"] {
        assert!(
            entry.get(name).is_some(),
            "an attachment in a sync has `{name}`: {entry}"
        );
    }
    assert_eq!(
        entry["size"],
        json!(data.len().to_string()),
        "size is the encrypted data's length as text (vw_api.dart:139, spec-attachments.md:45)"
    );
}

#[tokio::test]
async fn the_download_address_is_on_the_servers_own_host_and_needs_no_bearer_token() {
    // kemlock vw_api.dart:453-465 (`attachmentAddress` needs an `id` and a `url` on the server's
    // own host, else `elsewhere`) and 470-499 (`downloadAttachment` sends no Authorization);
    // amethyst vaultwarden.rs:594-611 ("an address under /attachments/", "?token=", the size listed
    // is the encrypted bytes'); design: "`GET /attachments/{cipherId}/{attachmentId}?token=…` No
    // bearer token; the one query value a three-part JWT".
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "With a file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let data = some_data(97);
    let aid = attach(&s, &id, &data).await;

    let (info, url) = address_of(&s, &id, &aid).await;
    assert_eq!(
        info["id"],
        json!(aid),
        "the attachment's id comes back (vw_api.dart:461)"
    );
    assert_eq!(
        authority(&url),
        authority(s.http.base()),
        "the url is on the server's own host: the apps refuse another host and never send a \
         credential there (vw_api.dart:463, 680-685); got {url}"
    );
    assert!(
        url.contains(&format!("/attachments/{id}/{aid}?")),
        "the url is <domain>/attachments/{{cipherId}}/{{attachmentId}}?token=...; got {url}"
    );
    let token = token_of(&url);
    assert!(
        is_jwt(&token),
        "the one query value is a three-part JWT; got {token}"
    );

    let fetched = fetch(&s, &url).await;
    assert_eq!(
        fetched.status,
        200,
        "the data comes with no Authorization header, the token is the credential: {}",
        fetched.text()
    );
    assert_eq!(
        fetched.body, data,
        "the bytes come back as they were uploaded"
    );

    // A token is for one attachment only (spec-attachments.md:505, "a token for another
    // attachment returns 404")
    let other_id = attach(&s, &id, &some_data(33)).await;
    let (_, other_url) = address_of(&s, &id, &other_id).await;
    let other_token = token_of(&other_url);
    let crossed = fetch(
        &s,
        &format!(
            "{}/attachments/{id}/{aid}?token={other_token}",
            s.http.base()
        ),
    )
    .await;
    assert_eq!(
        crossed.status,
        404,
        "a token made for another attachment opens nothing; got {} {}",
        crossed.status,
        crossed.text()
    );
    let bare = fetch(&s, &format!("{}/attachments/{id}/{aid}", s.http.base())).await;
    assert_ne!(bare.status, 200, "no token, no data");
}

#[tokio::test]
#[ignore = "waits a minute and more for the download token to end"]
async fn a_download_token_ends_after_a_minute() {
    // spec-attachments.md:505 (4.): "a second fetch after more than a minute returns 404"; the
    // apps ask for the address again each time (vw_api.dart:453-465).
    // Vaultwarden 1.37.5 auth.rs: `generate_file_download_claims` sets `exp` a minute out, and
    // `decode_jwt` validates it with `validation.leeway = 30`, so a link is good for 90 seconds
    // and 404s (api/web.rs, `attachments`: a token that doesn't decode is `None`) after that.
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "With a file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let aid = attach(&s, &id, &some_data(40)).await;
    let (_, url) = address_of(&s, &id, &aid).await;
    assert_eq!(fetch(&s, &url).await.status, 200);
    // Past the minute and its 30 seconds of leeway
    tokio::time::sleep(Duration::from_secs(95)).await;
    let late = fetch(&s, &url).await;
    assert_eq!(
        late.status,
        404,
        "a download token lives a minute, 30 seconds more with the leeway; got {} {}",
        late.status,
        late.text()
    );
}

#[tokio::test]
async fn deleting_an_attachment_is_permanent_and_moves_the_revision_date() {
    // kemlock vw_api.dart:502-509 (`deleteAttachment`); amethyst vaultwarden.rs:751-792 (the one
    // delete the client allows itself); design: "`DELETE /api/ciphers/{id}/attachment/{attachmentId}`
    // Permanent"; "moved by every change, attachments included".
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "With a file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let aid = attach(&s, &id, &some_data(64)).await;
    let (_, url) = address_of(&s, &id, &aid).await;

    let before = s.revision_date().await;
    pause().await;
    let reply = s
        .delete(&format!("/api/ciphers/{id}/attachment/{aid}"))
        .await;
    assert!(
        reply.is_success(),
        "DELETE attachment: {} {}",
        reply.status,
        reply.text()
    );
    assert!(
        s.revision_date().await > before,
        "deleting an attachment moves the account's revision date"
    );
    let synced = s.synced_cipher(&id).await.expect("the cipher stays");
    assert!(
        attachments_of(&synced).is_empty(),
        "the attachment is gone from /api/sync: {synced}"
    );
    let gone = s.get(&format!("/api/ciphers/{id}/attachment/{aid}")).await;
    // Vaultwarden 1.37.5 api/core/ciphers.rs, `get_attachment`: a missing attachment is
    // `err!("Attachment doesn't exist")`, and `err!` answers 400 (error.rs, `Error::new_msg`
    // starts at BAD_REQUEST); only `err_code!` picks another status. The 404 is the file route's.
    assert_eq!(
        gone.status,
        400,
        "asking for it by id is a 400, as Vaultwarden's `err!` has it; got {}",
        gone.text()
    );
    assert_eq!(gone.json()["message"], "Attachment doesn't exist");
    let late = fetch(&s, &url).await;
    assert_eq!(
        late.status, 404,
        "its data can't be fetched any more, even with the old token"
    );
}

#[tokio::test]
async fn the_size_listed_is_the_bytes_uploaded_and_one_megabyte_off_the_announced_size_is_refused()
{
    // spec-attachments.md:504 (3.): "the attachment's `size` after the upload equals the encrypted
    // bytes sent; an upload 1 MiB + 1 byte off the announced `fileSize` is a 400 and the slot is gone".
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "With a file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();

    let slot = open_slot(&s, &id, 100, None).await.ok_json("attachment/v2");
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();
    let uploaded = upload(&s, &id, &aid, &some_data(150)).await;
    assert_eq!(
        uploaded.status,
        200,
        "an upload a little off the announced size is taken: {}",
        uploaded.text()
    );
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert_eq!(
        attachments_of(&synced)[0]["size"],
        json!("150"),
        "size is what was uploaded, not what was announced"
    );

    let slot = open_slot(&s, &id, 100, None).await.ok_json("attachment/v2");
    let second = slot["attachmentId"].as_str().expect("an id").to_owned();
    let refused = upload(&s, &id, &second, &some_data(100 + 1_048_576 + 1)).await;
    assert_eq!(
        refused.status,
        400,
        "an upload 1 MiB and a byte off the announced size is a 400; got {}",
        refused.text()
    );
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert!(
        !attachments_of(&synced)
            .iter()
            .any(|a| a["id"] == json!(second)),
        "and the slot is gone: {synced}"
    );
}

#[tokio::test]
async fn a_slot_opened_and_never_filled_is_listed_has_no_data_and_can_be_deleted() {
    // amethyst vaultwarden.rs:751-792 ("a ghost has no file", "the slot is gone" after the one
    // delete); spec-attachments.md:512 (11.): "open a slot and never upload: `/sync` shows the
    // attachment, a download of it fails".
    let s = fresh_session().await;
    let created = s.create_cipher(&login_cipher(&s.user_id, "A ghost")).await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let slot = open_slot(&s, &id, 4, created["revisionDate"].as_str())
        .await
        .ok_json("attachment/v2");
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert!(
        attachments_of(&synced)
            .iter()
            .any(|a| a["id"] == json!(aid)),
        "the ghost is listed"
    );

    let (_, url) = address_of(&s, &id, &aid).await;
    assert_ne!(fetch(&s, &url).await.status, 200, "a ghost has no file");
    let reply = s
        .delete(&format!("/api/ciphers/{id}/attachment/{aid}"))
        .await;
    assert!(
        reply.is_success(),
        "the one delete: {} {}",
        reply.status,
        reply.text()
    );
    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert!(attachments_of(&synced).is_empty(), "the slot is gone");
}

#[tokio::test]
async fn a_put_that_names_no_attachments_keeps_them_and_so_do_the_trash_and_restore() {
    // spec-attachments.md:507 (6.): "a `PUT` that omits `attachments` and `attachments2` leaves the
    // attachment, byte for byte (hash of a downloaded file the same), and `PUT /delete` then
    // `/restore` leaves it too"; amethyst vaultwarden.rs:691-709 (the file another app added
    // survives the client's next PUT); kemlock's writes never name attachments (`vw_codec.dart:
    // 706-722`).
    let s = fresh_session().await;
    let created = s
        .create_cipher(&login_cipher(&s.user_id, "Keeps its file"))
        .await;
    let id = created["id"].as_str().expect("an id").to_owned();
    let data = some_data(120);
    let aid = attach(&s, &id, &data).await;

    let synced = s.synced_cipher(&id).await.expect("in sync");
    let mut update = as_write(&synced, &s.user_id);
    assert!(
        update.get("attachments").is_none(),
        "the write names no attachments"
    );
    update["name"] = json!(kemlock_contract_tests::enc::enc("Renamed"));
    update["lastKnownRevisionDate"] = synced["revisionDate"].clone();
    s.update_cipher(&id, &update).await.ok_json("PUT");

    s.put_empty(&format!("/api/ciphers/{id}/delete"))
        .await
        .ok_json("PUT delete");
    s.put_empty(&format!("/api/ciphers/{id}/restore"))
        .await
        .ok_json("PUT restore");

    let synced = s.synced_cipher(&id).await.expect("in sync");
    assert_eq!(
        attachments_of(&synced).len(),
        1,
        "the attachment is still on the item"
    );
    let (_, url) = address_of(&s, &id, &aid).await;
    let fetched = fetch(&s, &url).await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body, data, "and its data is the same bytes");
}

#[tokio::test]
async fn a_refusal_to_open_a_slot_for_a_missing_cipher_mentions_the_cipher() {
    // kemlock vw_api.dart:694-697 (`_takesNoFiles`): a 4xx whose message doesn't mention the
    // cipher is read as "this server takes no files", and sync goes on without them. A cipher that
    // isn't there is an ordinary error, and its message must say so. Design: "a refusal is a 400
    // whose message doesn't mention the cipher" (that is the one for attachments switched off).
    let s = fresh_session().await;
    let reply = open_slot(&s, "11111111-2222-4333-8444-555555555555", 10, None).await;
    assert!(
        (400..500).contains(&reply.status) && reply.status != 401,
        "opening a slot on a missing cipher is a client error; got {} {}",
        reply.status,
        reply.text()
    );
    let message = message_of(&reply.json()).unwrap_or_default().to_lowercase();
    assert!(
        message.contains("cipher"),
        "Vaultwarden says the cipher doesn't exist; the app reads any other 4xx message as \
         'attachments are off' (vw_api.dart:696); got {message:?}"
    );
}
