//! Sync, folders, ciphers, attachments and the compatibility switch, through the router.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness, login_request};
use serde_json::{Value, json};
use time::Duration;

async fn revision(h: &Harness, token: &str) -> i64 {
    h.json("GET", "/api/accounts/revision-date", Some(token), None)
        .await
        .1
        .as_i64()
        .expect("a number")
}

#[tokio::test]
async fn every_change_moves_the_revision_date_forward() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let mut last = revision(&h, &token).await;

    let (status, folder) = h
        .json(
            "POST",
            "/api/folders",
            Some(&token),
            Some(json!({"name": "2.folder"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{folder}");
    let now = revision(&h, &token).await;
    assert!(now > last);
    last = now;

    // Two changes in one millisecond still differ.
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.one")),
        )
        .await;
    let a = revision(&h, &token).await;
    assert!(a > last);
    let id = cipher["id"].as_str().expect("an id").to_owned();
    h.json(
        "PUT",
        &format!("/api/ciphers/{id}/delete"),
        Some(&token),
        None,
    )
    .await;
    let b = revision(&h, &token).await;
    assert!(b > a);
}

#[tokio::test]
async fn sync_shows_the_profile_folders_and_ciphers() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, folder) = h
        .json(
            "POST",
            "/api/folders",
            Some(&token),
            Some(json!({"name": "2.Kemlock"})),
        )
        .await;
    assert_eq!(folder["object"], "folder");
    assert_eq!(folder["name"], "2.Kemlock");
    let mut request = login_request(user, "2.name");
    request["folderId"] = folder["id"].clone();
    request["favorite"] = json!(true);
    let (status, cipher) = h
        .json("POST", "/api/ciphers", Some(&token), Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{cipher}");
    assert_eq!(cipher["object"], "cipherDetails");
    assert_eq!(cipher["folderId"], folder["id"]);
    assert_eq!(cipher["favorite"], true);
    assert_eq!(cipher["login"]["uri"], "2.uri");

    let (status, sync) = h
        .json("GET", "/api/sync?excludeDomains=true", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync["object"], "sync");
    assert_eq!(sync["domains"], Value::Null);
    assert_eq!(sync["collections"], json!([]));
    assert_eq!(sync["policies"], json!([]));
    assert_eq!(sync["sends"], json!([]));
    assert_eq!(sync["profile"]["email"], "ada@example.com");
    assert_eq!(sync["profile"]["id"], user.to_string());
    assert_eq!(sync["folders"].as_array().map(Vec::len), Some(1));
    assert_eq!(sync["ciphers"].as_array().map(Vec::len), Some(1));
    assert_eq!(sync["ciphers"][0]["id"], cipher["id"]);
    assert_eq!(
        sync["userDecryption"]["masterPasswordUnlock"]["salt"],
        "ada@example.com"
    );
    let (_, with_domains) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(with_domains["domains"]["object"], "domains");

    // The cipher as /api/sync shows it is what GET gives.
    let (_, one) = h
        .json(
            "GET",
            &format!("/api/ciphers/{}", cipher["id"].as_str().expect("id")),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(one, sync["ciphers"][0]);
}

#[tokio::test]
async fn ssh_keys_need_a_new_enough_client() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let mut request = login_request(user, "2.key");
    request["type"] = json!(5);
    request["login"] = Value::Null;
    request["sshKey"] = json!({"privateKey": "2.k", "publicKey": "2.p", "keyFingerprint": "2.f"});
    let (status, body) = h
        .json("POST", "/api/ciphers", Some(&token), Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let count = |version: Option<&'static str>| {
        let h = &h;
        let token = token.clone();
        async move {
            let auth = format!("Bearer {token}");
            let mut headers = vec![("authorization", auth.as_str())];
            if let Some(v) = version {
                headers.push(("bitwarden-client-version", v));
            }
            let (_, _, bytes) = h
                .send(
                    "GET",
                    "/api/sync?excludeDomains=true",
                    &headers,
                    Body::empty(),
                )
                .await;
            let sync: Value = serde_json::from_slice(&bytes).expect("JSON");
            sync["ciphers"].as_array().map(Vec::len).expect("a list")
        }
    };
    assert_eq!(count(None).await, 0);
    assert_eq!(count(Some("2024.11.1")).await, 0);
    assert_eq!(count(Some("2024.12.0")).await, 1);
    assert_eq!(count(Some("2025.12.0")).await, 1);
}

#[tokio::test]
async fn writes_are_checked_like_vaultwardens() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;

    // `encryptedFor` is required, and must be this user's.
    let mut missing = login_request(user, "2.x");
    missing
        .as_object_mut()
        .expect("an object")
        .remove("encryptedFor");
    let (status, _) = h
        .json("POST", "/api/ciphers", Some(&token), Some(missing))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut other = login_request(user, "2.x");
    other["encryptedFor"] = json!(uuid::Uuid::new_v4().to_string());
    let (status, body) = h
        .json("POST", "/api/ciphers", Some(&token), Some(other))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["message"], "Invalid user cipher");

    let mut bad_folder = login_request(user, "2.x");
    bad_folder["folderId"] = json!(uuid::Uuid::new_v4().to_string());
    let (status, body) = h
        .json("POST", "/api/ciphers", Some(&token), Some(bad_folder))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid folder");

    let mut org = login_request(user, "2.x");
    org["organizationId"] = json!(uuid::Uuid::new_v4().to_string());
    let (_, body) = h
        .json("POST", "/api/ciphers", Some(&token), Some(org))
        .await;
    assert_eq!(
        body["message"],
        "You don't have permission to add item to organization"
    );

    // The mobile apps' null date on a create is ignored.
    let mut create = login_request(user, "2.x");
    create["lastKnownRevisionDate"] = json!("0001-01-01T00:00:00");
    let (status, cipher) = h
        .json("POST", "/api/ciphers", Some(&token), Some(create))
        .await;
    assert_eq!(status, StatusCode::OK, "{cipher}");
    let id = cipher["id"].as_str().expect("an id").to_owned();
    let revision_date = cipher["revisionDate"].as_str().expect("a date").to_owned();

    // An update with the revision date it read passes; with one 10 seconds older, it is stale.
    h.env.advance(Duration::seconds(10));
    let mut update = login_request(user, "2.renamed");
    update["lastKnownRevisionDate"] = json!(revision_date);
    let (status, updated) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&token),
            Some(update),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["name"], "2.renamed");
    assert_ne!(updated["revisionDate"], cipher["revisionDate"]);
    assert_eq!(updated["creationDate"], cipher["creationDate"]);
    let mut stale = login_request(user, "2.stale");
    stale["lastKnownRevisionDate"] = json!(revision_date);
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&token),
            Some(stale),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "The client copy of this cipher is out of date. Resync the client and try again."
    );
    // An unparsable date doesn't stop a write.
    let mut odd = login_request(user, "2.odd");
    odd["lastKnownRevisionDate"] = json!("yesterday");
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&token),
            Some(odd),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{}", uuid::Uuid::new_v4()),
            Some(&token),
            Some(login_request(user, "2.n")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher doesn't exist");
}

#[tokio::test]
async fn unknown_keys_and_passkeys_survive_an_update_byte_for_byte() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let mut request = login_request(user, "2.name");
    request["login"]["fido2Credentials"] = json!([{"credentialId": "2.id", "keyValue": "2.kv", "counter": "0", "creationDate": "2026-01-01T00:00:00Z"}]);
    request["login"]["somethingNew"] = json!({"a": [1, 2, 3]});
    request["fields"] = json!([{"name": "2.amethystora-vault", "value": "2.v", "type": 0}]);
    let (_, created) = h
        .json("POST", "/api/ciphers", Some(&token), Some(request.clone()))
        .await;
    assert_eq!(
        created["login"]["fido2Credentials"],
        request["login"]["fido2Credentials"]
    );
    assert_eq!(
        created["login"]["somethingNew"],
        request["login"]["somethingNew"]
    );
    assert_eq!(created["fields"], request["fields"]);

    let id = created["id"].as_str().expect("an id");
    request["login"]["password"] = json!("2.changed");
    let (_, updated) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}"),
            Some(&token),
            Some(request.clone()),
        )
        .await;
    assert_eq!(updated["login"]["password"], "2.changed");
    assert_eq!(
        updated["login"]["fido2Credentials"],
        request["login"]["fido2Credentials"]
    );
    assert_eq!(
        updated["login"]["somethingNew"],
        request["login"]["somethingNew"]
    );
}

#[tokio::test]
async fn trash_restore_and_permanent_delete_keep_their_verbs() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let create = |name: &'static str| {
        let (h, token) = (&h, token.clone());
        async move {
            h.json(
                "POST",
                "/api/ciphers",
                Some(&token),
                Some(login_request(user, name)),
            )
            .await
            .1["id"]
                .as_str()
                .expect("an id")
                .to_owned()
        }
    };
    let a = create("2.a").await;
    let b = create("2.b").await;
    let c = create("2.c").await;

    // PUT .../delete is the trash.
    let (status, _, bytes) = h
        .send(
            "PUT",
            &format!("/api/ciphers/{a}/delete"),
            &[("authorization", format!("Bearer {token}").as_str())],
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    let (_, trashed) = h
        .json("GET", &format!("/api/ciphers/{a}"), Some(&token), None)
        .await;
    assert!(trashed["deletedDate"].is_string());
    let (_, restored) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{a}/restore"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(restored["deletedDate"], Value::Null);

    // DELETE and POST .../delete are permanent.
    let (status, _) = h
        .json("DELETE", &format!("/api/ciphers/{a}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .json("GET", &format!("/api/ciphers/{a}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher doesn't exist");
    h.json(
        "POST",
        &format!("/api/ciphers/{b}/delete"),
        Some(&token),
        None,
    )
    .await;
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(sync["ciphers"].as_array().map(Vec::len), Some(1));

    // Bulk: trash, restore, delete.
    h.json(
        "PUT",
        "/api/ciphers/delete",
        Some(&token),
        Some(json!({"ids": [c]})),
    )
    .await;
    let (_, one) = h
        .json("GET", &format!("/api/ciphers/{c}"), Some(&token), None)
        .await;
    assert!(one["deletedDate"].is_string());
    let (_, list) = h
        .json(
            "PUT",
            "/api/ciphers/restore",
            Some(&token),
            Some(json!({"ids": [c]})),
        )
        .await;
    assert_eq!(list["object"], "list");
    assert_eq!(list["data"][0]["deletedDate"], Value::Null);
    h.json(
        "DELETE",
        "/api/ciphers",
        Some(&token),
        Some(json!({"ids": [c]})),
    )
    .await;
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(sync["ciphers"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn folders_move_and_vanish_without_losing_ciphers() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, folder) = h
        .json(
            "POST",
            "/api/folders",
            Some(&token),
            Some(json!({"name": "2.a"})),
        )
        .await;
    let fid = folder["id"].as_str().expect("an id").to_owned();
    let (_, renamed) = h
        .json(
            "PUT",
            &format!("/api/folders/{fid}"),
            Some(&token),
            Some(json!({"name": "2.b"})),
        )
        .await;
    assert_eq!(renamed["name"], "2.b");
    let (_, list) = h.json("GET", "/api/folders", Some(&token), None).await;
    assert_eq!(list["data"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["object"], "list");
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/folders/{}", uuid::Uuid::new_v4()),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid folder");

    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.c")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();
    let (status, _) = h
        .json(
            "POST",
            "/api/ciphers/move",
            Some(&token),
            Some(json!({"folderId": fid, "ids": [cid]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, moved) = h
        .json("GET", &format!("/api/ciphers/{cid}"), Some(&token), None)
        .await;
    assert_eq!(moved["folderId"], fid.as_str());
    assert_eq!(
        moved["revisionDate"], cipher["revisionDate"],
        "a move leaves the cipher's date"
    );
    // Moving something that isn't there says how many moved.
    let (status, body) = h
        .json(
            "POST",
            "/api/ciphers/move",
            Some(&token),
            Some(json!({"folderId": null, "ids": [cid, uuid::Uuid::new_v4().to_string()]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Not all ciphers are moved! 1 of the selected 2 were moved."
    );

    let (status, _) = h
        .json("DELETE", &format!("/api/folders/{fid}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(sync["folders"], json!([]));
    assert_eq!(sync["ciphers"].as_array().map(Vec::len), Some(1));
    assert_eq!(sync["ciphers"][0]["folderId"], Value::Null);
}

#[tokio::test]
async fn an_import_makes_folders_and_ciphers_or_nothing() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let body = json!({
        "ciphers": [login_request(user, "2.one"), login_request(user, "2.two")],
        "folders": [{"name": "2.imported"}],
        "folderRelationships": [{"key": 1, "value": 0}]
    });
    let before = revision(&h, &token).await;
    let (status, _) = h
        .json("POST", "/api/ciphers/import", Some(&token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(revision(&h, &token).await > before);
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(sync["folders"].as_array().map(Vec::len), Some(1));
    let ciphers = sync["ciphers"].as_array().expect("a list");
    assert_eq!(ciphers.len(), 2);
    let in_folder = ciphers.iter().filter(|c| c["folderId"].is_string()).count();
    assert_eq!(in_folder, 1);

    let mut long = login_request(user, "2.long");
    long["notes"] = json!("n".repeat(10_001));
    let (status, body) = h
        .json(
            "POST",
            "/api/ciphers/import",
            Some(&token),
            Some(json!({"ciphers": [login_request(user, "2.ok"), long], "folders": [], "folderRelationships": []})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "The model state is invalid.");
    assert!(body["validationErrors"]["Ciphers[1].Notes"].is_array());
    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(
        sync["ciphers"].as_array().map(Vec::len),
        Some(2),
        "nothing was imported"
    );
}

#[tokio::test]
async fn archived_ciphers_come_back_archived() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let id = cipher["id"].as_str().expect("an id");
    let (_, archived) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}/archive"),
            Some(&token),
            None,
        )
        .await;
    assert!(archived["archivedDate"].is_string());
    let (_, back) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{id}/unarchive"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(back["archivedDate"], Value::Null);
}

#[tokio::test]
async fn another_accounts_data_is_out_of_reach() {
    let h = Harness::new().await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    h.account("bob@example.com", HASH).await;
    let bob = h.login("bob@example.com", HASH).await["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&ada),
            Some(login_request(ada_id, "2.secret")),
        )
        .await;
    let id = cipher["id"].as_str().expect("an id");
    let (status, body) = h
        .json("GET", &format!("/api/ciphers/{id}"), Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher doesn't exist");
    let (_, sync) = h.json("GET", "/api/sync", Some(&bob), None).await;
    assert_eq!(sync["ciphers"], json!([]));
    let (status, _) = h.json("GET", "/api/sync", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.json("GET", "/api/sync", Some("garbage"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn multipart(boundary: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"2.encrypted-name\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test]
async fn an_attachment_is_opened_uploaded_read_downloaded_and_deleted() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();
    let before = revision(&h, &token).await;

    let (status, slot) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/v2"),
            Some(&token),
            Some(json!({"key": "2.attkey", "fileName": "2.file", "fileSize": 17, "adminRequest": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{slot}");
    assert_eq!(slot["object"], "attachment-fileUpload");
    assert_eq!(slot["fileUploadType"], 0);
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();
    assert_eq!(aid.len(), 20);
    assert_eq!(slot["url"], format!("/ciphers/{cid}/attachment/{aid}"));
    assert_eq!(slot["cipherResponse"]["id"], cid.as_str());
    assert_eq!(slot["cipherResponse"]["attachments"][0]["id"], aid.as_str());

    let file = b"0123456789abcdefg".to_vec();
    let boundary = "kemlockboundary";
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let auth = format!("Bearer {token}");
    let (status, _, bytes) = h
        .send(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/{aid}"),
            &[
                ("authorization", auth.as_str()),
                ("content-type", content_type.as_str()),
            ],
            Body::from(multipart(boundary, &file)),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );

    // The cipher shows it, with a link on this server's own host; the cipher's date didn't move,
    // the account's did.
    let (_, shown) = h
        .json(
            "GET",
            &format!("/api/ciphers/{cid}/attachment/{aid}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(shown["object"], "attachment");
    assert_eq!(shown["size"], "17");
    assert_eq!(shown["sizeName"], "17.00 bytes");
    assert_eq!(shown["key"], "2.attkey");
    let url = shown["url"].as_str().expect("a url").to_owned();
    assert!(
        url.starts_with(&format!("{DOMAIN}/attachments/{cid}/{aid}?token=")),
        "{url}"
    );
    let (_, after) = h
        .json("GET", &format!("/api/ciphers/{cid}"), Some(&token), None)
        .await;
    assert_eq!(after["revisionDate"], cipher["revisionDate"]);
    assert!(revision(&h, &token).await > before);

    // The link needs no bearer token, and its one query value is a three-part token.
    let path = url.trim_start_matches(DOMAIN).to_owned();
    let (status, headers, bytes) = h.send("GET", &path, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, file);
    assert_eq!(headers["content-type"], "application/octet-stream");
    let token_part = path.split("token=").nth(1).expect("a token");
    assert_eq!(token_part.split('.').count(), 3);
    let (status, _, _) = h
        .send(
            "GET",
            &format!("/attachments/{cid}/{aid}?token=a.b.c"),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h
        .send(
            "GET",
            &format!("/attachments/{cid}/{aid}"),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A link for another file isn't good for this one, and a minute later it has expired.
    h.env.advance(Duration::seconds(95));
    let (status, _, _) = h.send("GET", &path, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, deleted) = h
        .json(
            "DELETE",
            &format!("/api/ciphers/{cid}/attachment/{aid}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["cipher"]["attachments"], Value::Null);
    assert!(h.blobs.is_empty());
}

#[tokio::test]
async fn a_file_far_from_its_declared_size_loses_its_slot() {
    let h = Harness::new().await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/v2"),
            Some(&token),
            Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": "-1"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Attachment size can't be negative");
    let (_, body) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/v2"),
            Some(&token),
            Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": 600_000_000})),
        )
        .await;
    assert_eq!(body["message"], "Max file size is 525 MB.");

    let (_, slot) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/v2"),
            Some(&token),
            Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": "10"})),
        )
        .await;
    let aid = slot["attachmentId"].as_str().expect("an id");
    let boundary = "b";
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let auth = format!("Bearer {token}");
    let big = vec![1u8; 2 * 1024 * 1024];
    let (status, _, bytes) = h
        .send(
            "POST",
            &format!("/api/ciphers/{cid}/attachment/{aid}"),
            &[
                ("authorization", auth.as_str()),
                ("content-type", content_type.as_str()),
            ],
            Body::from(multipart(boundary, &big)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .starts_with("Attachment size mismatch (expected within [")
    );
    let (_, after) = h
        .json("GET", &format!("/api/ciphers/{cid}"), Some(&token), None)
        .await;
    assert_eq!(after["attachments"], Value::Null);
}

#[tokio::test]
async fn with_the_switch_off_every_bitwarden_route_is_a_404() {
    let h = Harness::with(|s| s.compat = false).await;
    for (method, path) in [
        ("GET", "/api/config"),
        ("POST", "/identity/accounts/prelogin"),
        ("POST", "/identity/connect/token"),
        ("GET", "/api/sync"),
        ("GET", "/api/accounts/revision-date"),
        ("GET", "/attachments/a/b?token=x"),
    ] {
        let (status, _, _) = h.send(method, path, &[], Body::empty()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[test]
fn the_switch_reads_the_environment_the_way_the_design_names_it() {
    assert_eq!(
        kemlock_api_bw::settings::COMPAT_VAR,
        "KEMLOCK_BITWARDEN_COMPAT"
    );
    assert!(kemlock_api_bw::settings::compat_enabled(None));
    assert!(!kemlock_api_bw::settings::compat_enabled(Some("false")));
}

/// Opens a slot for a file of `size` bytes: the status and the answer.
async fn open_slot(h: &Harness, token: &str, cid: &str, size: u64) -> (StatusCode, Value) {
    h.json(
        "POST",
        &format!("/api/ciphers/{cid}/attachment/v2"),
        Some(token),
        Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": size})),
    )
    .await
}

async fn send_file(h: &Harness, token: &str, cid: &str, aid: &str, size: usize) -> StatusCode {
    let boundary = "quota";
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let auth = format!("Bearer {token}");
    h.send(
        "POST",
        &format!("/api/ciphers/{cid}/attachment/{aid}"),
        &[
            ("authorization", auth.as_str()),
            ("content-type", content_type.as_str()),
        ],
        Body::from(multipart(boundary, &vec![7u8; size])),
    )
    .await
    .0
}

#[tokio::test]
async fn an_attachment_that_does_not_fit_the_quota_is_refused_in_vaultwardens_words() {
    let live = kemlock_app::admin::Live::new(false);
    live.set_user_attachment_limit(Some(1024));
    let shared = live.clone();
    let h = Harness::with(move |s| s.live = Some(shared)).await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();

    let (status, slot) = open_slot(&h, &token, &cid, 600).await;
    assert_eq!(status, StatusCode::OK, "{slot}");
    let first = slot["attachmentId"].as_str().expect("an id").to_owned();
    assert_eq!(
        send_file(&h, &token, &cid, &first, 600).await,
        StatusCode::OK
    );

    // 424 bytes are left: one more byte doesn't fit.
    let (status, body) = open_slot(&h, &token, &cid, 425).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Attachment storage limit exceeded with this file"
    );
    let (status, slot) = open_slot(&h, &token, &cid, 424).await;
    assert_eq!(status, StatusCode::OK, "{slot}");
    let second = slot["attachmentId"].as_str().expect("an id").to_owned();
    assert_eq!(
        send_file(&h, &token, &cid, &second, 424).await,
        StatusCode::OK
    );

    // Nothing is left.
    let (status, body) = open_slot(&h, &token, &cid, 1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Attachment storage limit reached! Delete some attachments to free up space"
    );

    // 0 switches attachments off.
    live.set_user_attachment_limit(Some(0));
    let (status, body) = open_slot(&h, &token, &cid, 1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Attachments are disabled");
}

#[tokio::test]
async fn a_quota_lowered_before_the_bytes_arrive_refuses_them_and_keeps_the_slot() {
    let live = kemlock_app::admin::Live::new(false);
    live.set_user_attachment_limit(Some(1024));
    let shared = live.clone();
    let h = Harness::with(move |s| s.live = Some(shared)).await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();
    let (status, slot) = open_slot(&h, &token, &cid, 600).await;
    assert_eq!(status, StatusCode::OK, "{slot}");
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();

    // Vaultwarden's save_attachment refuses the file and leaves the slot it was opened for, where
    // only a size mismatch deletes it.
    live.set_user_attachment_limit(Some(10));
    assert_eq!(
        send_file(&h, &token, &cid, &aid, 600).await,
        StatusCode::BAD_REQUEST
    );
    let (_, shown) = h
        .json("GET", &format!("/api/ciphers/{cid}"), Some(&token), None)
        .await;
    assert_eq!(shown["attachments"][0]["id"], aid.as_str(), "{shown}");
    assert!(h.blobs.is_empty());

    // With the room back the same slot takes the file.
    live.set_user_attachment_limit(Some(1024));
    assert_eq!(send_file(&h, &token, &cid, &aid, 600).await, StatusCode::OK);
}

#[tokio::test]
async fn announces_that_arrive_together_cannot_overrun_the_attachment_quota() {
    let live = kemlock_app::admin::Live::new(false);
    live.set_user_attachment_limit(Some(1024));
    let shared = live.clone();
    let h = Harness::with(move |s| s.live = Some(shared)).await;
    let (token, user) = h.signed_in("ada@example.com").await;
    let (_, cipher) = h
        .json(
            "POST",
            "/api/ciphers",
            Some(&token),
            Some(login_request(user, "2.a")),
        )
        .await;
    let cid = cipher["id"].as_str().expect("an id").to_owned();

    // 1 KiB holds one file of 600, not two.
    let (first, second) = tokio::join!(
        open_slot(&h, &token, &cid, 600),
        open_slot(&h, &token, &cid, 600)
    );
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
}
