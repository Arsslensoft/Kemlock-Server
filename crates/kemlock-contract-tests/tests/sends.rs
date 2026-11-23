//! Sends: the routes the web vault and the apps call, as Vaultwarden 1.37.5 answers them.
//!
//! The source is Vaultwarden's `src/api/core/sends.rs`, `src/auth/send.rs` and
//! `src/db/models/send.rs`. A recipient gets a short-lived bearer token from
//! `POST /identity/connect/token` (`grant_type=send_access`) and reads the Send with it.

use kemlock_contract_tests::enc::enc;
use kemlock_contract_tests::util::message_of;
use kemlock_contract_tests::{Reply, Session, fresh_session};
use serde_json::{Value, json};

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("an object, got {value}"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// A date a few days ahead, in the form the apps send. The suite's clock is the machine's.
fn in_days(days: i64) -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let seconds = i64::try_from(seconds).unwrap_or(0) + days * 86_400;
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let z = seconds.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let secs_of_day = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        secs_of_day / 3_600,
        secs_of_day % 3_600 / 60,
        secs_of_day % 60
    )
}

fn text_send(name: &str) -> Value {
    json!({
        "type": 0,
        "key": enc("send key"),
        "name": enc(name),
        "notes": null,
        "text": {"text": enc("the text"), "hidden": false},
        "file": null,
        "deletionDate": in_days(7),
        "expirationDate": null,
        "maxAccessCount": null,
        "password": null,
        "disabled": false,
        "hideEmail": false
    })
}

async fn create(s: &Session, body: &Value) -> Value {
    s.post("/api/sends", body).await.ok_json("POST /api/sends")
}

#[tokio::test]
async fn a_text_send_has_vaultwardens_keys_and_is_listed_synced_edited_and_deleted() {
    let s = fresh_session().await;
    let send = create(&s, &text_send("first")).await;
    assert_eq!(
        sorted_keys(&send),
        [
            "accessCount",
            "accessId",
            "authType",
            "deletionDate",
            "disabled",
            "expirationDate",
            "file",
            "hideEmail",
            "id",
            "key",
            "maxAccessCount",
            "name",
            "notes",
            "object",
            "password",
            "revisionDate",
            "text",
            "type"
        ],
        "a send has Vaultwarden's keys: {send}"
    );
    assert_eq!(send["object"], "send");
    assert_eq!(send["authType"], 2, "no password is auth type 2: {send}");
    assert_eq!(send["accessCount"], 0);
    assert!(send["file"].is_null());
    assert_eq!(send["text"]["hidden"], false);
    let id = send["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        send["accessId"].as_str().map(str::len),
        Some(22),
        "the access id is the uuid's bytes as unpadded base64url: {send}"
    );

    let list = s.get("/api/sends").await.ok_json("GET /api/sends");
    assert_eq!(list["object"], "list");
    assert_eq!(list["data"][0]["id"], id.as_str());
    let sync = s.get("/api/sync").await.ok_json("GET /api/sync");
    assert_eq!(
        sync["sends"][0]["id"],
        id.as_str(),
        "a sync lists the sends"
    );

    let mut edit = text_send("renamed");
    edit["maxAccessCount"] = json!("3");
    let edited = s
        .put(&format!("/api/sends/{id}"), &edit)
        .await
        .ok_json("PUT /api/sends/{id}");
    assert_eq!(
        edited["maxAccessCount"], 3,
        "a number sent as text is read as one: {edited}"
    );

    let gone = s.delete(&format!("/api/sends/{id}")).await;
    assert!(gone.is_success(), "{} {}", gone.status, gone.text());
    let missing = s.get(&format!("/api/sends/{id}")).await;
    assert_eq!(missing.status, 400);
    assert_eq!(
        message_of(&missing.json()).as_deref(),
        Some("Send not found")
    );
}

#[tokio::test]
async fn a_send_is_refused_with_vaultwardens_messages() {
    let s = fresh_session().await;

    let mut far = text_send("far");
    far["deletionDate"] = json!(in_days(60));
    let reply = s.post("/api/sends", &far).await;
    assert_eq!(reply.status, 400);
    assert!(
        message_of(&reply.json())
            .is_some_and(|m| m.starts_with("You cannot have a Send with a deletion date that far")),
        "{}",
        reply.text()
    );

    let mut emails = text_send("emails");
    emails["emails"] = json!("someone@example.com");
    let reply = s.post("/api/sends", &emails).await;
    assert_eq!(
        message_of(&reply.json()).as_deref(),
        Some("Sends with email verification is not supported")
    );

    let mut file = text_send("file");
    file["type"] = json!(1);
    file["file"] = json!({"fileName": enc("a.txt")});
    let reply = s.post("/api/sends", &file).await;
    assert_eq!(
        message_of(&reply.json()).as_deref(),
        Some("File sends should use /api/sends/file/v2")
    );

    let send = create(&s, &text_send("fixed type")).await;
    let id = send["id"].as_str().expect("an id");
    let mut other = text_send("fixed type");
    other["type"] = json!(1);
    let reply = s.put(&format!("/api/sends/{id}"), &other).await;
    assert_eq!(
        message_of(&reply.json()).as_deref(),
        Some("Sends can't change type")
    );
}

#[tokio::test]
async fn a_password_is_kept_as_a_hash_and_remove_password_takes_it_away() {
    let s = fresh_session().await;
    let mut body = text_send("protected");
    body["password"] = json!("hash-from-the-client");
    let send = create(&s, &body).await;
    assert_eq!(send["authType"], 1, "{send}");
    assert!(send["password"].is_string());
    assert_ne!(send["password"], "hash-from-the-client");
    let id = send["id"].as_str().expect("an id");

    let removed = s
        .send(s.call("PUT", &format!("/api/sends/{id}/remove-password")))
        .await
        .ok_json("remove-password");
    assert_eq!(removed["authType"], 2);
    assert!(removed["password"].is_null());
}

fn multipart(name: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = "kemlock-contract-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn upload(s: &Session, path: &str, name: &str, bytes: &[u8]) -> Reply {
    let (content_type, body) = multipart(name, bytes);
    s.send(s.call("POST", path).body(&content_type, body)).await
}

#[tokio::test]
async fn a_file_send_is_made_with_a_size_a_file_id_and_an_upload_that_must_match() {
    let s = fresh_session().await;
    let file_name = enc("report.pdf");
    let mut request = text_send("file");
    request["type"] = json!(1);
    request["text"] = Value::Null;
    request["file"] = json!({"fileName": file_name});
    request["fileLength"] = json!(5);
    let made = s
        .post("/api/sends/file/v2", &request)
        .await
        .ok_json("POST /api/sends/file/v2");
    assert_eq!(
        sorted_keys(&made),
        ["fileUploadType", "object", "sendResponse", "url"],
        "{made}"
    );
    assert_eq!(made["fileUploadType"], 0);
    assert_eq!(made["object"], "send-fileUpload");
    let send = &made["sendResponse"];
    let id = send["id"].as_str().expect("an id");
    let file_id = send["file"]["id"].as_str().expect("a file id");
    assert_eq!(
        send["file"]["size"], "5",
        "mobile clients read the size as text: {send}"
    );
    assert_eq!(send["file"]["sizeName"], "5.00 bytes");
    assert_eq!(made["url"], format!("/sends/{id}/file/{file_id}").as_str());

    let path = format!("/api/sends/{id}/file/{file_id}");
    let wrong_size = upload(&s, &path, &file_name, b"abcdef").await;
    assert_eq!(
        message_of(&wrong_size.json()).as_deref(),
        Some("Send file size does not match.")
    );
    let wrong_name = upload(&s, &path, "other.pdf", b"abcde").await;
    assert_eq!(
        message_of(&wrong_name.json()).as_deref(),
        Some("Send file name does not match.")
    );
    let stored = upload(&s, &path, &file_name, b"abcde").await;
    assert!(stored.is_success(), "{} {}", stored.status, stored.text());
}

#[tokio::test]
async fn a_recipient_gets_a_token_reads_the_send_and_the_count_is_kept() {
    let s = fresh_session().await;
    let mut body = text_send("shared");
    body["maxAccessCount"] = json!(1);
    let send = create(&s, &body).await;
    let access_id = send["accessId"].as_str().expect("an access id");

    let form = vec![
        ("grant_type".to_owned(), "send_access".to_owned()),
        ("client_id".to_owned(), "send".to_owned()),
        ("send_id".to_owned(), access_id.to_owned()),
    ];
    let reply = s.http.token(&form).await;
    let token = reply.ok_json("send_access grant");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["scope"], "api.send.access");
    let bearer = token["access_token"].as_str().expect("an access token");

    let access = s
        .http
        .send(s.http.call("POST", "/api/sends/access").bearer(bearer))
        .await
        .ok_json("POST /api/sends/access");
    assert_eq!(
        sorted_keys(&access),
        [
            "creatorIdentifier",
            "expirationDate",
            "file",
            "id",
            "name",
            "object",
            "text",
            "type"
        ]
    );
    assert_eq!(access["object"], "send-access");
    assert_eq!(access["creatorIdentifier"], s.account.email.as_str());

    // That was the one access there was.
    let again = s.http.token(&form).await;
    assert_eq!(again.status, 404, "{}", again.text());
}
