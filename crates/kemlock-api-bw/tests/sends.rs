//! Sends through the router, with the shapes and messages of Vaultwarden 1.37.5.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, Harness, keys};
use serde_json::{Value, json};

/// A week after the harness clock's start.
const DELETE_IN_A_WEEK: &str = "2026-11-28T12:00:00.000Z";

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn text_send(name: &str) -> Value {
    json!({
        "type": 0,
        "key": "2.key|iv|mac",
        "name": name,
        "notes": null,
        "text": {"text": "2.text|iv|mac", "hidden": false},
        "file": null,
        "deletionDate": DELETE_IN_A_WEEK,
        "expirationDate": null,
        "maxAccessCount": null,
        "password": null,
        "disabled": false,
        "hideEmail": false
    })
}

/// A token a recipient would be handed, made with the server's key.
fn recipient_token(h: &Harness, send: &str) -> String {
    let now = h.env.time().unix_timestamp();
    keys()
        .encode(&json!({
            "nbf": now,
            "exp": now + 120,
            "iss": format!("{DOMAIN}|send"),
            "sub": send,
        }))
        .expect("a token")
}

async fn create(h: &Harness, token: &str, body: Value) -> Value {
    let (status, send) = h.json("POST", "/api/sends", Some(token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{send}");
    send
}

#[tokio::test]
async fn a_text_send_has_vaultwardens_shape_and_is_listed_synced_edited_and_deleted() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;

    let send = create(&h, &token, text_send("2.name|iv|mac")).await;
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
        ]
    );
    assert_eq!(send["object"], "send");
    assert_eq!(send["type"], 0);
    assert_eq!(send["authType"], 2);
    assert_eq!(send["accessCount"], 0);
    assert_eq!(send["text"]["text"], "2.text|iv|mac");
    assert_eq!(send["text"]["hidden"], false);
    assert!(send["file"].is_null());
    assert!(send["password"].is_null());
    assert_eq!(send["deletionDate"], "2026-11-28T12:00:00.000000Z");
    let id = send["id"].as_str().expect("an id").to_owned();
    assert_eq!(send["accessId"].as_str().map(str::len), Some(22));

    let (status, list) = h.json("GET", "/api/sends", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["object"], "list");
    assert!(list["continuationToken"].is_null());
    assert_eq!(list["data"][0]["id"], id.as_str());

    let (_, sync) = h.json("GET", "/api/sync", Some(&token), None).await;
    assert_eq!(sync["sends"][0]["id"], id.as_str());
    assert_eq!(sync["sends"][0]["object"], "send");

    let mut edit = text_send("2.renamed|iv|mac");
    edit["maxAccessCount"] = json!("3");
    let (status, edited) = h
        .json("PUT", &format!("/api/sends/{id}"), Some(&token), Some(edit))
        .await;
    assert_eq!(status, StatusCode::OK, "{edited}");
    assert_eq!(edited["name"], "2.renamed|iv|mac");
    assert_eq!(edited["maxAccessCount"], 3, "a text number is read as one");

    let (status, one) = h
        .json("GET", &format!("/api/sends/{id}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["name"], "2.renamed|iv|mac");

    let (status, _) = h
        .json("DELETE", &format!("/api/sends/{id}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .json("GET", &format!("/api/sends/{id}"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Send not found");
    let (_, list) = h.json("GET", "/api/sends", Some(&token), None).await;
    assert_eq!(list["data"], json!([]));
}

#[tokio::test]
async fn a_send_is_refused_with_vaultwardens_messages() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;

    let mut far = text_send("2.n");
    far["deletionDate"] = json!("2027-03-01T00:00:00.000Z");
    let (status, body) = h.json("POST", "/api/sends", Some(&token), Some(far)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
    );

    let mut emails = text_send("2.n");
    emails["emails"] = json!("a@example.com");
    let (_, body) = h
        .json("POST", "/api/sends", Some(&token), Some(emails))
        .await;
    assert_eq!(
        body["message"],
        "Sends with email verification is not supported"
    );

    let mut file = text_send("2.n");
    file["type"] = json!(1);
    file["file"] = json!({"fileName": "2.f"});
    let (_, body) = h.json("POST", "/api/sends", Some(&token), Some(file)).await;
    assert_eq!(body["message"], "File sends should use /api/sends/file/v2");

    let mut bad = text_send("2.n");
    bad["type"] = json!(7);
    let (_, body) = h.json("POST", "/api/sends", Some(&token), Some(bad)).await;
    assert_eq!(body["message"], "Invalid Send type");

    let mut none = text_send("2.n");
    none["text"] = Value::Null;
    let (_, body) = h.json("POST", "/api/sends", Some(&token), Some(none)).await;
    assert_eq!(body["message"], "Send data not provided");

    let mut count = text_send("2.n");
    count["maxAccessCount"] = json!("many");
    let (_, body) = h
        .json("POST", "/api/sends", Some(&token), Some(count))
        .await;
    assert_eq!(body["message"], "Can't convert to number");

    // A Send never changes type.
    let send = create(&h, &token, text_send("2.n")).await;
    let id = send["id"].as_str().expect("an id");
    let mut other = text_send("2.n");
    other["type"] = json!(1);
    let (_, body) = h
        .json(
            "PUT",
            &format!("/api/sends/{id}"),
            Some(&token),
            Some(other),
        )
        .await;
    assert_eq!(body["message"], "Sends can't change type");

    // A body of the wrong shape is a 422, as Rocket's JSON guard answers.
    let (status, _) = h
        .json("POST", "/api/sends", Some(&token), Some(json!({"type": 0})))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_password_is_hashed_and_taken_away_by_remove_password() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;
    let mut body = text_send("2.n");
    body["password"] = json!("client-hash");
    let send = create(&h, &token, body).await;
    assert_eq!(send["authType"], 1);
    assert!(send["password"].is_string());
    assert_ne!(send["password"], "client-hash", "only a hash is kept");
    let id = send["id"].as_str().expect("an id");

    let (status, removed) = h
        .json(
            "PUT",
            &format!("/api/sends/{id}/remove-password"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["authType"], 2);
    assert!(removed["password"].is_null());
}

#[tokio::test]
async fn a_recipient_reads_a_text_send_with_a_token_and_the_count_is_kept() {
    let h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let mut body = text_send("2.shared");
    body["maxAccessCount"] = json!(1);
    let send = create(&h, &owner, body).await;
    let id = send["id"].as_str().expect("an id").to_owned();
    let token = recipient_token(&h, &id);

    let (status, access) = h
        .json("POST", "/api/sends/access", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{access}");
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
    assert_eq!(access["id"], send["accessId"]);
    assert_eq!(access["name"], "2.shared");
    assert_eq!(access["text"]["text"], "2.text|iv|mac");
    assert_eq!(access["creatorIdentifier"], "ada@example.com");

    // That was the one access there was.
    let (status, body) = h
        .json("POST", "/api/sends/access", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body["message"],
        "Send does not exist or is no longer available"
    );

    let (_, one) = h
        .json("GET", &format!("/api/sends/{id}"), Some(&owner), None)
        .await;
    assert_eq!(one["accessCount"], 1);
}

#[tokio::test]
async fn a_recipient_without_a_token_or_for_an_unreachable_send_is_turned_away() {
    let h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;

    let (status, _) = h.json("POST", "/api/sends/access", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .json("POST", "/api/sends/access", Some("not-a-token"), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let missing = recipient_token(&h, "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a");
    let (status, body) = h
        .json("POST", "/api/sends/access", Some(&missing), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body["message"],
        "Send does not exist or is no longer available"
    );

    // A disabled Send can't be reached either, and a hidden email isn't shown.
    let mut disabled = text_send("2.off");
    disabled["disabled"] = json!(true);
    let send = create(&h, &owner, disabled).await;
    let token = recipient_token(&h, send["id"].as_str().expect("an id"));
    let (status, _) = h
        .json("POST", "/api/sends/access", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mut hidden = text_send("2.hidden");
    hidden["hideEmail"] = json!(true);
    let send = create(&h, &owner, hidden).await;
    let token = recipient_token(&h, send["id"].as_str().expect("an id"));
    let (_, access) = h
        .json("POST", "/api/sends/access", Some(&token), None)
        .await;
    assert!(access["creatorIdentifier"].is_null(), "{access}");
}

fn multipart(name: Option<&str>, bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = "kemlock-test-boundary";
    let disposition = match name {
        Some(name) => format!("form-data; name=\"data\"; filename=\"{name}\""),
        None => "form-data; name=\"data\"".to_owned(),
    };
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: {disposition}\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn upload(
    h: &Harness,
    token: &str,
    path: &str,
    name: Option<&str>,
    bytes: &[u8],
) -> (StatusCode, Value) {
    let (content_type, body) = multipart(name, bytes);
    let auth = format!("Bearer {token}");
    let (status, _, answer) = h
        .send(
            "POST",
            path,
            &[
                ("content-type", content_type.as_str()),
                ("authorization", auth.as_str()),
            ],
            Body::from(body),
        )
        .await;
    (
        status,
        serde_json::from_slice(&answer).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_file_send_is_uploaded_counted_and_downloaded_once_per_access() {
    let h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;

    let mut request = text_send("2.file");
    request["type"] = json!(1);
    request["text"] = Value::Null;
    request["file"] = json!({"fileName": "2.report|iv|mac"});
    request["fileLength"] = json!(5);
    let (status, made) = h
        .json("POST", "/api/sends/file/v2", Some(&owner), Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert_eq!(
        sorted_keys(&made),
        ["fileUploadType", "object", "sendResponse", "url"]
    );
    assert_eq!(made["fileUploadType"], 0);
    assert_eq!(made["object"], "send-fileUpload");
    let send = &made["sendResponse"];
    let id = send["id"].as_str().expect("an id").to_owned();
    let file_id = send["file"]["id"].as_str().expect("a file id").to_owned();
    assert_eq!(file_id.len(), 64);
    assert_eq!(
        send["file"]["size"], "5",
        "mobile clients read the size as text"
    );
    assert_eq!(send["file"]["sizeName"], "5.00 bytes");
    assert_eq!(made["url"], format!("/sends/{id}/file/{file_id}").as_str());

    let path = format!("/api/sends/{id}/file/{file_id}");
    let (status, body) = upload(&h, &owner, &path, Some("2.report|iv|mac"), b"abcdef").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Send file size does not match.");
    let (_, body) = upload(&h, &owner, &path, Some("2.other"), b"abcde").await;
    assert_eq!(body["message"], "Send file name does not match.");
    let (_, body) = upload(&h, &owner, &path, None, b"abcde").await;
    assert_eq!(
        body["message"],
        "Send file name does not match or is not provided."
    );
    let (_, body) = upload(
        &h,
        &owner,
        &format!("/api/sends/{id}/file/someotherfile"),
        Some("2.report|iv|mac"),
        b"abcde",
    )
    .await;
    assert_eq!(body["message"], "Send file does not match send data.");
    let (status, _) = upload(&h, &owner, &path, Some("2.report|iv|mac"), b"abcde").await;
    assert_eq!(status, StatusCode::OK);

    // A recipient asks for the file and follows the link.
    let token = recipient_token(&h, &id);
    let (status, link) = h
        .json(
            "POST",
            &format!("/api/sends/access/file/{file_id}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{link}");
    assert_eq!(link["object"], "send-fileDownload");
    assert_eq!(link["id"], file_id.as_str());
    let url = link["url"].as_str().expect("a url");
    let path = url.strip_prefix(DOMAIN).expect("on this server's host");
    let (status, _, bytes) = h.send("GET", path, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, b"abcde");

    // The link is for one file of one Send.
    let wrong = path.replace(&file_id, "0".repeat(64).as_str());
    let (status, _, _) = h.send("GET", &wrong, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h
        .send(
            "GET",
            &format!("/api/sends/{id}/{file_id}"),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no token, no file");

    // The file's access was counted when its link was given out.
    let (_, one) = h
        .json("GET", &format!("/api/sends/{id}"), Some(&owner), None)
        .await;
    assert_eq!(one["accessCount"], 1);

    // The file goes with the Send.
    h.json("DELETE", &format!("/api/sends/{id}"), Some(&owner), None)
        .await;
    assert!(h.blobs.is_empty());
}

#[tokio::test]
async fn a_text_send_has_no_file_to_ask_for() {
    let h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let send = create(&h, &owner, text_send("2.t")).await;
    let token = recipient_token(&h, send["id"].as_str().expect("an id"));
    let (status, body) = h
        .json("POST", "/api/sends/access/file/abc", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Send is not a file type send.");
}

#[tokio::test]
async fn the_send_access_grant_takes_ten_password_tries_a_minute_per_send() {
    let h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let mut body = text_send("2.guarded");
    body["password"] = json!("client-hash");
    let guarded = create(&h, &owner, body).await;
    let mut body = text_send("2.other");
    body["password"] = json!("client-hash");
    let other = create(&h, &owner, body).await;
    let grant = |send: &Value, password: &'static str| {
        let h = &h;
        let access_id = send["accessId"].as_str().expect("an access id").to_owned();
        async move {
            h.token(&[
                ("grant_type", "send_access"),
                ("client_id", "send"),
                ("send_id", access_id.as_str()),
                ("password_hash_b64", password),
            ])
            .await
        }
    };

    for _ in 0..10 {
        let (status, body) = grant(&guarded, "wrong").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["send_access_error_type"], "password_hash_b64_invalid");
    }
    // The eleventh try is refused, even with the right password.
    let (status, body) = grant(&guarded, "client-hash").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.get("access_token").is_none());
    // The count is the Send's, so another Send is untouched.
    let (status, body) = grant(&other, "client-hash").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "api.send.access");

    // A minute later the window has turned over.
    h.env.advance(time::Duration::seconds(60));
    let (status, body) = grant(&guarded, "client-hash").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_send_limit_counts_the_accounts_file_sends_and_zero_switches_them_off() {
    // `USER_SEND_LIMIT` is in KiB: 1 KiB here.
    let live = kemlock_app::admin::Live::new(false);
    live.set_send_limit(Some(1024));
    let shared = live.clone();
    let h = Harness::with(move |s| s.live = Some(shared)).await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let file_send = |length: u64| {
        let mut request = text_send("2.file");
        request["type"] = json!(1);
        request["text"] = Value::Null;
        request["file"] = json!({"fileName": "2.report|iv|mac"});
        request["fileLength"] = json!(length);
        request
    };
    let ask = |length: u64| {
        let (h, owner, request) = (&h, &owner, file_send(length));
        async move {
            h.json("POST", "/api/sends/file/v2", Some(owner), Some(request))
                .await
        }
    };

    let (status, made) = ask(600).await;
    assert_eq!(status, StatusCode::OK, "{made}");
    // 424 bytes are left: one more byte doesn't fit, and exactly that many does.
    let (status, body) = ask(425).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Send storage limit exceeded with this file"
    );
    let (status, made) = ask(424).await;
    assert_eq!(status, StatusCode::OK, "{made}");
    // Nothing is left.
    let (status, body) = ask(1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Send storage limit reached! Delete some sends to free up space"
    );
    // A text Send takes none of it.
    let (status, _) = h
        .json(
            "POST",
            "/api/sends",
            Some(&owner),
            Some(text_send("2.note")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    live.set_send_limit(Some(0));
    let (status, body) = ask(1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "File uploads are disabled");
}

#[tokio::test]
async fn file_sends_made_together_cannot_overrun_the_send_limit() {
    let live = kemlock_app::admin::Live::new(false);
    live.set_send_limit(Some(1024));
    let shared = live.clone();
    let h = Harness::with(move |s| s.live = Some(shared)).await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let ask = || {
        let mut request = text_send("2.file");
        request["type"] = json!(1);
        request["text"] = Value::Null;
        request["file"] = json!({"fileName": "2.report|iv|mac"});
        request["fileLength"] = json!(600);
        h.json("POST", "/api/sends/file/v2", Some(&owner), Some(request))
    };

    // 1 KiB holds one file of 600, not two.
    let (first, second) = tokio::join!(ask(), ask());
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
}

// ---------------------------------------------------------------------------------------------
// A replica serves no Send that has a view limit.

/// A federation view of a replica: the account's vault has its home elsewhere.
struct ReplicaView;

impl kemlock_app::federation_view::FederationView for ReplicaView {
    fn vault_servers(
        &self,
        _vault: kemlock_domain::Owner,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        Result<Option<kemlock_app::federation_view::VaultServers>, kemlock_app::ports::StoreError>,
    > {
        Box::pin(async { Ok(None) })
    }

    fn siblings(
        &self,
        _owner: kemlock_domain::Owner,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        Result<Vec<kemlock_app::federation_view::SiblingSet>, kemlock_app::ports::StoreError>,
    > {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn resolve_siblings(
        &self,
        _owner: kemlock_domain::Owner,
        _item: kemlock_domain::ItemId,
    ) -> kemlock_app::federation_view::BoxFut<'_, Result<u64, kemlock_app::ports::StoreError>> {
        Box::pin(async { Ok(0) })
    }

    fn is_replica_account(
        &self,
        _user: kemlock_domain::UserId,
    ) -> kemlock_app::federation_view::BoxFut<'_, Result<bool, kemlock_app::ports::StoreError>>
    {
        Box::pin(async { Ok(true) })
    }

    fn limited_send_home(
        &self,
        _owner: kemlock_domain::UserId,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        Result<Option<String>, kemlock_app::ports::StoreError>,
    > {
        Box::pin(async { Ok(Some("https://nas.example.org".to_owned())) })
    }
}

#[tokio::test]
async fn a_replica_answers_a_send_with_a_view_limit_as_unavailable_and_serves_one_without() {
    let mut h = Harness::new().await;
    let (owner, _) = h.signed_in("ada@example.com").await;
    let mut limited = text_send("2.limited");
    limited["maxAccessCount"] = json!(3);
    let limited = create(&h, &owner, limited).await;
    let open = create(&h, &owner, text_send("2.open")).await;
    let limited_token = recipient_token(&h, limited["id"].as_str().expect("id"));
    let open_token = recipient_token(&h, open["id"].as_str().expect("id"));

    let view: kemlock_app::federation_view::SharedView = std::sync::Arc::new(ReplicaView);
    h.router = h.router.clone().layer(axum::Extension(view));

    // Vaultwarden's answer for a Send that can't be reached: nothing is counted.
    let (status, body) = h
        .json("POST", "/api/sends/access", Some(&limited_token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        body["message"],
        "Send does not exist or is no longer available"
    );
    let (status, _) = h
        .json(
            "POST",
            "/api/sends/access/file/abc",
            Some(&limited_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, served) = h
        .json("POST", "/api/sends/access", Some(&open_token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{served}");
    let (_, listed) = h
        .json(
            "GET",
            &format!("/api/sends/{}", limited["id"].as_str().expect("id")),
            Some(&owner),
            None,
        )
        .await;
    assert_eq!(
        listed["accessCount"], 0,
        "the refused access counted no view"
    );
}
