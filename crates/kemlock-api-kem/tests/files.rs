//! The file routes in-process: DPoP-authenticated, with the real blob store over memory (so the
//! `KMA1` checks are the adapter's own) and an in-memory attachment table.

mod common;
#[path = "../../kemlock-app/tests/file_fakes/mod.rs"]
mod file_fakes;

use axum::http::StatusCode;
use common::*;
use file_fakes::FakeAttachments;
use kemlock_api_kem::files_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::files::{BlobStore, BlobUpload, FilesConfig};
use kemlock_app::ports::Clock;
use kemlock_blob::{ObjectBlobStore, S3Config, kma1};
use kemlock_domain::{Attachment, AttachmentId, AttachmentLimits, AttachmentStatus, BlobId, Owner};
use serde_json::json;
use std::time::Duration;

/// The app's two-chunk `KMA1` fixture, byte for byte.
const TWO_CHUNKS: &[u8] = include_bytes!("../../kemlock-blob/tests/fixtures/two-chunks.kma1");

/// A `KMA1`-shaped file of a valid length: the right header, filler for the rest.
fn kma1_file(plain: usize) -> Vec<u8> {
    let len = usize::try_from(kma1::sealed_length(plain as u64)).expect("fits");
    let mut bytes = b"KMA1".to_vec();
    bytes.extend((0..len - 4).map(|i| (i % 253) as u8));
    bytes
}

struct Setup {
    app: App,
    merged: axum::Router,
    client: Client,
    session: Session,
    attachments: FakeAttachments,
    blobs: ObjectBlobStore,
}

async fn setup() -> Setup {
    setup_with(FilesConfig::default(), ObjectBlobStore::memory()).await
}

async fn setup_with(config: FilesConfig, blobs: ObjectBlobStore) -> Setup {
    let app = App::new(true);
    let attachments = FakeAttachments::new();
    let merged = app.router.clone().merge(files_router(
        app.api.clone(),
        blobs.clone(),
        attachments.clone(),
        config,
    ));
    let client = Client::new(merged.clone(), app.clock.clone(), DpopSigner::es256());
    let session = register_and_sign_in(&client, "sam@example.org").await;
    Setup {
        app,
        merged,
        client,
        session,
        attachments,
        blobs,
    }
}

impl Setup {
    /// Another account on the same server, with a device of its own.
    async fn stranger(&self) -> (Client, Session) {
        let client = Client::new(
            self.merged.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in(&client, "ann@example.org").await;
        (client, session)
    }
}

fn files_uri(item: &str) -> String {
    format!("/kem/v1/items/{item}/files")
}

fn file_uri(item: &str, file: &str) -> String {
    format!("/kem/v1/items/{item}/files/{file}")
}

fn authed(session: &Session) -> Req<'_> {
    Req {
        access_token: Some(&session.access_token),
        ..Req::default()
    }
}

async fn start(client: &Client, session: &Session, item: &str, size: u64) -> Reply {
    client
        .send(
            "POST",
            &files_uri(item),
            Req {
                body: Some(json!({ "size": size })),
                ..authed(session)
            },
        )
        .await
}

/// Starts an upload and returns its file id; the start must work.
async fn started(client: &Client, session: &Session, item: &str, size: u64) -> String {
    let reply = start(client, session, item, size).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    reply.json()["fileId"]
        .as_str()
        .expect("a file id")
        .to_owned()
}

/// `PUT`s the bytes with the given `Content-Length` header (none for `None`).
async fn upload(
    client: &Client,
    session: &Session,
    item: &str,
    file: &str,
    bytes: &[u8],
    length: Option<u64>,
) -> Reply {
    let mut headers = vec![("content-type", "application/octet-stream".to_owned())];
    if let Some(length) = length {
        headers.push(("content-length", length.to_string()));
    }
    client
        .send(
            "PUT",
            &file_uri(item, file),
            Req {
                headers,
                raw_body: Some(bytes.to_vec()),
                ..authed(session)
            },
        )
        .await
}

/// Starts and finishes an upload of `bytes` the way a client does; returns the file id.
async fn stored(client: &Client, session: &Session, item: &str, bytes: &[u8]) -> String {
    let file = started(client, session, item, bytes.len() as u64).await;
    let reply = upload(
        client,
        session,
        item,
        &file,
        bytes,
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    file
}

async fn download(client: &Client, session: &Session, item: &str, file: &str) -> Reply {
    client
        .send("GET", &file_uri(item, file), authed(session))
        .await
}

async fn delete(client: &Client, session: &Session, item: &str, file: &str) -> Reply {
    client
        .send("DELETE", &file_uri(item, file), authed(session))
        .await
}

/// Writes a live item of the signed-in account so the item exists.
async fn put_item(s: &Setup) -> String {
    let id = new_item_id();
    let reply = s
        .client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                headers: vec![("if-none-match", "*".to_owned())],
                body: Some(item_json(&s.session.user_id, &id, 1)),
                ..authed(&s.session)
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    id
}

fn blob_of(s: &Setup, file: &str) -> BlobId {
    let id: AttachmentId = file.parse().expect("a file id");
    s.attachments.get(id).expect("the attachment row").blob
}

// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_file_goes_up_comes_back_and_is_deleted() {
    let s = setup().await;
    let item = put_item(&s).await;

    // Start: the id, the limits and where to send the bytes.
    let reply = start(&s.client, &s.session, &item, TWO_CHUNKS.len() as u64).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let json = reply.json();
    let file = json["fileId"].as_str().expect("fileId").to_owned();
    assert_eq!(json["itemId"], item);
    assert_eq!(json["size"], 65_680);
    assert_eq!(json["maxSize"], 100 * 1024 * 1024);
    assert_eq!(json["presigned"], false);
    assert!(json["expiresIn"].is_null());
    let own = format!("{DOMAIN}{}", file_uri(&item, &file));
    assert_eq!(json["uploadUrl"], own);
    assert_eq!(reply.header("location"), Some(own.as_str()));
    assert!(reply.header("dpop-nonce").is_some());

    // Upload: the app's fixture, byte for byte.
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        TWO_CHUNKS,
        Some(TWO_CHUNKS.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["status"], "ready");
    assert_eq!(reply.json()["fileId"], file);
    assert!(
        s.app
            .store
            .events()
            .iter()
            .any(|e| e.action == "attachment.upload" && e.target.as_deref() == Some(file.as_str()))
    );

    // Download: the same bytes, as a stream with its length.
    let reply = download(&s.client, &s.session, &item, &file).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, TWO_CHUNKS);
    assert_eq!(
        reply.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(reply.header("content-length"), Some("65680"));
    assert_eq!(reply.header("cache-control"), Some("private, no-store"));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));

    // A local folder has no pre-signed URLs, so asking for one still gets the bytes.
    let reply = s
        .client
        .send(
            "GET",
            &format!("{}?presign=true", file_uri(&item, &file)),
            authed(&s.session),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, TWO_CHUNKS);

    // Delete: gone, bytes and row.
    let blob = blob_of(&s, &file);
    let reply = delete(&s.client, &s.session, &item, &file).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty());
    let reply = download(&s.client, &s.session, &item, &file).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.problem(), "not-found");
    assert!(s.blobs.open(blob).await.is_err(), "the bytes are gone");
    assert_eq!(
        delete(&s.client, &s.session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_few_megabytes_stream_through_both_ways() {
    let s = setup().await;
    let item = put_item(&s).await;
    let bytes = kma1_file(3 * 1024 * 1024 + 777);
    let file = stored(&s.client, &s.session, &item, &bytes).await;
    let reply = download(&s.client, &s.session, &item, &file).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body == bytes, "the bytes changed on the way");
}

#[tokio::test]
async fn every_route_needs_a_dpop_bound_token() {
    let s = setup().await;
    let item = new_item_id();
    let file = AttachmentId::random().to_string();
    let routes = [
        ("POST", files_uri(&item)),
        ("PUT", file_uri(&item, &file)),
        ("GET", file_uri(&item, &file)),
        ("DELETE", file_uri(&item, &file)),
        ("POST", format!("{}/finish", file_uri(&item, &file))),
    ];
    for (method, uri) in routes {
        // No token.
        let reply = s.client.send(method, &uri, Req::default()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        // A token without a proof.
        let reply = s
            .client
            .send(
                method,
                &uri,
                Req {
                    no_proof: true,
                    ..authed(&s.session)
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(reply.problem(), "invalid-dpop-proof", "{method} {uri}");
    }
}

#[tokio::test]
async fn a_token_used_with_another_devices_key_is_refused() {
    let s = setup().await;
    let thief = Client::new(s.merged.clone(), s.app.clock.clone(), DpopSigner::es256());
    let reply = start(&thief, &s.session, &new_item_id(), 100).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_content_length_is_required_and_must_be_the_size_announced() {
    let s = setup().await;
    let item = put_item(&s).await;
    let bytes = kma1_file(500);
    let file = started(&s.client, &s.session, &item, bytes.len() as u64).await;

    let reply = upload(&s.client, &s.session, &item, &file, &bytes, None).await;
    assert_eq!(reply.status, StatusCode::LENGTH_REQUIRED);
    assert_eq!(reply.problem(), "length-required");

    // A header that says another number than was announced.
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &bytes,
        Some(bytes.len() as u64 + 1),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.problem(), "length-mismatch");

    // A body shorter, or longer, than the header says.
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &bytes[..100],
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.problem(), "length-mismatch");
    let mut longer = bytes.clone();
    longer.extend([0; 10]);
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &longer,
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.problem(), "length-mismatch");

    // Nothing was kept, and the right upload still goes through.
    assert_eq!(
        download(&s.client, &s.session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &bytes,
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
}

#[tokio::test]
async fn bytes_that_are_not_a_kma1_file_are_415() {
    let s = setup().await;
    let item = put_item(&s).await;
    let mut zip = kma1_file(500);
    zip[..4].copy_from_slice(b"PK\x03\x04");
    let file = started(&s.client, &s.session, &item, zip.len() as u64).await;

    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &zip,
        Some(zip.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(reply.problem(), "not-kma1");
    assert!(reply.content_type().starts_with("application/problem+json"));

    // Right magic but a length no chunks make: refused at the end.
    let mut odd = kma1_file(65_536);
    odd.extend([0; 5]);
    let odd_file = started(&s.client, &s.session, &item, odd.len() as u64).await;
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &odd_file,
        &odd,
        Some(odd.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Both are still pending: nothing to download.
    assert_eq!(
        download(&s.client, &s.session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        download(&s.client, &s.session, &item, &odd_file)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_size_limit_is_413_with_the_limit_named() {
    let config = FilesConfig {
        limits: AttachmentLimits { max_size: 1000 },
        ..FilesConfig::default()
    };
    let s = setup_with(config, ObjectBlobStore::memory()).await;
    let item = put_item(&s).await;

    let reply = start(&s.client, &s.session, &item, 1001).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "file-too-large");
    assert_eq!(reply.json()["maxSize"], 1000);

    let reply = start(&s.client, &s.session, &item, 1000).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["maxSize"], 1000);

    let reply = start(&s.client, &s.session, &item, 0).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_file_is_uploaded_once() {
    let s = setup().await;
    let item = put_item(&s).await;
    let bytes = kma1_file(100);
    let file = stored(&s.client, &s.session, &item, &bytes).await;
    let reply = upload(
        &s.client,
        &s.session,
        &item,
        &file,
        &bytes,
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.problem(), "already-uploaded");
}

#[tokio::test]
async fn finishing_settles_a_file_and_is_harmless_twice() {
    let s = setup().await;
    let item = put_item(&s).await;
    let file = started(&s.client, &s.session, &item, 100).await;
    let uri = format!("{}/finish", file_uri(&item, &file));

    // Nothing was uploaded yet.
    let reply = s.client.send("POST", &uri, authed(&s.session)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());

    // Bytes arrive some other way (a pre-signed PUT), then finish.
    let bytes = kma1_file(72);
    assert_eq!(bytes.len(), 100);
    let blob = blob_of(&s, &file);
    let mut writer = s.blobs.begin(blob, 100).await.expect("begins");
    writer
        .write(bytes::Bytes::from(bytes.clone()))
        .await
        .expect("written");
    writer.finish().await.expect("finished");

    let reply = s.client.send("POST", &uri, authed(&s.session)).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["status"], "ready");
    let reply = s.client.send("POST", &uri, authed(&s.session)).await;
    assert_eq!(reply.status, StatusCode::OK);

    assert_eq!(
        download(&s.client, &s.session, &item, &file).await.body,
        bytes
    );
}

#[tokio::test]
async fn nobody_else_reaches_a_file() {
    let s = setup().await;
    let item = put_item(&s).await;
    let bytes = kma1_file(100);
    let file = stored(&s.client, &s.session, &item, &bytes).await;
    let pending = started(&s.client, &s.session, &item, 100).await;
    let (ann, ann_session) = s.stranger().await;

    // Starting a file on someone else's item is forbidden.
    let reply = start(&ann, &ann_session, &item, 100).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Everything else about someone else's file is simply not found.
    assert_eq!(
        download(&ann, &ann_session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(&ann, &ann_session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
    let reply = upload(
        &ann,
        &ann_session,
        &item,
        &pending,
        &bytes,
        Some(bytes.len() as u64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let finish = format!("{}/finish", file_uri(&item, &pending));
    assert_eq!(
        ann.send("POST", &finish, authed(&ann_session)).await.status,
        StatusCode::NOT_FOUND
    );

    // And through another item's URL the owner doesn't reach it either.
    let other = put_item(&s).await;
    assert_eq!(
        download(&s.client, &s.session, &other, &file).await.status,
        StatusCode::NOT_FOUND
    );

    // The owner's file is untouched.
    assert_eq!(
        download(&s.client, &s.session, &item, &file).await.body,
        bytes
    );
}

#[tokio::test]
async fn a_file_may_be_started_before_its_item_is_written() {
    let s = setup().await;
    let item = new_item_id();
    let reply = start(&s.client, &s.session, &item, 100).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

#[tokio::test]
async fn malformed_requests_are_400() {
    let s = setup().await;
    let item = put_item(&s).await;

    let reply = start(&s.client, &s.session, "not-a-uuid", 100).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = download(&s.client, &s.session, &item, "not-a-uuid").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // A body that isn't JSON, and a field that isn't known.
    for body in [
        Req {
            raw_body: Some(b"nope".to_vec()),
            ..authed(&s.session)
        },
        Req {
            body: Some(json!({"size": 100, "name": "passwords.txt"})),
            ..authed(&s.session)
        },
        Req {
            body: Some(json!({"size": -5})),
            ..authed(&s.session)
        },
    ] {
        let reply = s.client.send("POST", &files_uri(&item), body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
    }

    // An unknown file of the right shape.
    let unknown = AttachmentId::random().to_string();
    assert_eq!(
        download(&s.client, &s.session, &item, &unknown)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_pending_file_cannot_be_downloaded_but_can_be_deleted() {
    let s = setup().await;
    let item = put_item(&s).await;
    let file = started(&s.client, &s.session, &item, 100).await;
    assert_eq!(
        download(&s.client, &s.session, &item, &file).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(&s.client, &s.session, &item, &file).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(s.attachments.count(), 0);
}

fn bucket() -> S3Config {
    S3Config {
        endpoint: Some("http://localhost:9000".to_owned()),
        bucket: "kemlock".to_owned(),
        region: "us-east-1".to_owned(),
        access_key_id: "AKIDEXAMPLE".to_owned(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        path_style: true,
    }
}

#[tokio::test]
async fn a_bucket_with_presigning_answers_start_with_its_own_url() {
    let blobs =
        ObjectBlobStore::s3(&bucket(), Some(Duration::from_secs(300))).expect("a bucket store");
    let s = setup_with(FilesConfig::default(), blobs).await;
    let item = put_item(&s).await;

    let reply = start(&s.client, &s.session, &item, 100).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let json = reply.json();
    assert_eq!(json["presigned"], true);
    assert_eq!(json["expiresIn"], 300);
    let url = json["uploadUrl"].as_str().expect("an upload URL");
    assert!(url.starts_with("http://localhost:9000/kemlock/"), "{url}");
    assert!(url.contains("X-Amz-Signature="), "{url}");
    let file = json["fileId"].as_str().expect("fileId");
    // The server's own route is still named, for clients that can't use the bucket.
    assert_eq!(
        reply.header("location"),
        Some(format!("{DOMAIN}{}", file_uri(&item, file)).as_str())
    );

    // A ready file can be fetched through a pre-signed URL when the client asks.
    let id = AttachmentId::random();
    s.attachments.insert(Attachment {
        id,
        item: item.parse().expect("an item id"),
        owner: Owner::User(s.session.user_id.parse().expect("a user id")),
        blob: BlobId::random(),
        size: 100,
        status: AttachmentStatus::Ready,
        created_at: s.app.clock.now(),
    });
    let reply = s
        .client
        .send(
            "GET",
            &format!("{}?presign=true", file_uri(&item, &id.to_string())),
            authed(&s.session),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let json = reply.json();
    assert_eq!(json["expiresIn"], 300);
    assert!(
        json["url"]
            .as_str()
            .is_some_and(|u| u.contains("X-Amz-Signature="))
    );
}

#[tokio::test]
async fn the_routes_do_not_disturb_the_item_routes() {
    let s = setup().await;
    let id = new_item_id();
    let reply = s
        .client
        .send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Req {
                headers: vec![("if-none-match", "*".to_owned())],
                body: Some(item_json(&s.session.user_id, &id, 1)),
                ..authed(&s.session)
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let reply = s
        .client
        .get_authed("/kem/v1/sync", &s.session.access_token)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        s.client.get("/kem/v1/nope").await.status,
        StatusCode::NOT_FOUND
    );
}
