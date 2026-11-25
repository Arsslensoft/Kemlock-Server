//! The Send routes in-process: the owner's DPoP-authenticated routes, the public access routes
//! (password, view limit, rate limit, files), over the real blob store in memory and in-memory
//! Send and policy fakes.

mod common;
#[path = "../../kemlock-app/tests/send_fakes/mod.rs"]
mod send_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::*;
use kemlock_api_kem::sends_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::sends::{SendRules, SendsConfig};
use kemlock_blob::{ObjectBlobStore, kma1};
use kemlock_domain::sends::SendLimits;
use send_fakes::{FakeSends, FixedRules};
use serde_json::{Value, json};
use uuid::Uuid;

const WEEK: i64 = 7 * 24 * 3600;

/// A password proof: the 32 bytes of the client's Argon2id.
const PROOF: [u8; 32] = [7; 32];

/// A `KMA1`-shaped file of a valid length: the right header, filler for the rest.
fn kma1_file(plain: usize) -> Vec<u8> {
    let len = usize::try_from(kma1::sealed_length(plain as u64)).expect("fits");
    let mut bytes = b"KMA1".to_vec();
    bytes.extend((0..len - 4).map(|i| (i % 253) as u8));
    bytes
}

struct Rig {
    app: App,
    merged: Router,
    owner: Client,
    session: Session,
    rules: FixedRules,
    sends: FakeSends,
}

fn rig() -> Rig {
    rig_with(SendsConfig::default())
}

fn rig_with(config: SendsConfig) -> Rig {
    let app = App::new(true);
    let sends = FakeSends::new();
    let rules = FixedRules::new();
    let merged = app.router.clone().merge(sends_router(
        app.api.clone(),
        sends.clone(),
        ObjectBlobStore::memory(),
        rules.clone(),
        config,
    ));
    let owner = Client::new(merged.clone(), app.clock.clone(), DpopSigner::es256());
    Rig {
        app,
        merged,
        owner,
        session: Session {
            access_token: String::new(),
            refresh_token: String::new(),
            user_id: String::new(),
            device_id: String::new(),
        },
        rules,
        sends,
    }
}

impl Rig {
    async fn signed_in() -> Rig {
        Rig::signed_in_with(SendsConfig::default()).await
    }

    async fn signed_in_with(config: SendsConfig) -> Rig {
        let mut rig = rig_with(config);
        rig.session = register_and_sign_in(&rig.owner, "sam@example.org").await;
        rig
    }

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

    /// Someone with a link and no account.
    fn recipient(&self) -> Client {
        Client::new(
            self.merged.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        )
    }

    fn authed(&self) -> Req<'_> {
        Req {
            access_token: Some(&self.session.access_token),
            ..Req::default()
        }
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.owner
            .send(
                method,
                uri,
                Req {
                    body,
                    ..self.authed()
                },
            )
            .await
    }

    fn deletion(&self) -> i64 {
        self.app.now() + WEEK
    }

    /// The request body that makes a note; `with` adds or replaces fields.
    fn note_body(&self, with: Value) -> Value {
        let mut body = json!({
            "id": Uuid::new_v4().to_string(),
            "kind": "text",
            "meta": b64(&[1; 40]),
            "sealedKey": b64(&[2; 64]),
            "payload": b64(&[3; 60]),
            "deletionAt": self.deletion(),
        });
        merge(&mut body, with);
        body
    }

    fn file_body(&self, size: u64) -> Value {
        self.note_body(json!({"kind": "file", "file": {"size": size}}))
    }

    /// Makes a Send and returns its JSON; the call must work.
    async fn make(&self, body: Value) -> Value {
        let reply = self.call("POST", "/kem/v1/sends", Some(body)).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
        reply.json()
    }

    /// Makes a file Send and uploads `bytes` to it.
    async fn make_file(&self, bytes: &[u8], with: Value) -> Value {
        let mut body = self.file_body(bytes.len() as u64);
        merge(&mut body, with);
        let send = self.make(body).await;
        let id = send["id"].as_str().expect("an id").to_owned();
        let reply = self.upload(&id, bytes, Some(bytes.len() as u64)).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        reply.json()
    }

    /// `PUT`s the bytes with the given `Content-Length` header (none for `None`).
    async fn upload(&self, id: &str, bytes: &[u8], length: Option<u64>) -> Reply {
        let mut headers = vec![("content-type", "application/octet-stream".to_owned())];
        if let Some(length) = length {
            headers.push(("content-length", length.to_string()));
        }
        self.owner
            .send(
                "PUT",
                &format!("/kem/v1/sends/{id}/file"),
                Req {
                    headers,
                    raw_body: Some(bytes.to_vec()),
                    ..self.authed()
                },
            )
            .await
    }
}

/// Opens a Send as a recipient: no account, no DPoP, an optional password proof.
async fn open(client: &Client, access_id: &str, password: Option<&[u8]>) -> Reply {
    let body = password.map(|p| json!({"password": b64(p)}));
    client
        .send(
            "POST",
            &format!("/kem/v1/send-access/{access_id}"),
            Req {
                body,
                no_proof: true,
                ..Req::default()
            },
        )
        .await
}

async fn download(client: &Client, access_id: &str, password: Option<&[u8]>) -> Reply {
    let body = password.map(|p| json!({"password": b64(p)}));
    client
        .send(
            "POST",
            &format!("/kem/v1/send-access/{access_id}/file"),
            Req {
                body,
                no_proof: true,
                ..Req::default()
            },
        )
        .await
}

/// Adds the fields of `with` to `body`, replacing the ones it has.
fn merge(body: &mut Value, with: Value) {
    let (Some(target), Value::Object(fields)) = (body.as_object_mut(), with) else {
        return;
    };
    for (key, value) in fields {
        target.insert(key, value);
    }
}

// ---- the owner's routes ----

#[tokio::test]
async fn the_owners_routes_need_a_signed_in_device() {
    let rig = rig();
    let reply = rig.owner.send("GET", "/kem/v1/sends", Req::default()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "unauthorized");
    // Answers from the Send routes carry the DPoP nonce too.
    assert!(reply.header("dpop-nonce").is_some());
}

#[tokio::test]
async fn a_note_is_made_listed_read_changed_and_deleted() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({"maxAccess": 5}))).await;
    let id = made["id"].as_str().expect("an id").to_owned();
    assert_eq!(made["kind"], "text");
    assert_eq!(made["accessCount"], 0);
    assert_eq!(made["maxAccess"], 5);
    assert_eq!(made["hasPassword"], false);
    assert_eq!(made["file"], Value::Null);
    assert_eq!(made["accessId"].as_str().map(str::len), Some(22));
    assert_eq!(made["payload"], b64(&[3; 60]));
    assert!(made.get("uploadUrl").is_none());

    let list = rig.call("GET", "/kem/v1/sends", None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json().as_array().map(Vec::len), Some(1));
    assert_eq!(list.json()[0]["id"], made["id"]);

    let read = rig.call("GET", &format!("/kem/v1/sends/{id}"), None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["accessId"], made["accessId"]);

    let changed = rig
        .call(
            "PUT",
            &format!("/kem/v1/sends/{id}"),
            Some(json!({
                "meta": b64(&[9; 40]),
                "payload": b64(&[8; 30]),
                "maxAccess": 9,
                "hideEmail": true,
                "disabled": false,
                "deletionAt": rig.deletion(),
                "password": b64(&PROOF),
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.json());
    let changed = changed.json();
    assert_eq!(changed["maxAccess"], 9);
    assert_eq!(changed["hideEmail"], true);
    assert_eq!(changed["hasPassword"], true);
    assert_eq!(changed["payload"], b64(&[8; 30]));
    assert_eq!(changed["meta"], b64(&[9; 40]));
    assert_eq!(changed["sealedKey"], made["sealedKey"]);

    let deleted = rig
        .call("DELETE", &format!("/kem/v1/sends/{id}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = rig.call("GET", &format!("/kem/v1/sends/{id}"), None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(rig.sends.count(), 0);
}

#[tokio::test]
async fn removing_a_password_and_asking_for_both_is_refused() {
    let rig = Rig::signed_in().await;
    let made = rig
        .make(rig.note_body(json!({"password": b64(&PROOF)})))
        .await;
    assert_eq!(made["hasPassword"], true);
    let id = made["id"].as_str().expect("an id");
    let update = |extra: Value| {
        let mut body = json!({
            "meta": b64(&[9; 40]),
            "deletionAt": rig.deletion(),
        });
        merge(&mut body, extra);
        body
    };

    let both = rig
        .call(
            "PUT",
            &format!("/kem/v1/sends/{id}"),
            Some(update(
                json!({"password": b64(&PROOF), "removePassword": true}),
            )),
        )
        .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);

    let kept = rig
        .call(
            "PUT",
            &format!("/kem/v1/sends/{id}"),
            Some(update(json!({}))),
        )
        .await;
    assert_eq!(kept.json()["hasPassword"], true);
    let removed = rig
        .call(
            "PUT",
            &format!("/kem/v1/sends/{id}"),
            Some(update(json!({"removePassword": true}))),
        )
        .await;
    assert_eq!(removed.json()["hasPassword"], false);
}

#[tokio::test]
async fn bad_requests_are_400s() {
    let rig = Rig::signed_in().await;
    let bad = |with: Value| rig.note_body(with);
    for body in [
        bad(json!({"kind": "video"})),
        bad(json!({"meta": "not base64!"})),
        bad(json!({"deletionAt": rig.app.now() + 40 * 24 * 3600})),
        bad(json!({"deletionAt": rig.app.now() - 10})),
        bad(json!({"maxAccess": 0})),
        bad(json!({"password": "not base64!"})),
        bad(json!({"surprise": true})),
        bad(json!({"file": {"size": 10}})),
        rig.file_body(0),
    ] {
        let reply = rig.call("POST", "/kem/v1/sends", Some(body.clone())).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.content_type(), "application/problem+json");
    }
    assert_eq!(rig.sends.count(), 0);

    let not_a_uuid = rig.call("GET", "/kem/v1/sends/nope", None).await;
    assert_eq!(not_a_uuid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_client_chooses_the_id_and_a_taken_one_is_a_conflict() {
    let rig = Rig::signed_in().await;
    let id = Uuid::new_v4();
    let made = rig.make(rig.note_body(json!({"id": id.to_string()}))).await;
    assert_eq!(made["id"], id.to_string());
    // The link carries the same 16 bytes in base64url.
    assert_eq!(made["accessId"], b64(id.as_bytes()));

    let again = rig
        .call(
            "POST",
            "/kem/v1/sends",
            Some(rig.note_body(json!({"id": id.to_string()}))),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-exists");
    assert_eq!(rig.sends.count(), 1);
}

#[tokio::test]
async fn the_server_checks_the_lengths_and_shapes_it_can_see() {
    let rig = Rig::signed_in().await;
    let mut without_id = rig.note_body(json!({}));
    without_id.as_object_mut().expect("an object").remove("id");
    let v7 = Uuid::now_v7().to_string();
    for (what, body) in [
        ("no id", without_id),
        (
            "an id that is not a UUID",
            rig.note_body(json!({"id": "nope"})),
        ),
        ("a version 7 id", rig.note_body(json!({"id": v7}))),
        (
            "a meta under 28 bytes",
            rig.note_body(json!({"meta": b64(&[1; 27])})),
        ),
        (
            "a payload under 28 bytes",
            rig.note_body(json!({"payload": b64(&[1; 27])})),
        ),
        (
            "a sealed key of 63 bytes",
            rig.note_body(json!({"sealedKey": b64(&[1; 63])})),
        ),
        (
            "a sealed key of 65 bytes",
            rig.note_body(json!({"sealedKey": b64(&[1; 65])})),
        ),
        (
            "a proof of 31 bytes",
            rig.note_body(json!({"password": b64(&[1; 31])})),
        ),
        (
            "a proof of 33 bytes",
            rig.note_body(json!({"password": b64(&[1; 33])})),
        ),
        ("a file size that no chunks make", rig.file_body(27)),
        (
            "a file size with a short last chunk",
            rig.file_body(12 + 65_552 + 5),
        ),
    ] {
        let reply = rig.call("POST", "/kem/v1/sends", Some(body)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{what}");
        assert_eq!(reply.content_type(), "application/problem+json", "{what}");
    }
    assert_eq!(rig.sends.count(), 0);

    // The shortest sealed parts and a proof of exactly 32 bytes are fine.
    let made = rig
        .make(rig.note_body(json!({
            "meta": b64(&[1; 28]),
            "payload": b64(&[1; 28]),
            "password": b64(&PROOF),
        })))
        .await;
    assert_eq!(made["hasPassword"], true);

    // A change is held to the same lengths.
    let id = made["id"].as_str().expect("an id");
    for body in [
        json!({"meta": b64(&[1; 27]), "deletionAt": rig.deletion()}),
        json!({"meta": b64(&[1; 40]), "payload": b64(&[1; 27]), "deletionAt": rig.deletion()}),
        json!({"meta": b64(&[1; 40]), "password": b64(&[1; 31]), "deletionAt": rig.deletion()}),
    ] {
        let reply = rig
            .call("PUT", &format!("/kem/v1/sends/{id}"), Some(body.clone()))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn another_account_cannot_read_change_or_delete_a_send() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({}))).await;
    let id = made["id"].as_str().expect("an id");
    let (ann, session) = rig.stranger().await;
    let theirs = |body: Option<Value>| Req {
        access_token: Some(&session.access_token),
        body,
        ..Req::default()
    };

    let uri = format!("/kem/v1/sends/{id}");
    assert_eq!(
        ann.send("GET", &uri, theirs(None)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ann.send("DELETE", &uri, theirs(None)).await.status,
        StatusCode::NOT_FOUND
    );
    let update = json!({"meta": b64(&[9; 40]), "deletionAt": rig.deletion()});
    assert_eq!(
        ann.send("PUT", &uri, theirs(Some(update))).await.status,
        StatusCode::NOT_FOUND
    );
    let list = ann.send("GET", "/kem/v1/sends", theirs(None)).await;
    assert_eq!(list.json().as_array().map(Vec::len), Some(0));
    assert_eq!(rig.sends.count(), 1);
}

#[tokio::test]
async fn a_policy_that_removes_send_refuses_making_and_changing_but_not_deleting() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({}))).await;
    let id = made["id"].as_str().expect("an id").to_owned();
    rig.rules.set(SendRules {
        disabled: true,
        force_email: false,
    });

    let refused = rig
        .call("POST", "/kem/v1/sends", Some(rig.note_body(json!({}))))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.problem(), "send-policy");
    let changed = rig
        .call(
            "PUT",
            &format!("/kem/v1/sends/{id}"),
            Some(json!({"meta": b64(&[9; 40]), "deletionAt": rig.deletion()})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::FORBIDDEN);
    let deleted = rig
        .call("DELETE", &format!("/kem/v1/sends/{id}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn always_show_the_senders_email_refuses_hiding_it() {
    let rig = Rig::signed_in().await;
    rig.rules.set(SendRules {
        disabled: false,
        force_email: true,
    });
    let hiding = rig
        .call(
            "POST",
            "/kem/v1/sends",
            Some(rig.note_body(json!({"hideEmail": true}))),
        )
        .await;
    assert_eq!(hiding.status, StatusCode::FORBIDDEN);
    assert_eq!(hiding.problem(), "send-policy");
    let showing = rig
        .call("POST", "/kem/v1/sends", Some(rig.note_body(json!({}))))
        .await;
    assert_eq!(showing.status, StatusCode::CREATED);
}

// ---- opening a Send ----

#[tokio::test]
async fn anyone_with_the_link_opens_a_note_and_gets_ciphertext_only() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({}))).await;
    let access = made["accessId"].as_str().expect("an access id");
    let recipient = rig.recipient();

    let reply = open(&recipient, access, None).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.header("cache-control"), Some("private, no-store"));
    let opened = reply.json();
    assert_eq!(opened["id"], access);
    assert_eq!(opened["kind"], "text");
    assert_eq!(opened["payload"], b64(&[3; 60]));
    assert_eq!(opened["senderEmail"], "sam@example.org");
    assert_eq!(opened["deletionAt"], made["deletionAt"]);
    assert_eq!(opened["fileSize"], Value::Null);
    // Nothing the owner keeps sealed for themselves leaves.
    let text = reply.json().to_string();
    assert!(
        !text.contains(&b64(&[1; 40])),
        "the owner's name stays home"
    );
    assert!(!text.contains(&b64(&[2; 64])), "so does the sealed key");

    let owner_view = rig
        .call(
            "GET",
            &format!("/kem/v1/sends/{}", made["id"].as_str().expect("id")),
            None,
        )
        .await;
    assert_eq!(owner_view.json()["accessCount"], 1);
}

#[tokio::test]
async fn a_hidden_email_is_not_sent() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({"hideEmail": true}))).await;
    let reply = open(
        &rig.recipient(),
        made["accessId"].as_str().expect("an access id"),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["senderEmail"], Value::Null);
}

#[tokio::test]
async fn the_view_limit_makes_the_last_view_the_last() {
    let rig = Rig::signed_in().await;
    let made = rig.make(rig.note_body(json!({"maxAccess": 2}))).await;
    let access = made["accessId"].as_str().expect("an access id");
    let recipient = rig.recipient();
    assert_eq!(open(&recipient, access, None).await.status, StatusCode::OK);
    assert_eq!(open(&recipient, access, None).await.status, StatusCode::OK);
    let third = open(&recipient, access, None).await;
    assert_eq!(third.status, StatusCode::NOT_FOUND);
    assert_eq!(third.problem(), "not-found");
}

#[tokio::test]
async fn a_closed_or_unknown_send_is_the_same_404() {
    let rig = Rig::signed_in().await;
    let off = rig.make(rig.note_body(json!({"disabled": true}))).await;
    let expiring = rig
        .make(rig.note_body(json!({"expiresAt": rig.app.now() + 3600})))
        .await;
    let recipient = rig.recipient();

    let disabled = open(&recipient, off["accessId"].as_str().expect("id"), None).await;
    assert_eq!(disabled.status, StatusCode::NOT_FOUND);
    let unknown = open(&recipient, "AAAAAAAAAAAAAAAAAAAAAA", None).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let garbage = open(&recipient, "not-an-id", None).await;
    assert_eq!(garbage.status, StatusCode::NOT_FOUND);
    assert_eq!(disabled.json(), unknown.json());
    assert_eq!(unknown.json(), garbage.json());

    let access = expiring["accessId"].as_str().expect("id");
    assert_eq!(open(&recipient, access, None).await.status, StatusCode::OK);
    rig.app.clock.advance(time::Duration::hours(2));
    assert_eq!(
        open(&recipient, access, None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_password_is_asked_for_and_checked() {
    let rig = Rig::signed_in().await;
    let made = rig
        .make(rig.note_body(json!({"password": b64(&PROOF)})))
        .await;
    let access = made["accessId"].as_str().expect("an access id");
    let recipient = rig.recipient();

    let none = open(&recipient, access, None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.problem(), "send-password-required");
    assert!(none.header("www-authenticate").is_some());
    let wrong = open(&recipient, access, Some(b"another")).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.problem(), "send-wrong-password");

    let right = open(&recipient, access, Some(&PROOF)).await;
    assert_eq!(right.status, StatusCode::OK, "{:?}", right.json());
    assert_eq!(right.json()["payload"], b64(&[3; 60]));
    // Only the open counted a view.
    let owner_view = rig
        .call(
            "GET",
            &format!("/kem/v1/sends/{}", made["id"].as_str().expect("id")),
            None,
        )
        .await;
    assert_eq!(owner_view.json()["accessCount"], 1);
}

#[tokio::test]
async fn wrong_passwords_are_limited_per_send() {
    let rig = Rig::signed_in().await;
    let guarded = rig
        .make(rig.note_body(json!({"password": b64(&PROOF)})))
        .await;
    let other = rig
        .make(rig.note_body(json!({"password": b64(&PROOF)})))
        .await;
    let access = guarded["accessId"].as_str().expect("an access id");
    let recipient = rig.recipient();

    for n in 0..10 {
        let wrong = open(&recipient, access, Some(b"guess")).await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "try {n}");
    }
    // The eleventh in the minute is turned away, even with the right proof.
    let limited = open(&recipient, access, Some(&PROOF)).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.problem(), "rate-limited");
    assert!(limited.header("retry-after").is_some());

    // Another Send has its own count, and a request with no proof costs nothing.
    let other_access = other["accessId"].as_str().expect("an access id");
    assert_eq!(
        open(&recipient, other_access, Some(&PROOF)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        open(&recipient, access, None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

// ---- file Sends ----

#[tokio::test]
async fn a_file_send_is_closed_until_uploaded_and_then_streams() {
    let rig = Rig::signed_in().await;
    let bytes = kma1_file(70_000);
    let made = rig.make(rig.file_body(bytes.len() as u64)).await;
    let id = made["id"].as_str().expect("an id").to_owned();
    let access = made["accessId"].as_str().expect("an access id").to_owned();
    assert_eq!(made["kind"], "file");
    assert_eq!(made["file"], json!({"size": bytes.len(), "ready": false}));
    assert_eq!(
        made["uploadUrl"],
        format!("{DOMAIN}/kem/v1/sends/{id}/file")
    );
    let recipient = rig.recipient();
    assert_eq!(
        open(&recipient, &access, None).await.status,
        StatusCode::NOT_FOUND
    );

    let uploaded = rig.upload(&id, &bytes, Some(bytes.len() as u64)).await;
    assert_eq!(uploaded.status, StatusCode::OK, "{:?}", uploaded.json());
    assert_eq!(
        uploaded.json()["file"],
        json!({"size": bytes.len(), "ready": true})
    );

    let described = open(&recipient, &access, None).await;
    assert_eq!(described.status, StatusCode::OK);
    assert_eq!(described.json()["kind"], "file");
    assert_eq!(described.json()["fileSize"], bytes.len());

    let file = download(&recipient, &access, None).await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(file.content_type(), "application/octet-stream");
    assert_eq!(
        file.header("content-length"),
        Some(bytes.len().to_string().as_str())
    );
    assert_eq!(file.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(file.body, bytes);
}

#[tokio::test]
async fn an_upload_must_match_the_announced_size_and_be_kma1() {
    let rig = Rig::signed_in().await;
    let bytes = kma1_file(1000);
    let made = rig.make(rig.file_body(bytes.len() as u64)).await;
    let id = made["id"].as_str().expect("an id");

    let chunked = rig.upload(id, &bytes, None).await;
    assert_eq!(chunked.status, StatusCode::LENGTH_REQUIRED);
    let wrong_length = rig.upload(id, &bytes, Some(bytes.len() as u64 - 1)).await;
    assert_eq!(wrong_length.status, StatusCode::BAD_REQUEST);
    let short = rig
        .upload(id, &bytes[..100], Some(bytes.len() as u64))
        .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    let not_kma1 = vec![0x42u8; bytes.len()];
    let refused = rig.upload(id, &not_kma1, Some(bytes.len() as u64)).await;
    assert_eq!(refused.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(refused.problem(), "not-kma1");

    // None of that opened it; the real file does, once.
    let ok = rig.upload(id, &bytes, Some(bytes.len() as u64)).await;
    assert_eq!(ok.status, StatusCode::OK);
    let again = rig.upload(id, &bytes, Some(bytes.len() as u64)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-uploaded");
}

#[tokio::test]
async fn only_the_owner_uploads_and_a_note_takes_no_file() {
    let rig = Rig::signed_in().await;
    let bytes = kma1_file(500);
    let made = rig.make(rig.file_body(bytes.len() as u64)).await;
    let id = made["id"].as_str().expect("an id");
    let (ann, session) = rig.stranger().await;
    let stranger = ann
        .send(
            "PUT",
            &format!("/kem/v1/sends/{id}/file"),
            Req {
                access_token: Some(&session.access_token),
                headers: vec![("content-length", bytes.len().to_string())],
                raw_body: Some(bytes.clone()),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(stranger.status, StatusCode::NOT_FOUND);

    let note = rig.make(rig.note_body(json!({}))).await;
    let to_a_note = rig
        .upload(
            note["id"].as_str().expect("an id"),
            &bytes,
            Some(bytes.len() as u64),
        )
        .await;
    assert_eq!(to_a_note.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_file_over_the_limit_is_refused_with_the_limit() {
    let config = SendsConfig {
        limits: SendLimits {
            max_file_size: 1000,
        },
        ..SendsConfig::default()
    };
    let rig = Rig::signed_in_with(config).await;
    let reply = rig
        .call("POST", "/kem/v1/sends", Some(rig.file_body(1001)))
        .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "file-too-large");
    assert_eq!(reply.json()["maxSize"], 1000);
}

#[tokio::test]
async fn a_file_download_needs_the_password_and_counts_a_view() {
    let rig = Rig::signed_in().await;
    let bytes = kma1_file(2000);
    let made = rig
        .make_file(&bytes, json!({"password": b64(&PROOF), "maxAccess": 1}))
        .await;
    let access = made["accessId"].as_str().expect("an access id").to_owned();
    let recipient = rig.recipient();

    let none = download(&recipient, &access, None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.problem(), "send-password-required");
    let ok = download(&recipient, &access, Some(&PROOF)).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.body, bytes);
    // The one view is used.
    let again = download(&recipient, &access, Some(&PROOF)).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(
        open(&recipient, &access, Some(&PROOF)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn deleting_a_file_send_closes_its_link() {
    let rig = Rig::signed_in().await;
    let bytes = kma1_file(300);
    let made = rig.make_file(&bytes, json!({})).await;
    let id = made["id"].as_str().expect("an id");
    let access = made["accessId"].as_str().expect("an access id");
    let recipient = rig.recipient();
    assert_eq!(
        download(&recipient, access, None).await.status,
        StatusCode::OK
    );
    let deleted = rig
        .call("DELETE", &format!("/kem/v1/sends/{id}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        download(&recipient, access, None).await.status,
        StatusCode::NOT_FOUND
    );
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
async fn a_replica_refuses_a_send_with_a_view_limit_and_serves_one_without() {
    let rig = Rig::signed_in().await;
    let limited = rig.make(rig.note_body(json!({"maxAccess": 2}))).await;
    let open_one = rig.make(rig.note_body(json!({}))).await;
    let limited_file = rig
        .make_file(&kma1_file(100), json!({"maxAccess": 2}))
        .await;

    let view: kemlock_app::federation_view::SharedView = std::sync::Arc::new(ReplicaView);
    let router = rig.merged.clone().layer(axum::Extension(view));
    let recipient = Client::new(router, rig.app.clock.clone(), DpopSigner::es256());

    let refused = open(&recipient, limited["accessId"].as_str().expect("id"), None).await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE, "{:?}", refused.json());
    assert_eq!(refused.json()["home"], "https://nas.example.org");
    assert!(refused.json()["detail"].as_str().is_some_and(|d| d.contains("Try again")));
    let file = download(
        &recipient,
        limited_file["accessId"].as_str().expect("id"),
        None,
    )
    .await;
    assert_eq!(file.status, StatusCode::SERVICE_UNAVAILABLE);

    // A Send without a limit opens at the replica, and nothing was counted for the refused one.
    let served = open(&recipient, open_one["accessId"].as_str().expect("id"), None).await;
    assert_eq!(served.status, StatusCode::OK, "{:?}", served.json());
    let at_home = open(
        &rig.recipient(),
        limited["accessId"].as_str().expect("id"),
        None,
    )
    .await;
    assert_eq!(at_home.status, StatusCode::OK);
}
