//! Device approval, device sign-in, the trusted-device key copy and device sign-out, over HTTP
//! against the fakes, with real DPoP.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_domain::DeviceId;
use serde_json::{Value, json};

const EMAIL: &str = "sam@example.org";
const PHRASE_WORDS: usize = 5;
/// A `kx1` sealed box of a 64-byte root key: 1 + 1600 + 12 + 64 + 16 bytes.
const SEALED_LEN: usize = 1 + 1600 + 12 + 64 + 16;

fn sealed_box() -> String {
    b64(&[0x5b_u8; SEALED_LEN])
}

/// An app with signups on and `EMAIL` signed in on an open device.
async fn open_device() -> (App, Client, Session) {
    let app = App::new(true);
    let open = app.client();
    let session = register_and_sign_in(&open, EMAIL).await;
    (app, open, session)
}

async fn ask(new_device: &Client, email: &str) -> Reply {
    new_device
        .post(
            "/kem/v1/auth/device/request",
            json!({
                "email": email,
                "publicKey": b64(&[9u8; 1600]),
                "device": {"name": "Firefox on Linux", "kind": "kemlock-web"},
            }),
        )
        .await
}

async fn poll(new_device: &Client, id: &str) -> Value {
    let reply = new_device
        .get(&format!("/kem/v1/auth/device/request/{id}"))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    reply.json()
}

async fn answer(open: &Client, session: &Session, id: &str, body: Value) -> Reply {
    open.post_authed(
        &format!("/kem/v1/devices/approvals/{id}"),
        &session.access_token,
        body,
    )
    .await
}

async fn sign_in_as_approved(new_device: &Client, id: &str) -> Reply {
    let challenge = new_device
        .post("/kem/v1/auth/device/challenge", json!({"requestId": id}))
        .await;
    assert_eq!(challenge.status, StatusCode::OK, "{:?}", challenge.json());
    new_device
        .post(
            "/kem/v1/auth/device/verify",
            json!({"challenge": challenge.json()["challenge"]}),
        )
        .await
}

#[tokio::test]
async fn a_new_device_is_approved_by_an_open_one_and_signs_in() {
    let (app, open, session) = open_device().await;
    let new_device = app.client();

    let asked = ask(&new_device, EMAIL).await;
    assert_eq!(asked.status, StatusCode::CREATED, "{:?}", asked.json());
    let asked = asked.json();
    let id = asked["requestId"].as_str().expect("requestId").to_owned();
    let phrase = asked["phrase"].as_str().expect("phrase").to_owned();
    assert_eq!(phrase.split(' ').count(), PHRASE_WORDS);
    assert!(asked["expiresAt"].as_str().is_some());

    // The open device sees it, with the phrase, a truncated address and an age.
    let listed = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.json());
    let listed = listed.json();
    let entries = listed["approvals"].as_array().expect("approvals");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], id);
    assert_eq!(entries[0]["phrase"], phrase);
    assert_eq!(
        entries[0]["publicKey"],
        b64(&[9u8; 1600]),
        "the open device gets the one-time key, to work the phrase out and seal the root key to"
    );
    assert_eq!(entries[0]["ip"], "0.0.0.0/24");
    assert_eq!(entries[0]["deviceName"], "Firefox on Linux");
    assert_eq!(entries[0]["deviceKind"], "kemlock-web");
    assert_eq!(entries[0]["ageSeconds"], 0);

    assert_eq!(poll(&new_device, &id).await["status"], "pending");

    // The open device approves with the root key sealed to the new device's key.
    let approved = answer(
        &open,
        &session,
        &id,
        json!({"decision": "approve", "sealedKey": sealed_box()}),
    )
    .await;
    assert_eq!(approved.status, StatusCode::NO_CONTENT);

    let polled = poll(&new_device, &id).await;
    assert_eq!(polled["status"], "approved");
    assert_eq!(polled["sealedKey"], sealed_box());
    assert_eq!(
        polled["accountId"], session.user_id,
        "the new device needs the account id to rebuild the sealed box's aad"
    );

    // It's no longer pending on the open device.
    let relisted = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await
        .json();
    assert_eq!(relisted["approvals"], json!([]));

    // The new device signs in with the key it asked with.
    let signed = sign_in_as_approved(&new_device, &id).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let tokens = Session::from_tokens(&signed.json());
    assert_eq!(tokens.user_id, session.user_id);
    assert_ne!(tokens.device_id, session.device_id);
    let me = new_device
        .get_authed("/kem/v1/devices/key-copy", &tokens.access_token)
        .await;
    assert_eq!(me.status, StatusCode::NOT_FOUND, "signed in, no copy yet");
    assert_eq!(poll(&new_device, &id).await["status"], "used");

    // The approval is used up.
    let again = new_device
        .post("/kem/v1/auth/device/challenge", json!({"requestId": id}))
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_denial_gives_no_key_and_no_sign_in() {
    let (app, open, session) = open_device().await;
    let new_device = app.client();
    let id = ask(&new_device, EMAIL).await.json()["requestId"]
        .as_str()
        .expect("requestId")
        .to_owned();

    let denied = answer(&open, &session, &id, json!({"decision": "deny"})).await;
    assert_eq!(denied.status, StatusCode::NO_CONTENT);

    let polled = poll(&new_device, &id).await;
    assert_eq!(polled["status"], "denied");
    assert!(polled["sealedKey"].is_null());
    assert!(
        polled.get("accountId").is_none(),
        "only an approval names the account"
    );
    let challenge = new_device
        .post("/kem/v1/auth/device/challenge", json!({"requestId": id}))
        .await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenge.problem(), "unauthorized");
}

#[tokio::test]
async fn only_the_key_that_asked_can_read_or_use_the_answer() {
    let (app, open, session) = open_device().await;
    let new_device = app.client();
    let thief = app.client();
    let id = ask(&new_device, EMAIL).await.json()["requestId"]
        .as_str()
        .expect("requestId")
        .to_owned();
    answer(
        &open,
        &session,
        &id,
        json!({"decision": "approve", "sealedKey": sealed_box()}),
    )
    .await;

    // Another key learns nothing from polling.
    let stolen = poll(&thief, &id).await;
    assert_eq!(stolen["status"], "pending");
    assert!(stolen["sealedKey"].is_null());
    assert!(stolen.get("accountId").is_none());
    // And can't get a challenge.
    let challenge = thief
        .post("/kem/v1/auth/device/challenge", json!({"requestId": id}))
        .await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
    // A challenge made for the right key is useless to the other one.
    let mine = new_device
        .post("/kem/v1/auth/device/challenge", json!({"requestId": id}))
        .await
        .json();
    let replay = thief
        .post(
            "/kem/v1/auth/device/verify",
            json!({"challenge": mine["challenge"]}),
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    // The owner still can.
    let signed = new_device
        .post(
            "/kem/v1/auth/device/verify",
            json!({"challenge": mine["challenge"]}),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}

#[tokio::test]
async fn an_unknown_email_gets_the_same_answer_and_shows_nowhere() {
    let (app, open, session) = open_device().await;
    let new_device = app.client();

    let asked = ask(&new_device, "nobody@example.org").await;
    assert_eq!(asked.status, StatusCode::CREATED);
    assert!(asked.json()["phrase"].as_str().is_some());

    let listed = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await
        .json();
    assert_eq!(listed["approvals"], json!([]));
}

#[tokio::test]
async fn an_account_takes_ten_requests_an_hour() {
    let (app, _open, _session) = open_device().await;
    let new_device = app.client();
    for _ in 0..10 {
        assert_eq!(ask(&new_device, EMAIL).await.status, StatusCode::CREATED);
    }
    let refused = ask(&new_device, EMAIL).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.problem(), "rate-limited");
    assert!(refused.header("retry-after").is_some());
}

#[tokio::test]
async fn requests_expire_after_fifteen_minutes() {
    let (app, open, _session) = open_device().await;
    let new_device = app.client();
    let id = ask(&new_device, EMAIL).await.json()["requestId"]
        .as_str()
        .expect("requestId")
        .to_owned();

    app.clock.advance(time::Duration::minutes(14));
    // The access token has run out by now (it lives 10 minutes); sign in again to look.
    let session = {
        let signed = sign_in_reply(&open, EMAIL, test_device()).await;
        assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
        Session::from_tokens(&signed.json()["tokens"])
    };
    let listed = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await
        .json();
    assert_eq!(listed["approvals"].as_array().map(Vec::len), Some(1));

    app.clock.advance(time::Duration::minutes(2));
    let session = {
        let signed = sign_in_reply(&open, EMAIL, test_device()).await;
        Session::from_tokens(&signed.json()["tokens"])
    };
    let listed = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await
        .json();
    assert_eq!(listed["approvals"], json!([]));
    assert_eq!(poll(&new_device, &id).await["status"], "expired");
    let late = answer(
        &open,
        &session,
        &id,
        json!({"decision": "approve", "sealedKey": sealed_box()}),
    )
    .await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_requests_and_answers_are_refused() {
    let (app, open, session) = open_device().await;
    let new_device = app.client();

    let short_key = new_device
        .post(
            "/kem/v1/auth/device/request",
            json!({"email": EMAIL, "publicKey": b64(&[1u8; 10]), "device": {"name": "x"}}),
        )
        .await;
    assert_eq!(short_key.status, StatusCode::BAD_REQUEST);
    assert_eq!(short_key.problem(), "invalid-request");
    let padded = new_device
        .post(
            "/kem/v1/auth/device/request",
            json!({"email": EMAIL, "publicKey": "AAAA====", "device": {"name": "x"}}),
        )
        .await;
    assert_eq!(padded.status, StatusCode::BAD_REQUEST);

    let id = ask(&new_device, EMAIL).await.json()["requestId"]
        .as_str()
        .expect("requestId")
        .to_owned();
    for body in [
        json!({"decision": "approve"}),
        json!({"decision": "deny", "sealedKey": sealed_box()}),
        json!({"decision": "maybe"}),
        json!({"decision": "approve", "sealedKey": b64(&[1u8; 40])}),
    ] {
        let reply = answer(&open, &session, &id, body.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    let bad_id = answer(&open, &session, "not-a-uuid", json!({"decision": "deny"})).await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
    // Nothing above answered it.
    assert_eq!(poll(&new_device, &id).await["status"], "pending");
}

#[tokio::test]
async fn approvals_need_a_signed_in_device_of_the_same_account() {
    let (app, open, _session) = open_device().await;
    let new_device = app.client();
    let id = ask(&new_device, EMAIL).await.json()["requestId"]
        .as_str()
        .expect("requestId")
        .to_owned();

    let no_token = open.get("/kem/v1/devices/approvals").await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);

    // Another account can't see or answer it.
    let stranger_client = app.client();
    let stranger = register_and_sign_in(&stranger_client, "kim@example.org").await;
    let listed = stranger_client
        .get_authed("/kem/v1/devices/approvals", &stranger.access_token)
        .await
        .json();
    assert_eq!(listed["approvals"], json!([]));
    let reply = answer(
        &stranger_client,
        &stranger,
        &id,
        json!({"decision": "approve", "sealedKey": sealed_box()}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(poll(&new_device, &id).await["status"], "pending");
}

#[tokio::test]
async fn a_device_keeps_and_fetches_its_wrapped_copy() {
    let (_app, open, session) = open_device().await;
    let token = &session.access_token;

    let none = open.get_authed("/kem/v1/devices/key-copy", token).await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);

    let put = open
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(token),
                body: Some(json!({
                    "wrappedKey": b64(&[0xc3u8; 92]),
                    "protection": "secure-enclave",
                })),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    assert_eq!(put.json()["deviceId"], session.device_id);

    let got = open.get_authed("/kem/v1/devices/key-copy", token).await;
    assert_eq!(got.status, StatusCode::OK);
    let got = got.json();
    assert_eq!(got["wrappedKey"], b64(&[0xc3u8; 92]));
    assert_eq!(got["protection"], "secure-enclave");

    let bad = open
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(token),
                body: Some(json!({"wrappedKey": b64(&[]), "protection": "software"})),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let unknown = open
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(token),
                body: Some(json!({"wrappedKey": b64(&[1u8; 8]), "protection": "tpm"})),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);

    let removed = open
        .send(
            "DELETE",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let gone = open.get_authed("/kem/v1/devices/key-copy", token).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signing_a_device_out_deletes_its_tokens_and_its_copy() {
    let (app, open, session) = open_device().await;
    let other = app.client();
    let other_session = {
        let signed = sign_in_reply(&other, EMAIL, test_device()).await;
        assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
        Session::from_tokens(&signed.json()["tokens"])
    };
    let put = other
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(&other_session.access_token),
                body: Some(json!({
                    "wrappedKey": b64(&[0xc3u8; 92]),
                    "protection": "keystore",
                })),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    let other_id: DeviceId = other_session.device_id.parse().expect("a device id");
    assert!(app.store.key_copy_of(other_id).is_some());

    let out = open
        .post_authed(
            "/kem/v1/devices/sign-out",
            &session.access_token,
            json!({"deviceId": other_session.device_id}),
        )
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT, "{:?}", out.body);

    assert!(app.store.key_copy_of(other_id).is_none());
    // Its access token has not run out and carries the account's stamp, and opens nothing now.
    let used = other
        .get_authed("/kem/v1/devices/key-copy", &other_session.access_token)
        .await;
    assert_eq!(used.status, StatusCode::UNAUTHORIZED, "{:?}", used.json());
    let refreshed = other
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": other_session.refresh_token}),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);
    // The device that signed it out is untouched, and a device that isn't there is a 404.
    let again = open
        .post_authed(
            "/kem/v1/devices/sign-out",
            &session.access_token,
            json!({"deviceId": other_session.device_id}),
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn one_device_stops_trusting_another_and_the_list_says_since_when() {
    let (app, open, session) = open_device().await;
    let other = app.client();
    let other_session = {
        let signed = sign_in_reply(&other, EMAIL, test_device()).await;
        assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
        Session::from_tokens(&signed.json()["tokens"])
    };
    let put = other
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(&other_session.access_token),
                body: Some(json!({
                    "wrappedKey": b64(&[0xc3u8; 92]),
                    "protection": "keystore",
                })),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    let other_id: DeviceId = other_session.device_id.parse().expect("a device id");

    // The list names the device as trusted, and since when its copy was made.
    let listed = open
        .get_authed("/kem/v1/devices", &session.access_token)
        .await
        .json();
    let entry = |list: &Value, id: &str| {
        list["devices"]
            .as_array()
            .expect("a list")
            .iter()
            .find(|d| d["id"] == id)
            .expect("listed")
            .clone()
    };
    let trusted = entry(&listed, &other_session.device_id);
    assert_eq!(trusted["trusted"], true);
    assert_eq!(trusted["trustedSince"], put.json()["createdAt"]);
    let mine = entry(&listed, &session.device_id);
    assert_eq!(mine["trusted"], false);
    assert!(mine["trustedSince"].is_null());

    // Another device of the account takes the copy away; the session goes on.
    let uri = format!("/kem/v1/devices/{}/key-copy", other_session.device_id);
    let removed = open
        .send(
            "DELETE",
            &uri,
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    assert!(app.store.key_copy_of(other_id).is_none());
    let refreshed = other
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": other_session.refresh_token}),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.json());
    let after = open
        .get_authed("/kem/v1/devices", &session.access_token)
        .await
        .json();
    let untrusted = entry(&after, &other_session.device_id);
    assert_eq!(untrusted["trusted"], false);
    assert!(untrusted["trustedSince"].is_null());
    assert!(
        app.store
            .events()
            .iter()
            .any(|e| e.action == "device.untrust")
    );

    // Nothing to take away is fine; a device that isn't there, or isn't an id, is refused.
    let again = open
        .send(
            "DELETE",
            &uri,
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    for (target, status) in [
        (DeviceId::random().to_string(), StatusCode::NOT_FOUND),
        ("not-a-uuid".to_owned(), StatusCode::BAD_REQUEST),
    ] {
        let reply = open
            .send(
                "DELETE",
                &format!("/kem/v1/devices/{target}/key-copy"),
                Req {
                    access_token: Some(&session.access_token),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.status, status, "{target}");
    }
}

#[tokio::test]
async fn a_device_of_another_account_can_not_be_untrusted() {
    let (app, open, session) = open_device().await;
    let stranger = app.client();
    let stranger_session = register_and_sign_in(&stranger, "kim@example.org").await;
    let stranger_id: DeviceId = stranger_session.device_id.parse().expect("a device id");
    let put = stranger
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(&stranger_session.access_token),
                body: Some(json!({"wrappedKey": b64(&[0xc3u8; 92]), "protection": "keystore"})),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());

    let reply = open
        .send(
            "DELETE",
            &format!("/kem/v1/devices/{}/key-copy", stranger_session.device_id),
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(app.store.key_copy_of(stranger_id).is_some());
    let anonymous = open
        .send(
            "DELETE",
            &format!("/kem/v1/devices/{}/key-copy", stranger_session.device_id),
            Req::default(),
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_openapi_document_names_the_new_routes() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    for (path, method) in [
        ("/kem/v1/auth/device/request", "post"),
        ("/kem/v1/auth/device/request/{id}", "get"),
        ("/kem/v1/auth/device/challenge", "post"),
        ("/kem/v1/auth/device/verify", "post"),
        ("/kem/v1/devices/approvals", "get"),
        ("/kem/v1/devices/approvals/{id}", "post"),
        ("/kem/v1/devices/key-copy", "get"),
        ("/kem/v1/devices/key-copy", "put"),
        ("/kem/v1/devices/key-copy", "delete"),
        ("/kem/v1/devices/{id}/key-copy", "delete"),
        ("/kem/v1/devices/sign-out", "post"),
        ("/kem/v1/emergency", "get"),
        ("/kem/v1/emergency/grants", "post"),
        ("/kem/v1/emergency/grants/{id}", "delete"),
        ("/kem/v1/emergency/grants/{id}/accept", "post"),
        ("/kem/v1/emergency/grants/{id}/confirm", "post"),
        ("/kem/v1/emergency/grants/{id}/initiate", "post"),
        ("/kem/v1/emergency/grants/{id}/approve", "post"),
        ("/kem/v1/emergency/grants/{id}/reject", "post"),
        ("/kem/v1/emergency/grants/{id}/key", "get"),
    ] {
        assert!(
            json["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
    // The first slice's routes are still there.
    assert!(json["paths"]["/kem/v1/sync"]["get"].is_object());
    assert!(json["components"]["schemas"]["ApprovalRequestBody"].is_object());
}

// ---------------------------------------------------------------------------------------------
// the browser extension's device kind and key protection

#[tokio::test]
async fn the_extension_is_a_device_of_its_own_kind_named_for_its_browser() {
    let (app, open, session) = open_device().await;
    for (device_type, browser) in [(2, "Chrome"), (3, "Firefox"), (5, "Edge")] {
        let asked = app
            .client()
            .post(
                "/kem/v1/auth/device/request",
                json!({
                    "email": EMAIL,
                    "publicKey": b64(&[9u8; 1600]),
                    "device": {"name": "Kemlock", "kind": "kemlock-browser", "deviceType": device_type},
                }),
            )
            .await;
        assert_eq!(asked.status, StatusCode::CREATED, "{:?}", asked.json());
        let listed = open
            .get_authed("/kem/v1/devices/approvals", &session.access_token)
            .await
            .json();
        let entry = listed["approvals"]
            .as_array()
            .expect("approvals")
            .iter()
            .find(|e| e["id"] == asked.json()["requestId"])
            .expect("the request is listed")
            .clone();
        assert_eq!(entry["deviceKind"], "kemlock-browser");
        assert_eq!(entry["deviceName"], format!("Kemlock, {browser}"));
    }
}

#[tokio::test]
async fn the_browser_is_not_added_twice_to_a_name_that_has_it() {
    let (app, open, session) = open_device().await;
    let asked = app
        .client()
        .post(
            "/kem/v1/auth/device/request",
            json!({
                "email": EMAIL,
                "publicKey": b64(&[9u8; 1600]),
                "device": {"name": "Kemlock for browsers, firefox", "kind": "kemlock-browser", "deviceType": 3},
            }),
        )
        .await;
    assert_eq!(asked.status, StatusCode::CREATED);
    let listed = open
        .get_authed("/kem/v1/devices/approvals", &session.access_token)
        .await
        .json();
    assert_eq!(
        listed["approvals"][0]["deviceName"],
        "Kemlock for browsers, firefox"
    );
}

#[tokio::test]
async fn a_device_type_goes_only_with_the_browser_kind_and_a_browser_number() {
    let (app, _open, _session) = open_device().await;
    for device in [
        json!({"name": "Web", "kind": "kemlock-web", "deviceType": 2}),
        json!({"name": "Anything", "deviceType": 3}),
        json!({"name": "Kemlock", "kind": "kemlock-browser", "deviceType": 4}),
        json!({"name": "Kemlock", "kind": "kemlock-browser", "deviceType": 0}),
        json!({"name": "Kemlock", "kind": "kemlock-browser", "deviceType": 9}),
    ] {
        let reply = app
            .client()
            .post(
                "/kem/v1/auth/device/request",
                json!({"email": EMAIL, "publicKey": b64(&[9u8; 1600]), "device": device}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{device}");
    }
}

#[tokio::test]
async fn the_browser_protection_is_kept_and_shown_back() {
    let (_app, open, session) = open_device().await;
    let token = &session.access_token;
    let put = open
        .send(
            "PUT",
            "/kem/v1/devices/key-copy",
            Req {
                access_token: Some(token),
                body: Some(json!({"wrappedKey": b64(&[0xc4u8; 93]), "protection": "browser"})),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    let got = open.get_authed("/kem/v1/devices/key-copy", token).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.json()["protection"], "browser");
    assert_eq!(got.json()["wrappedKey"], b64(&[0xc4u8; 93]));
}
