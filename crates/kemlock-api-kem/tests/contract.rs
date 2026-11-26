//! What the app's sync client needs beyond items: signed manifests, the device list, one device
//! on both APIs, the one-time move to OPAQUE, the account's keys and tombstone times, over HTTP
//! against the fakes with real OPAQUE, DPoP and `sig1`.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_app::api_use::ApiUseRepo;
use kemlock_app::bitwarden::BwAccount;
use kemlock_app::ports::Clock;
use kemlock_app::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_crypto::bundle::Bundle;
use kemlock_crypto::manifest::{Entry, Manifest};
use kemlock_crypto::owner::Owner as CryptoOwner;
use kemlock_crypto::{kx1, sig1};
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::{AccountMode, UserId};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const EMAIL: &str = "sam@example.org";
const BW_HASH: &str = "the-bitwarden-master-password-hash";

async fn signed_in() -> (App, Client, Session) {
    let app = App::new(true);
    let client = app.client();
    let session = register_and_sign_in(&client, EMAIL).await;
    (app, client, session)
}

fn user_id(session: &Session) -> UserId {
    session.user_id.parse().expect("a user id")
}

async fn authed(
    client: &Client,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> Reply {
    client
        .send(
            method,
            uri,
            Req {
                access_token: Some(token),
                body,
                ..Req::default()
            },
        )
        .await
}

// ---------------------------------------------------------------------------------------------
// Signed manifests.

/// Gives the account a real bundle for `key`, as a client that made its keys would have
/// registered: the filler bundle the fakes register with can't verify a signature.
fn publish_bundle(app: &App, user: UserId, key: &sig1::SigningKey) {
    let bundle = Bundle {
        account_id: *user.as_bytes(),
        key_version: 1,
        kx1_public: kx1::PublicKey::from_bytes(&[7; kx1::PUBLIC_KEY_LEN]).expect("a 1600-byte key"),
        sig1_public: key.public_key().expect("the public key derives"),
    };
    let mut stored = app.store.user(user).expect("the account");
    stored.public_bundle = bundle.to_bytes();
    app.store.put_user(stored);
}

fn signed_manifest(user: UserId, key: &sig1::SigningKey, counter: u64) -> Value {
    let manifest = Manifest {
        owner: CryptoOwner::user(*user.as_bytes()),
        counter,
        entries: vec![
            Entry::live([2; 16], 3, b"cipher two"),
            Entry::tombstone([1; 16], 5),
        ],
    };
    json!({
        "manifest": b64(&manifest.to_bytes().expect("encodes")),
        "signature": b64(&manifest.sign(key).expect("signs")),
    })
}

fn manifest_uri(user: UserId) -> String {
    format!("/kem/v1/manifests/user:{user}")
}

#[tokio::test]
async fn a_signed_manifest_is_stored_and_the_latest_is_read_back() {
    let (app, client, session) = signed_in().await;
    let user = user_id(&session);
    let key = sig1::SigningKey::generate();
    publish_bundle(&app, user, &key);

    let missing = authed(
        &client,
        "GET",
        &manifest_uri(user),
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let body = signed_manifest(user, &key, 7);
    let put = authed(
        &client,
        "PUT",
        &manifest_uri(user),
        &session.access_token,
        Some(body.clone()),
    )
    .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    let stored = put.json();
    assert_eq!(stored["owner"], format!("user:{user}"));
    assert_eq!(stored["counter"], 7);
    assert_eq!(stored["manifest"], body["manifest"]);
    assert_eq!(stored["signature"], body["signature"]);
    assert_eq!(stored["signer"], session.user_id);

    let got = authed(
        &client,
        "GET",
        &manifest_uri(user),
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.json(), stored);

    let newer = signed_manifest(user, &key, 8);
    let put = authed(
        &client,
        "PUT",
        &manifest_uri(user),
        &session.access_token,
        Some(newer.clone()),
    )
    .await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    let got = authed(
        &client,
        "GET",
        &manifest_uri(user),
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(got.json()["counter"], 8);
    assert_eq!(got.json()["manifest"], newer["manifest"]);
}

#[tokio::test]
async fn a_counter_not_above_the_stored_one_is_a_409_naming_it() {
    let (app, client, session) = signed_in().await;
    let user = user_id(&session);
    let key = sig1::SigningKey::generate();
    publish_bundle(&app, user, &key);
    for counter in [5u64, 5, 4] {
        let reply = authed(
            &client,
            "PUT",
            &manifest_uri(user),
            &session.access_token,
            Some(signed_manifest(user, &key, counter)),
        )
        .await;
        if counter == 5 && reply.status == StatusCode::OK {
            continue;
        }
        assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.json());
        assert_eq!(reply.problem(), "stale-manifest");
        assert_eq!(reply.json()["currentCounter"], 5);
    }
}

#[tokio::test]
async fn a_signature_by_another_key_or_over_other_bytes_is_refused() {
    let (app, client, session) = signed_in().await;
    let user = user_id(&session);
    let key = sig1::SigningKey::generate();
    publish_bundle(&app, user, &key);

    let stranger = sig1::SigningKey::generate();
    let forged = authed(
        &client,
        "PUT",
        &manifest_uri(user),
        &session.access_token,
        Some(signed_manifest(user, &stranger, 1)),
    )
    .await;
    assert_eq!(
        forged.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        forged.json()
    );
    assert_eq!(forged.problem(), "invalid-request");

    // The signature of counter 1 over the bytes of counter 2.
    let one = signed_manifest(user, &key, 1);
    let two = signed_manifest(user, &key, 2);
    let spliced = json!({"manifest": two["manifest"], "signature": one["signature"]});
    let reply = authed(
        &client,
        "PUT",
        &manifest_uri(user),
        &session.access_token,
        Some(spliced),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    let not_base64 = json!({"manifest": "not base64!", "signature": "AAAA"});
    let reply = authed(
        &client,
        "PUT",
        &manifest_uri(user),
        &session.access_token,
        Some(not_base64),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    let nothing = authed(
        &client,
        "GET",
        &manifest_uri(user),
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(nothing.status, StatusCode::NOT_FOUND, "nothing was stored");
}

#[tokio::test]
async fn manifests_are_for_their_owner_and_need_a_token() {
    let (app, client, session) = signed_in().await;
    let user = user_id(&session);
    let key = sig1::SigningKey::generate();
    publish_bundle(&app, user, &key);

    let other = UserId::random();
    let reply = authed(
        &client,
        "PUT",
        &manifest_uri(other),
        &session.access_token,
        Some(signed_manifest(other, &key, 1)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = authed(
        &client,
        "GET",
        &manifest_uri(other),
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let bad_owner = authed(
        &client,
        "GET",
        "/kem/v1/manifests/nobody",
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(bad_owner.status, StatusCode::BAD_REQUEST);

    let anonymous = client.get(&manifest_uri(user)).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// The device list.

fn kemlock_device(name: &str, identifier: Option<&str>) -> Value {
    let mut device = json!({"name": name, "kind": "kemlock-android"});
    if let Some(identifier) = identifier {
        device["bitwardenDeviceIdentifier"] = json!(identifier);
    }
    device
}

async fn sign_in_session(client: &Client, device: Value) -> Session {
    let reply = sign_in_reply(client, EMAIL, device).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    Session::from_tokens(&reply.json()["tokens"])
}

#[tokio::test]
async fn the_device_list_names_each_device_and_each_apis_last_use() {
    let (app, phone, phone_session) = signed_in().await;
    app.clock.advance(Duration::minutes(1));
    let browser = app.client();
    let browser_session = sign_in_session(
        &browser,
        json!({"name": "Firefox on Linux", "kind": "bitwarden"}),
    )
    .await;

    // The browser only talks to the Bitwarden API, two minutes later.
    app.clock.advance(Duration::minutes(2));
    let bitwarden_use = app.clock.now();
    let browser_id = browser_session.device_id.parse().expect("a device id");
    app.store
        .record_use(
            kemlock_domain::DeviceId(browser_id),
            ApiKind::Bitwarden,
            bitwarden_use,
        )
        .await
        .expect("records");

    let reply = authed(
        &phone,
        "GET",
        "/kem/v1/devices",
        &phone_session.access_token,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let devices = reply.json()["devices"].as_array().expect("a list").clone();
    assert_eq!(devices.len(), 2);

    // Most recently seen first.
    let seen = |d: &Value| {
        OffsetDateTime::parse(d["lastSeenAt"].as_str().expect("a time"), &Rfc3339)
            .expect("RFC 3339")
    };
    assert!(seen(&devices[0]) >= seen(&devices[1]));
    let find = |id: &str| {
        devices
            .iter()
            .find(|d| d["id"] == id)
            .expect("the device is listed")
    };
    let first = find(&browser_session.device_id);
    assert_eq!(first["id"], browser_session.device_id);
    assert_eq!(first["name"], "Firefox on Linux");
    assert_eq!(first["kind"], "bitwarden");
    assert_eq!(first["current"], false);
    assert_eq!(first["trusted"], false);
    assert!(first["trustedSince"].is_null());
    assert!(first.get("lastKemlockUseAt").is_some_and(Value::is_null));
    let used = OffsetDateTime::parse(
        first["lastBitwardenUseAt"].as_str().expect("a time"),
        &Rfc3339,
    )
    .expect("RFC 3339");
    assert_eq!(used, bitwarden_use);
    assert!(first["createdAt"].is_string());

    let second = find(&phone_session.device_id);
    assert_eq!(second["id"], phone_session.device_id);
    assert_eq!(second["name"], "Test device");
    assert_eq!(second["kind"], "kemlock-cli");
    assert_eq!(second["current"], true);
    assert!(
        second["lastKemlockUseAt"].is_string(),
        "the list request itself is a use of the Kemlock API"
    );
    assert!(second["lastBitwardenUseAt"].is_null());
    assert!(second["lastSeenAt"].is_string());
}

#[tokio::test]
async fn the_device_list_shows_devices_that_only_ever_used_the_bitwarden_api() {
    use kemlock_app::ports::DeviceRepo;
    use kemlock_domain::{Device, DeviceId, DeviceKind};
    let (app, phone, session) = signed_in().await;
    let user = user_id(&session);
    // The access token lasts ten minutes, so the clock stays well inside that.
    app.clock.advance(Duration::minutes(3));

    // What the Bitwarden API leaves behind on a sign-in: a device with no DPoP key and a use of
    // its own API. A second one signed in before uses were recorded, so it has no use row.
    let make = |name: &str| Device {
        id: DeviceId::random(),
        user,
        name: name.to_owned(),
        kind: DeviceKind::Bitwarden,
        dpop_jkt: None,
        created_at: app.clock.now(),
        last_seen_at: app.clock.now(),
    };
    let recorded = make("Vaultwarden phone");
    let older = make("Old Vaultwarden phone");
    for device in [&recorded, &older] {
        DeviceRepo::upsert(&app.store, device)
            .await
            .expect("stored");
    }
    app.clock.advance(Duration::minutes(2));
    let bitwarden_use = app.clock.now();
    app.store
        .record_use(recorded.id, ApiKind::Bitwarden, bitwarden_use)
        .await
        .expect("records");

    let reply = authed(
        &phone,
        "GET",
        "/kem/v1/devices",
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let devices = reply.json()["devices"].as_array().expect("a list").clone();
    assert_eq!(devices.len(), 3);
    let find = |id: DeviceId| {
        devices
            .iter()
            .find(|d| d["id"] == id.0.to_string())
            .expect("the device is listed")
    };
    let time = |value: &Value| {
        OffsetDateTime::parse(value.as_str().expect("a time"), &Rfc3339).expect("RFC 3339")
    };
    let first = find(recorded.id);
    assert_eq!(first["name"], "Vaultwarden phone");
    assert_eq!(first["kind"], "bitwarden");
    assert_eq!(time(&first["lastBitwardenUseAt"]), bitwarden_use);
    assert!(first["lastKemlockUseAt"].is_null());
    let second = find(older.id);
    assert_eq!(time(&second["lastBitwardenUseAt"]), older.last_seen_at);
    assert!(second["lastKemlockUseAt"].is_null());
    // The device that asked used the Kemlock API only.
    let own = find(DeviceId(session.device_id.parse().expect("a device id")));
    assert!(own["lastBitwardenUseAt"].is_null());
}

#[tokio::test]
async fn each_request_on_the_kemlock_api_records_a_use_of_it() {
    let (app, client, session) = signed_in().await;
    let device = kemlock_domain::DeviceId(session.device_id.parse().expect("a device id"));
    assert_eq!(app.store.use_of(device), None, "sign-in is not a request");

    let first = app.clock.now();
    let reply = authed(&client, "GET", "/kem/v1/sync", &session.access_token, None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        app.store.use_of(device).expect("a row").kemlock,
        Some(first)
    );

    app.clock.advance(Duration::minutes(5));
    let reply = authed(&client, "GET", "/kem/v1/sync", &session.access_token, None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        app.store.use_of(device).expect("a row").kemlock,
        Some(app.clock.now())
    );
    assert_eq!(app.store.use_of(device).expect("a row").bitwarden, None);
}

#[tokio::test]
async fn the_device_list_needs_a_token() {
    let (_app, client, _session) = signed_in().await;
    let reply = client.get("/kem/v1/devices").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// One device on both APIs.

/// The Bitwarden API's formula, written out again.
fn bitwarden_id(user: UserId, identifier: &str) -> String {
    let mut input = b"kemlock/bitwarden/device".to_vec();
    input.extend_from_slice(user.as_bytes());
    input.extend_from_slice(identifier.as_bytes());
    let digest = kemlock_crypto::hash::sha256(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

#[tokio::test]
async fn signing_in_with_the_vaultwarden_identifier_is_the_bitwarden_apis_device() {
    let app = App::new(true);
    let client = app.client();
    let (reply, user) = register(&client, EMAIL, None).await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let identifier = "6c1a1d3e-6d5c-4f3e-9d0e-0a0a0a0a0a0a";
    let session = sign_in_session(
        &client,
        kemlock_device("Kemlock on Pixel", Some(identifier)),
    )
    .await;
    assert_eq!(session.device_id, bitwarden_id(user, identifier));

    // The same phone signs in again: still one device.
    let again = app.client();
    let session2 =
        sign_in_session(&again, kemlock_device("Kemlock on Pixel", Some(identifier))).await;
    assert_eq!(session2.device_id, session.device_id);
    let listed = authed(
        &again,
        "GET",
        "/kem/v1/devices",
        &session2.access_token,
        None,
    )
    .await;
    assert_eq!(listed.json()["devices"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn a_bad_identifier_is_a_400_and_the_field_is_optional() {
    let app = App::new(true);
    let client = app.client();
    register(&client, EMAIL, None).await;

    let empty = sign_in_reply(&client, EMAIL, kemlock_device("Pixel", Some(""))).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    let long = sign_in_reply(
        &client,
        EMAIL,
        kemlock_device("Pixel", Some(&"x".repeat(257))),
    )
    .await;
    assert_eq!(long.status, StatusCode::BAD_REQUEST);

    let none = sign_in_reply(&client, EMAIL, kemlock_device("Pixel", None)).await;
    assert_eq!(none.status, StatusCode::OK, "{:?}", none.json());
}

// ---------------------------------------------------------------------------------------------
// A Compatible account moves to OPAQUE.

fn pbkdf2(secret: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(rounds).expect("non-zero"),
        salt,
        secret,
        &mut out,
    );
    out
}

/// A copied Vaultwarden account: Compatible, a Bitwarden record with a real PBKDF2 hash, and
/// neither an OPAQUE record nor keys.
async fn compatible_app() -> (App, Client, UserId) {
    let app = App::new(true);
    let client = app.client();
    let (reply, user) = register(&client, EMAIL, None).await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let mut copied = app.store.user(user).expect("the account");
    copied.mode = AccountMode::Compatible;
    copied.opaque_record = None;
    copied.wrapped_root_key.clear();
    copied.public_bundle.clear();
    copied.bundle_signature.clear();
    copied.sealed_private_keys.clear();
    app.store.put_user(copied);
    app.store.put_bw_account(BwAccount {
        user,
        password_hash: pbkdf2(BW_HASH.as_bytes(), &[8; 64], 1_000),
        salt: vec![8; 64],
        password_iterations: 1_000,
        kdf_type: 0,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        akey: "2.iv|data|mac".to_owned(),
        private_key: None,
        public_key: None,
        password_hint: None,
        api_key: None,
        avatar_color: None,
        revision_ms: 1,
    });
    (app, client, user)
}

async fn bitwarden_start(client: &Client, hash: &str, request: &[u8]) -> Reply {
    client
        .post(
            "/kem/v1/auth/bitwarden/start",
            json!({"email": EMAIL, "masterPasswordHash": hash, "request": b64(request)}),
        )
        .await
}

fn finish_body(user: UserId, ticket: &Value, upload: &[u8]) -> Value {
    json!({
        "ticket": ticket,
        "upload": b64(upload),
        "kdf": {"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": b64(&[4u8; 16])},
        "publicBundle": b64(&fakes::bundle(user)),
        "bundleSignature": b64(&fakes::bundle_signature(user)),
        "sealedPrivateKeys": b64(&[0x22u8; 64]),
        "wrappedRootKey": b64(&[0x33u8; WRAPPED_ROOT_KEY_LEN]),
    })
}

#[tokio::test]
async fn a_compatible_account_enrols_opaque_in_one_exchange_and_signs_in_with_it() {
    let (app, client, user) = compatible_app().await;
    let stamp = app.store.user(user).expect("account").security_stamp;

    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = bitwarden_start(&client, BW_HASH, &request).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    assert_eq!(started["userId"], user.to_string());
    assert_eq!(
        started["key"], "2.iv|data|mac",
        "the account's wrapped Bitwarden user key"
    );
    assert_eq!(started["twoFactor"], json!([]));
    let response = unb64(started["response"].as_str().expect("response"));
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");

    let finished = client
        .post(
            "/kem/v1/auth/bitwarden/finish",
            finish_body(user, &started["ticket"], &upload),
        )
        .await;
    assert_eq!(
        finished.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        finished.body
    );

    let account = app.store.user(user).expect("account");
    assert_eq!(account.mode, AccountMode::Compatible);
    assert!(account.opaque_record.is_some());
    assert_eq!(
        account.security_stamp, stamp,
        "Bitwarden apps stay signed in"
    );
    assert!(app.store.bw_account_of(user).is_some());

    // The account signs in with OPAQUE now, with no further prompt.
    let session = sign_in_session(&client, kemlock_device("Kemlock on Pixel", None)).await;
    assert_eq!(session.user_id, user.to_string());

    // And the web vault can read what it needs to unlock.
    let keys = authed(
        &client,
        "GET",
        "/kem/v1/account/keys",
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(keys.status, StatusCode::OK, "{:?}", keys.json());
    let keys = keys.json();
    assert_eq!(keys["keyVersion"], 1);
    assert_eq!(keys["wrappedRootKey"], b64(&[0x33u8; WRAPPED_ROOT_KEY_LEN]));
    assert_eq!(keys["publicBundle"], b64(&fakes::bundle(user)));
    assert_eq!(keys["bundleSignature"], b64(&fakes::bundle_signature(user)));
    assert_eq!(keys["sealedPrivateKeys"], b64(&[0x22u8; 64]));
    assert_eq!(keys["kdf"]["iterations"], 3);
}

#[tokio::test]
async fn repeated_wrong_hashes_are_refused_and_then_rate_limited() {
    let (_app, client, _user) = compatible_app().await;
    let (_state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");

    for _ in 0..10 {
        let wrong = bitwarden_start(&client, "another-hash", &request).await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());
    }
    // Ten failures in: even the right hash waits.
    let blocked = bitwarden_start(&client, BW_HASH, &request).await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.header("retry-after").is_some());
}

#[tokio::test]
async fn an_enrolled_account_cannot_enrol_again_and_unknown_emails_look_like_wrong_hashes() {
    let (_app, client, user) = compatible_app().await;
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = bitwarden_start(&client, BW_HASH, &request).await.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");
    let finished = client
        .post(
            "/kem/v1/auth/bitwarden/finish",
            finish_body(user, &started["ticket"], &upload),
        )
        .await;
    assert_eq!(finished.status, StatusCode::NO_CONTENT);

    let again = bitwarden_start(&client, BW_HASH, &request).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-exists");

    let nobody = client
        .post(
            "/kem/v1/auth/bitwarden/start",
            json!({"email": "nobody@example.org", "masterPasswordHash": BW_HASH, "request": b64(&request)}),
        )
        .await;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_ticket_is_for_the_key_that_asked() {
    let (app, client, user) = compatible_app().await;
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = bitwarden_start(&client, BW_HASH, &request).await.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");

    // Another device key cannot finish what this one started.
    let thief = app.client();
    let refused = thief
        .post(
            "/kem/v1/auth/bitwarden/finish",
            finish_body(user, &started["ticket"], &upload),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        refused.json()
    );
}

#[tokio::test]
async fn the_account_keys_need_a_token_and_keys_to_give() {
    let (app, client, session) = signed_in().await;
    let anonymous = client.get("/kem/v1/account/keys").await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let keys = authed(
        &client,
        "GET",
        "/kem/v1/account/keys",
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(keys.status, StatusCode::OK);

    // An account whose keys were cleared (a Compatible one before it enrols) has none to give.
    let user = user_id(&session);
    let mut bare = app.store.user(user).expect("the account");
    bare.wrapped_root_key.clear();
    bare.public_bundle.clear();
    app.store.put_user(bare);
    let keys = authed(
        &client,
        "GET",
        "/kem/v1/account/keys",
        &session.access_token,
        None,
    )
    .await;
    assert_eq!(keys.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// The first keys of an account that single sign-on made with none.

fn enrol_body(user: UserId) -> Value {
    json!({
        "publicBundle": b64(&fakes::bundle(user)),
        "bundleSignature": b64(&fakes::bundle_signature(user)),
        "sealedPrivateKeys": b64(&[0x22u8; 64]),
        "deviceCopy": {"wrappedKey": b64(&[0xc3u8; 93]), "protection": "web-crypto"},
    })
}

/// Signed in, with the account's key material taken away as `SsoFinish` leaves a new account's.
async fn keyless() -> (App, Client, Session, UserId) {
    let (app, client, session) = signed_in().await;
    let user = user_id(&session);
    let mut bare = app.store.user(user).expect("the account");
    bare.opaque_record = None;
    bare.wrapped_root_key.clear();
    bare.public_bundle.clear();
    bare.bundle_signature.clear();
    bare.sealed_private_keys.clear();
    bare.key_version = 0;
    app.store.put_user(bare);
    (app, client, session, user)
}

#[tokio::test]
async fn a_keyless_account_enrols_its_keys_once_and_keeps_the_devices_copy() {
    let (_app, client, session, user) = keyless().await;
    let token = &session.access_token;
    let path = "/kem/v1/account/keys/enrol";

    let anonymous = client.post(path, enrol_body(user)).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let before = authed(&client, "GET", "/kem/v1/account/keys", token, None).await;
    assert_eq!(before.status, StatusCode::NOT_FOUND);

    let enrolled = authed(&client, "POST", path, token, Some(enrol_body(user))).await;
    assert_eq!(enrolled.status, StatusCode::OK, "{:?}", enrolled.json());
    assert_eq!(enrolled.json()["keyVersion"], 1);

    // The keys read back with no password wrap, and the device holds its copy.
    let keys = authed(&client, "GET", "/kem/v1/account/keys", token, None).await;
    assert_eq!(keys.status, StatusCode::OK, "{:?}", keys.json());
    let keys = keys.json();
    assert_eq!(keys["keyVersion"], 1);
    assert_eq!(keys["wrappedRootKey"], "");
    assert_eq!(keys["publicBundle"], b64(&fakes::bundle(user)));
    assert_eq!(keys["sealedPrivateKeys"], b64(&[0x22u8; 64]));
    let copy = authed(&client, "GET", "/kem/v1/devices/key-copy", token, None).await;
    assert_eq!(copy.status, StatusCode::OK, "{:?}", copy.json());
    assert_eq!(copy.json()["wrappedKey"], b64(&[0xc3u8; 93]));
    assert_eq!(copy.json()["protection"], "web-crypto");

    // Keys are made once.
    let mut other = enrol_body(user);
    other["sealedPrivateKeys"] = json!(b64(&[0x99u8; 64]));
    let again = authed(&client, "POST", path, token, Some(other)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-exists");
}

#[tokio::test]
async fn an_account_that_has_keys_cannot_enrol_new_ones() {
    let (_app, client, session) = signed_in().await;
    let user = user_id(&session);
    let refused = authed(
        &client,
        "POST",
        "/kem/v1/account/keys/enrol",
        &session.access_token,
        Some(enrol_body(user)),
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.problem(), "already-exists");
}

#[tokio::test]
async fn enrolled_keys_must_be_for_this_account_and_well_formed() {
    let (_app, client, session, user) = keyless().await;
    let token = &session.access_token;
    let path = "/kem/v1/account/keys/enrol";

    let mut foreign = enrol_body(user);
    foreign["publicBundle"] = json!(b64(&fakes::bundle(UserId::random())));
    let mut not_base64 = enrol_body(user);
    not_base64["sealedPrivateKeys"] = json!("***");
    let mut unknown_protection = enrol_body(user);
    unknown_protection["deviceCopy"]["protection"] = json!("tpm");
    let mut empty_copy = enrol_body(user);
    empty_copy["deviceCopy"]["wrappedKey"] = json!(b64(&[]));
    for bad in [foreign, not_base64, unknown_protection, empty_copy] {
        let refused = authed(&client, "POST", path, token, Some(bad)).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.json()
        );
    }
    // None of it was kept: a good request still works.
    let enrolled = authed(&client, "POST", path, token, Some(enrol_body(user))).await;
    assert_eq!(enrolled.status, StatusCode::OK, "{:?}", enrolled.json());
}

// ---------------------------------------------------------------------------------------------
// Tombstones carry the server's time.

#[tokio::test]
async fn a_tombstone_in_sync_says_when_the_server_recorded_the_deletion() {
    let (app, client, session) = signed_in().await;
    let id = new_item_id();
    let path = format!("/kem/v1/items/{id}");
    let put = |precondition: (&'static str, &'static str), body: Value| {
        client.send(
            "PUT",
            &path,
            Req {
                access_token: Some(&session.access_token),
                headers: vec![(precondition.0, precondition.1.to_owned())],
                body: Some(body),
                ..Req::default()
            },
        )
    };
    let created = put(("if-none-match", "*"), item_json(&session.user_id, &id, 1)).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert!(created.json().get("deletedAt").is_none());

    app.clock.advance(Duration::minutes(5));
    let deleted_at = app.clock.now();
    let tombstone = json!({
        "id": id, "owner": format!("user:{}", session.user_id), "kind": "login",
        "format": "kem1", "revision": 2, "keyVersion": 1, "deleted": true,
        // A client that echoes a time back doesn't set it: the server's clock does.
        "deletedAt": "1999-01-01T00:00:00Z",
    });
    let deleted = put(("if-match", "1"), tombstone).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json());
    let at = OffsetDateTime::parse(
        deleted.json()["deletedAt"].as_str().expect("a time"),
        &Rfc3339,
    )
    .expect("RFC 3339");
    assert_eq!(at, deleted_at);

    let sync = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await
        .json();
    let items = sync["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["deleted"], true);
    let text = items[0]["deletedAt"].as_str().expect("a time");
    assert!(text.ends_with('Z'), "UTC: {text}");
    assert_eq!(
        OffsetDateTime::parse(text, &Rfc3339).expect("RFC 3339"),
        deleted_at
    );

    // A live item has no deletion time.
    let live_id = new_item_id();
    let live = client
        .send(
            "PUT",
            &format!("/kem/v1/items/{live_id}"),
            Req {
                access_token: Some(&session.access_token),
                headers: vec![("if-none-match", "*".to_owned())],
                body: Some(item_json(&session.user_id, &live_id, 1)),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(live.status, StatusCode::CREATED);
    let sync = client
        .get_authed("/kem/v1/sync", &session.access_token)
        .await
        .json();
    for item in sync["items"].as_array().expect("items") {
        assert_eq!(
            item.get("deletedAt").is_some(),
            item["deleted"] == true,
            "{item}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The OpenAPI document.

#[tokio::test]
async fn the_new_routes_are_documented() {
    let app = App::new(false);
    let json = app.client().get("/kem/v1/openapi.json").await.json();
    for (path, method) in [
        ("/kem/v1/manifests/{owner}", "put"),
        ("/kem/v1/manifests/{owner}", "get"),
        ("/kem/v1/devices", "get"),
        ("/kem/v1/auth/bitwarden/start", "post"),
        ("/kem/v1/auth/bitwarden/finish", "post"),
        ("/kem/v1/account/keys", "get"),
        ("/kem/v1/account/keys/enrol", "post"),
    ] {
        assert!(
            json["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
    for schema in [
        "ManifestRequest",
        "ManifestResponse",
        "DeviceListResponse",
        "BitwardenStartRequest",
        "BitwardenFinishRequest",
        "AccountKeysResponse",
        "EnrolKeysRequest",
        "EnrolKeysResponse",
    ] {
        assert!(
            json["components"]["schemas"][schema].is_object(),
            "{schema}"
        );
    }
    assert!(json["components"]["schemas"]["ItemDto"]["properties"]["deletedAt"].is_object());
    assert!(
        json["components"]["schemas"]["DeviceDto"]["properties"]["bitwardenDeviceIdentifier"]
            .is_object()
    );
}
