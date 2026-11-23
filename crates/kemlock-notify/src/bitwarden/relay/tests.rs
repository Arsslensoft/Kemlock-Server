use super::*;
use crate::testing::serve;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Form, Json, Router};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use time::macros::datetime;

/// Bitwarden's identity service and push relay, in one fake.
struct Fake {
    token_calls: AtomicUsize,
    expires_in: AtomicI64,
    /// How many relay calls to refuse with a 401 before accepting.
    refuse: AtomicUsize,
    forms: Mutex<Vec<HashMap<String, String>>>,
    /// `(path, bearer token, body)` of every relay call.
    calls: Mutex<Vec<(String, String, Value)>>,
}

impl Fake {
    fn new(expires_in: i64) -> Arc<Fake> {
        Arc::new(Fake {
            token_calls: AtomicUsize::new(0),
            expires_in: AtomicI64::new(expires_in),
            refuse: AtomicUsize::new(0),
            forms: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        })
    }
}

async fn connect_token(
    State(fake): State<Arc<Fake>>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let n = fake.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let good = form.get("client_id").map(String::as_str) == Some("installation.inst-1")
        && form.get("client_secret").map(String::as_str) == Some("secret-1");
    fake.forms.lock().expect("lock").push(form);
    if !good {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    Json(json!({
        "access_token": format!("token-{n}"),
        "expires_in": fake.expires_in.load(Ordering::SeqCst),
        "token_type": "Bearer",
    }))
    .into_response()
}

async fn relay_call(
    State(fake): State<Arc<Fake>>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned();
    if fake
        .refuse
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return StatusCode::UNAUTHORIZED;
    }
    fake.calls
        .lock()
        .expect("lock")
        .push((uri.path().to_owned(), bearer, body));
    StatusCode::OK
}

async fn client_for(fake: &Arc<Fake>, secret: &str) -> BitwardenPush {
    let app = Router::new()
        .route("/connect/token", post(connect_token))
        .route("/push/register", post(relay_call))
        .route("/push/delete", post(relay_call))
        .route("/push/send", post(relay_call))
        .with_state(fake.clone());
    let address = serve(app).await;
    let base = format!("http://{address}");
    BitwardenPush::new(BitwardenPushConfig {
        installation_id: "inst-1".to_owned(),
        installation_key: Zeroizing::new(secret.to_owned()),
        relay_uri: base.clone(),
        identity_uri: base,
    })
    .expect("a client")
}

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[test]
fn push_is_off_unless_enabled() {
    assert_eq!(
        BitwardenPushConfig::from_lookup(&lookup(&[]))
            .expect("ok")
            .map(|_| ()),
        None
    );
    // An id and a key without PUSH_ENABLED change nothing, as in Vaultwarden.
    let config = BitwardenPushConfig::from_lookup(&lookup(&[
        ("PUSH_INSTALLATION_ID", "i"),
        ("PUSH_INSTALLATION_KEY", "k"),
    ]))
    .expect("ok");
    assert!(config.is_none());
}

#[test]
fn enabling_push_needs_an_id_and_a_key() {
    assert!(matches!(
        BitwardenPushConfig::from_lookup(&lookup(&[("PUSH_ENABLED", "true")])),
        Err(PushConfigError::Missing("PUSH_INSTALLATION_ID"))
    ));
    assert!(matches!(
        BitwardenPushConfig::from_lookup(&lookup(&[
            ("PUSH_ENABLED", "true"),
            ("PUSH_INSTALLATION_ID", "i"),
        ])),
        Err(PushConfigError::Missing("PUSH_INSTALLATION_KEY"))
    ));
}

#[test]
fn the_defaults_are_bitwardens_us_cloud_and_the_key_stays_secret() {
    let config = BitwardenPushConfig::from_lookup(&lookup(&[
        ("PUSH_ENABLED", "true"),
        ("PUSH_INSTALLATION_ID", "inst"),
        ("PUSH_INSTALLATION_KEY", "very-secret"),
    ]))
    .expect("ok")
    .expect("on");
    assert_eq!(config.relay_uri, "https://push.bitwarden.com");
    assert_eq!(config.identity_uri, "https://identity.bitwarden.com");
    assert!(!format!("{config:?}").contains("very-secret"));
}

#[test]
fn the_eu_cloud_and_trailing_slashes() {
    let config = BitwardenPushConfig::from_lookup(&lookup(&[
        ("PUSH_ENABLED", "1"),
        ("PUSH_INSTALLATION_ID", "i"),
        ("PUSH_INSTALLATION_KEY", "k"),
        ("PUSH_RELAY_URI", "https://api.bitwarden.eu/"),
        ("PUSH_IDENTITY_URI", "https://identity.bitwarden.eu/"),
    ]))
    .expect("ok")
    .expect("on");
    assert_eq!(config.relay_uri, "https://api.bitwarden.eu");
    assert_eq!(config.identity_uri, "https://identity.bitwarden.eu");
}

#[test]
fn the_key_is_not_sent_over_plain_http() {
    let with = |extra: (&'static str, &'static str)| {
        BitwardenPushConfig::from_lookup(&lookup(&[
            ("PUSH_ENABLED", "true"),
            ("PUSH_INSTALLATION_ID", "i"),
            ("PUSH_INSTALLATION_KEY", "k"),
            extra,
        ]))
    };
    assert!(matches!(
        with(("PUSH_RELAY_URI", "http://push.example.com")),
        Err(PushConfigError::NotHttps("PUSH_RELAY_URI"))
    ));
    assert!(matches!(
        with(("PUSH_IDENTITY_URI", "http://identity.example.com")),
        Err(PushConfigError::NotHttps("PUSH_IDENTITY_URI"))
    ));
}

#[tokio::test]
async fn the_token_request_is_a_client_credentials_grant_for_the_installation() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    client
        .send(&BwPush::user_update(
            UpdateType::SyncVault,
            id(1),
            datetime!(2026-11-23 10:00 UTC),
        ))
        .await
        .expect("sends");
    let forms = fake.forms.lock().expect("lock");
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0]["grant_type"], "client_credentials");
    assert_eq!(forms[0]["scope"], "api.push");
    assert_eq!(forms[0]["client_id"], "installation.inst-1");
    assert_eq!(forms[0]["client_secret"], "secret-1");
}

#[tokio::test]
async fn the_bearer_token_is_reused_while_it_is_fresh() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    for _ in 0..3 {
        client
            .send(&BwPush::user_update(
                UpdateType::SyncVault,
                id(1),
                datetime!(2026-11-23 10:00 UTC),
            ))
            .await
            .expect("sends");
    }
    assert_eq!(fake.token_calls.load(Ordering::SeqCst), 1);
    let calls = fake.calls.lock().expect("lock");
    assert!(calls.iter().all(|(_, bearer, _)| bearer == "token-1"));
}

#[tokio::test]
async fn a_token_that_is_stale_is_fetched_again() {
    // Half of a 0-second lifetime is already over.
    let fake = Fake::new(0);
    let client = client_for(&fake, "secret-1").await;
    for _ in 0..2 {
        client
            .send(&BwPush::user_update(
                UpdateType::SyncVault,
                id(1),
                datetime!(2026-11-23 10:00 UTC),
            ))
            .await
            .expect("sends");
    }
    assert_eq!(fake.token_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_refused_installation_is_unauthorized() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "wrong").await;
    let result = client
        .send(&BwPush::user_update(
            UpdateType::SyncVault,
            id(1),
            datetime!(2026-11-23 10:00 UTC),
        ))
        .await;
    assert_eq!(result, Err(RelayError::Status(400)));
    assert!(fake.calls.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_revoked_token_is_dropped_so_the_next_send_gets_a_new_one() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    let push = BwPush::user_update(
        UpdateType::SyncVault,
        id(1),
        datetime!(2026-11-23 10:00 UTC),
    );
    client.send(&push).await.expect("sends");
    fake.refuse.store(1, Ordering::SeqCst);
    assert_eq!(client.send(&push).await, Err(RelayError::Unauthorized));
    client.send(&push).await.expect("sends again");
    assert_eq!(fake.token_calls.load(Ordering::SeqCst), 2);
    let calls = fake.calls.lock().expect("lock");
    assert_eq!(calls.last().expect("a call").1, "token-2");
}

#[tokio::test]
async fn registering_a_phone_sends_vaultwardens_body_and_returns_the_push_id() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    let push_uuid = client
        .register_device(&BwPushDevice {
            push_uuid: None,
            push_token: "fcm-token".to_owned(),
            user: id(1),
            device_type: 0,
            identifier: id(2),
        })
        .await
        .expect("registers");
    let calls = fake.calls.lock().expect("lock");
    let (path, _, body) = &calls[0];
    assert_eq!(path, "/push/register");
    assert_eq!(
        *body,
        json!({
            "deviceId": push_uuid,
            "pushToken": "fcm-token",
            "userId": id(1),
            "type": 0,
            "identifier": id(2),
            "installationId": "inst-1",
        })
    );
}

#[tokio::test]
async fn a_known_push_id_is_kept_and_unregistering_names_it() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    let known = id(77);
    let returned = client
        .register_device(&BwPushDevice {
            push_uuid: Some(known),
            push_token: "t".to_owned(),
            user: id(1),
            device_type: 1,
            identifier: id(2),
        })
        .await
        .expect("registers");
    assert_eq!(returned, known);
    client.unregister_device(known).await.expect("unregisters");
    let calls = fake.calls.lock().expect("lock");
    assert_eq!(calls[1].0, "/push/delete");
    assert_eq!(calls[1].2, json!({"id": known}));
}

#[tokio::test]
async fn a_cipher_push_has_vaultwardens_shape() {
    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    client
        .send(&BwPush::cipher(
            UpdateType::SyncCipherUpdate,
            id(10),
            id(1),
            datetime!(2026-11-23 10:00 UTC),
            Some(id(2)),
        ))
        .await
        .expect("sends");
    let calls = fake.calls.lock().expect("lock");
    assert_eq!(calls[0].0, "/push/send");
    assert_eq!(
        calls[0].2,
        json!({
            "userId": id(1),
            "organizationId": null,
            "deviceId": null,
            "identifier": id(2),
            "type": 0,
            "payload": {
                "id": id(10),
                "userId": id(1),
                "organizationId": null,
                "collectionIds": null,
                "revisionDate": "2026-11-23T10:00:00Z",
            },
            "clientType": null,
            "installationId": null,
        })
    );
}

#[test]
fn the_other_pushes_have_their_types_and_payloads() {
    let at = datetime!(2026-11-23 10:00 UTC);
    let logout = BwPush::logout(id(1), Some(id(2)), at);
    assert_eq!(logout.kind.code(), 11);
    assert_eq!(
        logout.payload,
        json!({"userId": id(1), "date": "2026-11-23T10:00:00Z"})
    );
    assert_eq!(logout.identifier, Some(id(2)));

    let folder = BwPush::folder(UpdateType::SyncFolderCreate, id(5), id(1), at, None);
    assert_eq!(folder.kind.code(), 7);
    assert_eq!(
        folder.payload,
        json!({"id": id(5), "userId": id(1), "revisionDate": "2026-11-23T10:00:00Z"})
    );

    let request = BwPush::auth_request(UpdateType::AuthRequest, id(6), id(1), Some(id(7)), None);
    assert_eq!(request.kind.code(), 15);
    assert_eq!(request.device_push_uuid, Some(id(7)));
    assert_eq!(request.payload, json!({"userId": id(1), "id": id(6)}));
}

#[test]
fn a_send_push_has_vaultwardens_payload_and_can_skip_the_acting_phone() {
    let at = datetime!(2026-11-25 10:00 UTC);
    let send = BwPush::send(UpdateType::SyncSendUpdate, id(5), id(1), at);
    assert_eq!(send.kind.code(), 13);
    assert_eq!(
        send.payload,
        json!({"id": id(5), "userId": id(1), "revisionDate": "2026-11-25T10:00:00Z"})
    );
    assert_eq!((send.device_push_uuid, send.identifier), (None, None));

    let from_a_phone = send.from_device(Some(id(7)), Some(id(8)));
    assert_eq!(from_a_phone.device_push_uuid, Some(id(7)));
    assert_eq!(from_a_phone.identifier, Some(id(8)));
    let body = from_a_phone.body();
    assert_eq!(body["deviceId"], json!(id(7)));
    assert_eq!(body["identifier"], json!(id(8)));
    assert_eq!(body["type"], 13);
}

#[tokio::test]
async fn the_device_routes_register_and_forget_phones_through_the_port() {
    use kemlock_app::bw_events::{BwDevice, BwPushToken, BwRelay};
    use kemlock_domain::{DeviceId, UserId};

    let fake = Fake::new(3600);
    let client = client_for(&fake, "secret-1").await;
    let relay: &dyn BwRelay = &client;
    let mut device = BwDevice {
        device: DeviceId(id(5)),
        user: UserId(id(1)),
        identifier: id(2),
        device_type: 1,
        push: None,
        updated_at: datetime!(2026-11-25 10:00 UTC),
    };
    // A phone with no token has nothing to register.
    assert!(relay.register(&device).await.is_err());
    assert!(fake.calls.lock().expect("lock").is_empty());

    device.push = Some(BwPushToken {
        push_uuid: id(77),
        token: "apns-token".to_owned(),
    });
    relay.register(&device).await.expect("registers");
    relay.unregister(id(77)).await.expect("forgets");
    {
        let calls = fake.calls.lock().expect("lock");
        assert_eq!(calls[0].0, "/push/register");
        assert_eq!(
            calls[0].2,
            json!({
                "deviceId": id(77),
                "pushToken": "apns-token",
                "userId": id(1),
                "type": 1,
                "identifier": id(2),
                "installationId": "inst-1",
            })
        );
        assert_eq!(calls[1].0, "/push/delete");
    }

    // A relay that turns the installation away is an error the route can say.
    let refused = client_for(&fake, "wrong").await;
    let error = BwRelay::register(&refused, &device)
        .await
        .expect_err("refused");
    assert!(error.contains("400"), "{error}");
}
