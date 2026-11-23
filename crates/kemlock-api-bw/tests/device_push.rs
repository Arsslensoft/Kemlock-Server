//! Push tokens of Bitwarden's phone apps: `PUT /api/devices/identifier/{id}/token` and the
//! `clear-token` routes, with a relay that records what it is asked.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness, claims};
use kemlock_app::bw_events::{BwDevice, BwDeviceRepo, BwRelay};
use kemlock_app::notices::BoxFuture;
use kemlock_domain::DeviceId;
use serde_json::json;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const APP_ID: &str = "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a";

#[derive(Default)]
struct Relay {
    registered: Mutex<Vec<BwDevice>>,
    forgotten: Mutex<Vec<Uuid>>,
    /// Refuse every registration.
    refuse: bool,
}

impl BwRelay for Relay {
    fn register<'a>(&'a self, device: &'a BwDevice) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if self.refuse {
                return Err("the relay is down".to_owned());
            }
            self.registered.lock().expect("lock").push(device.clone());
            Ok(())
        })
    }

    fn unregister(&self, push_uuid: Uuid) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.forgotten.lock().expect("lock").push(push_uuid);
            Ok(())
        })
    }
}

async fn phone(relay: Arc<Relay>) -> (Harness, String, DeviceId) {
    let h = Harness::with_relay(relay).await;
    let (token, _) = h.signed_in("ada@example.com").await;
    let device = claims(&token, h.env.time().unix_timestamp()).device;
    let device = DeviceId(Uuid::parse_str(&device).expect("a device id"));
    (h, token, device)
}

async fn put_token(h: &Harness, token: &str, push_token: &str) -> StatusCode {
    h.json(
        "PUT",
        &format!("/api/devices/identifier/{APP_ID}/token"),
        Some(token),
        Some(json!({"pushToken": push_token})),
    )
    .await
    .0
}

#[tokio::test]
async fn a_phones_token_is_registered_with_the_relay_and_kept() {
    let relay = Arc::new(Relay::default());
    let (h, token, device) = phone(relay.clone()).await;
    assert_eq!(put_token(&h, &token, "fcm-token").await, StatusCode::OK);

    let registered = relay.registered.lock().expect("lock").clone();
    assert_eq!(registered.len(), 1);
    let sent = registered[0].push.as_ref().expect("a token");
    assert_eq!(sent.token, "fcm-token");
    assert_eq!(
        registered[0].identifier,
        Uuid::parse_str(APP_ID).expect("uuid")
    );
    assert_eq!(registered[0].device_type, 0);

    let kept = BwDeviceRepo::bw_device(&h.store, device)
        .await
        .expect("reads")
        .expect("known");
    assert_eq!(kept.push, Some(sent.clone()));
    assert!(
        BwDeviceRepo::bw_user_has_push(&h.store, kept.user)
            .await
            .expect("reads")
    );
}

#[tokio::test]
async fn the_same_token_is_not_registered_twice_and_a_new_one_keeps_the_relays_id() {
    let relay = Arc::new(Relay::default());
    let (h, token, _) = phone(relay.clone()).await;
    put_token(&h, &token, "one").await;
    assert_eq!(put_token(&h, &token, "one").await, StatusCode::OK);
    assert_eq!(relay.registered.lock().expect("lock").len(), 1);

    assert_eq!(put_token(&h, &token, "two").await, StatusCode::OK);
    let registered = relay.registered.lock().expect("lock").clone();
    assert_eq!(registered.len(), 2);
    let first = registered[0].push.as_ref().expect("a token").push_uuid;
    let second = registered[1].push.as_ref().expect("a token");
    assert_eq!(
        second.push_uuid, first,
        "the relay still knows the phone by one id"
    );
    assert_eq!(second.token, "two");
}

#[tokio::test]
async fn a_post_works_as_a_put() {
    let relay = Arc::new(Relay::default());
    let (h, token, _) = phone(relay.clone()).await;
    let (status, _) = h
        .json(
            "POST",
            &format!("/api/devices/identifier/{APP_ID}/token"),
            Some(&token),
            Some(json!({"pushToken": "fcm-token"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(relay.registered.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn an_app_that_is_not_a_phone_registers_nothing() {
    let relay = Arc::new(Relay::default());
    let h = Harness::with_relay(relay.clone()).await;
    h.account("ada@example.com", HASH).await;
    let mut fields = Harness::password_fields("ada@example.com", HASH);
    fields.retain(|(name, _)| *name != "deviceType");
    // A desktop app.
    fields.push(("deviceType", "8"));
    let (status, body) = h.token(&fields).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().expect("a token");
    assert_eq!(put_token(&h, token, "fcm-token").await, StatusCode::OK);
    assert!(relay.registered.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_relay_that_fails_is_an_error_and_keeps_nothing() {
    let relay = Arc::new(Relay {
        refuse: true,
        ..Relay::default()
    });
    let (h, token, device) = phone(relay).await;
    let (status, body) = h
        .json(
            "PUT",
            &format!("/api/devices/identifier/{APP_ID}/token"),
            Some(&token),
            Some(json!({"pushToken": "fcm-token"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let kept = BwDeviceRepo::bw_device(&h.store, device)
        .await
        .expect("reads")
        .expect("known");
    assert!(kept.push.is_none());
}

#[tokio::test]
async fn clearing_the_token_forgets_the_phone_at_the_relay_and_here() {
    let relay = Arc::new(Relay::default());
    let (h, token, device) = phone(relay.clone()).await;
    put_token(&h, &token, "fcm-token").await;
    let push_uuid = relay.registered.lock().expect("lock")[0]
        .push
        .as_ref()
        .expect("a token")
        .push_uuid;

    // The route has no sign-in, as Vaultwarden's.
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/devices/identifier/{APP_ID}/clear-token"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(*relay.forgotten.lock().expect("lock"), vec![push_uuid]);
    let kept = BwDeviceRepo::bw_device(&h.store, device)
        .await
        .expect("reads")
        .expect("known");
    assert!(kept.push.is_none());

    // Again, with nothing left to forget; and an identifier that isn't one.
    for path in [APP_ID, "not-an-identifier"] {
        let (status, _) = h
            .json(
                "POST",
                &format!("/api/devices/identifier/{path}/clear-token"),
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(relay.forgotten.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn without_a_relay_the_routes_answer_and_keep_nothing() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in("ada@example.com").await;
    assert_eq!(put_token(&h, &token, "fcm-token").await, StatusCode::OK);
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/devices/identifier/{APP_ID}/clear-token"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // The sign-in recorded the device but no token.
    let device = claims(&token, h.env.time().unix_timestamp()).device;
    let known = BwDeviceRepo::bw_device(
        &h.store,
        DeviceId(Uuid::parse_str(&device).expect("a device id")),
    )
    .await
    .expect("reads")
    .expect("known");
    assert!(known.push.is_none());
}

#[tokio::test]
async fn the_token_route_needs_a_sign_in() {
    let relay = Arc::new(Relay::default());
    let h = Harness::with_relay(relay.clone()).await;
    let (status, _) = h
        .json(
            "PUT",
            &format!("/api/devices/identifier/{APP_ID}/token"),
            None,
            Some(json!({"pushToken": "fcm-token"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(relay.registered.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn the_unauthenticated_clear_token_route_is_rate_limited_per_address() {
    // Vaultwarden's unauthenticated limiter, not the login one: a burst of fifty, then one request
    // a minute. The login limiter is left tight to show the route does not draw on it.
    let h = Harness::with(|s| {
        s.login_ratelimit_max_burst = 1;
        s.unauthenticated_ratelimit_max_burst = 50;
        s.unauthenticated_ratelimit_seconds = 60;
    })
    .await;
    let clear = || async {
        h.json(
            "POST",
            &format!("/api/devices/identifier/{APP_ID}/clear-token"),
            None,
            None,
        )
        .await
    };
    for attempt in 1..=50 {
        let (status, _) = clear().await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt}");
    }
    let (status, body) = clear().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["message"], "Too many requests");

    // A minute later one more is taken.
    h.env.advance(time::Duration::seconds(60));
    let (status, _) = clear().await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = clear().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
