//! `POST` and `DELETE /kem/v1/devices/push-token` over HTTP against the fakes, with real DPoP.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_api_kem::push_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::ports::StoreError;
use kemlock_app::push::{PushInstallation, PushRegistration, PushRepo};
use kemlock_domain::{DeviceId, UserId};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Push tokens in memory.
#[derive(Clone, Default)]
struct MemPush(Arc<Mutex<HashMap<DeviceId, PushRegistration>>>);

impl MemPush {
    fn of(&self, user: &str) -> Vec<PushRegistration> {
        let user: UserId = user.parse().expect("a user id");
        self.0
            .lock()
            .expect("lock")
            .values()
            .filter(|r| r.user == user)
            .cloned()
            .collect()
    }
}

impl PushRepo for MemPush {
    async fn put_registration(&self, registration: &PushRegistration) -> Result<(), StoreError> {
        self.0
            .lock()
            .expect("lock")
            .insert(registration.device, registration.clone());
        Ok(())
    }

    async fn remove_registration(&self, device: DeviceId) -> Result<(), StoreError> {
        self.0.lock().expect("lock").remove(&device);
        Ok(())
    }

    async fn registrations_for(
        &self,
        users: &[UserId],
    ) -> Result<Vec<PushRegistration>, StoreError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .values()
            .filter(|r| users.contains(&r.user))
            .cloned()
            .collect())
    }

    async fn installation(&self) -> Result<Option<PushInstallation>, StoreError> {
        Ok(None)
    }

    async fn set_installation(&self, _: &PushInstallation) -> Result<(), StoreError> {
        Ok(())
    }

    async fn clear_installation(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// An app with the push routes merged beside the main router, and a signed-in device.
async fn scene() -> (Client, Session, MemPush) {
    let app = App::new(true);
    let push = MemPush::default();
    let router = app
        .router
        .clone()
        .merge(push_router(app.api.clone(), push.clone()));
    let client = Client::new(router, app.clock.clone(), DpopSigner::es256());
    let session = register_and_sign_in(&client, "ada@example.org").await;
    (client, session, push)
}

async fn call(
    client: &Client,
    session: &Session,
    method: &str,
    body: Option<serde_json::Value>,
) -> Reply {
    client
        .send(
            method,
            "/kem/v1/devices/push-token",
            Req {
                access_token: Some(&session.access_token),
                body,
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn a_device_registers_its_token() {
    let (client, session, push) = scene().await;
    let reply = call(
        &client,
        &session,
        "POST",
        Some(json!({"kind": "unifiedpush", "token": "https://ntfy.example.org/upAbc"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{:?}", reply.body);
    let stored = push.of(&session.user_id);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].token, "https://ntfy.example.org/upAbc");
    assert_eq!(stored[0].device.to_string(), session.device_id);
    assert_eq!(stored[0].kind.as_str(), "unifiedpush");
}

#[tokio::test]
async fn registering_again_replaces_the_token() {
    let (client, session, push) = scene().await;
    for token in ["first", "second"] {
        let reply = call(
            &client,
            &session,
            "POST",
            Some(json!({"kind": "apns", "token": token})),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
    }
    let stored = push.of(&session.user_id);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].token, "second");
    assert_eq!(stored[0].kind.as_str(), "apns");
}

#[tokio::test]
async fn a_bad_body_is_a_400_problem() {
    let (client, session, push) = scene().await;
    let bodies = [
        json!({"kind": "sms", "token": "t"}),
        // Firebase is no longer accepted.
        json!({"kind": "fcm", "token": "fcm-token"}),
        json!({"kind": "apns", "token": ""}),
        json!({"kind": "apns", "token": "has space"}),
        json!({"kind": "apns", "token": "x".repeat(513)}),
        json!({"kind": "apns"}),
        json!({"kind": "apns", "token": "t", "userId": "someone-else"}),
        json!({"kind": "unifiedpush", "token": "http://ntfy.example.org/up"}),
        json!({"kind": "unifiedpush", "token": "not a url"}),
        json!({"kind": "unifiedpush", "token": "https://u:p@ntfy.example.org/up"}),
    ];
    for body in bodies {
        let reply = call(&client, &session, "POST", Some(body.clone())).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert!(reply.content_type().starts_with("application/problem+json"));
    }
    assert!(push.of(&session.user_id).is_empty());
}

#[tokio::test]
async fn the_routes_need_a_signed_in_device() {
    let (client, _session, push) = scene().await;
    let reply = client
        .send(
            "POST",
            "/kem/v1/devices/push-token",
            Req {
                body: Some(json!({"kind": "apns", "token": "t"})),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(push.0.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn deleting_forgets_the_token_and_twice_is_fine() {
    let (client, session, push) = scene().await;
    call(
        &client,
        &session,
        "POST",
        Some(json!({"kind": "apns", "token": "t"})),
    )
    .await;
    assert_eq!(
        call(&client, &session, "DELETE", None).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(push.of(&session.user_id).is_empty());
    assert_eq!(
        call(&client, &session, "DELETE", None).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn the_answer_carries_the_dpop_nonce() {
    let (client, session, _push) = scene().await;
    let reply = call(&client, &session, "DELETE", None).await;
    assert!(reply.header("dpop-nonce").is_some());
}
