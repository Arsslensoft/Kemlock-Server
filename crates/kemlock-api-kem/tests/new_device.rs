//! The mail about a device that signs in to the Kemlock API for the first time.

mod common;

use axum::http::StatusCode;
use common::{App, register, register_and_sign_in, sign_in_reply};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_domain::DeviceKind;
use serde_json::json;
use std::sync::{Arc, Mutex};
use time::Duration;

const EMAIL: &str = "ada@example.org";

#[derive(Default)]
struct Mailbox(Mutex<Vec<Notice>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("the lock").push(notice);
        })
    }
}

impl Mailbox {
    fn notices(&self) -> Vec<Notice> {
        self.0.lock().expect("the lock").clone()
    }

    /// Waits until `count` notices have arrived (they are sent from a task of their own).
    async fn wait_for(&self, count: usize) {
        for _ in 0..200 {
            if self.notices().len() >= count {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("expected {count} notices, got {:?}", self.notices());
    }

    /// Gives a notice that should not be sent the chance to be.
    async fn settle(&self) {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
}

#[tokio::test]
async fn a_first_sign_in_is_mailed_and_a_known_device_is_not() {
    let mailbox = Arc::new(Mailbox::default());
    let app = App::mailing(true, mailbox.clone());
    let client = app.client();
    let session = register_and_sign_in(&client, EMAIL).await;

    mailbox.wait_for(1).await;
    let sent = mailbox.notices();
    let Notice::NewDevice(notice) = &sent[0] else {
        panic!("not a new-device notice: {:?}", sent[0]);
    };
    assert_eq!(notice.to.as_str(), EMAIL);
    assert_eq!(notice.device_name, "Test device");
    assert_eq!(notice.device_kind, DeviceKind::KemlockCli);

    // The same device signing in again is not new.
    app.clock.advance(Duration::seconds(5));
    let again = sign_in_reply(
        &client,
        EMAIL,
        json!({"id": session.device_id, "name": "Test device", "kind": "kemlock-cli"}),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
    mailbox.settle().await;
    assert_eq!(mailbox.notices().len(), 1);

    // Another device is.
    let other = app.client();
    let signed = sign_in_reply(
        &other,
        EMAIL,
        json!({"name": "Pixel", "kind": "kemlock-android"}),
    )
    .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    mailbox.wait_for(2).await;
    let Notice::NewDevice(second) = &mailbox.notices()[1] else {
        panic!("not a new-device notice");
    };
    assert_eq!(second.device_name, "Pixel");
    assert_eq!(second.device_kind, DeviceKind::KemlockAndroid);
}

#[tokio::test]
async fn a_refused_password_mails_nothing() {
    let mailbox = Arc::new(Mailbox::default());
    let app = App::mailing(true, mailbox.clone());
    let client = app.client();
    let (reply, _) = register(&client, EMAIL, None).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    // A sign-in that never finishes (no OPAQUE proof) leaves no device behind.
    let refused = client
        .post(
            "/kem/v1/auth/opaque/finish",
            json!({
                "email": EMAIL,
                "loginState": "AAAA",
                "finalization": "AAAA",
                "device": {"name": "Test device", "kind": "kemlock-cli"},
            }),
        )
        .await;
    assert_ne!(refused.status, StatusCode::OK);
    mailbox.settle().await;
    assert!(mailbox.notices().is_empty());
}

#[tokio::test]
async fn without_mail_a_first_sign_in_still_works() {
    let app = App::new(true);
    let client = app.client();
    register_and_sign_in(&client, EMAIL).await;
}
