//! The mail about a device that signs in for the first time, and Vaultwarden's
//! `REQUIRE_DEVICE_EMAIL`.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_domain::DeviceKind;
use kemlock_domain::unlock::truncate_ip;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

/// Keeps what it is asked to mail, or fails every time.
#[derive(Default)]
struct Mailbox {
    sent: Mutex<Vec<Notice>>,
    fail: bool,
}

impl Mailbox {
    fn notices(&self) -> Vec<Notice> {
        self.sent.lock().expect("lock").clone()
    }
}

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.fail {
                self.sent.lock().expect("lock").push(notice);
            }
        })
    }

    fn deliver_checked(&self, notice: Notice) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            if self.fail {
                return Err("the mail server is down".to_owned());
            }
            self.sent.lock().expect("lock").push(notice);
            Ok(())
        })
    }
}

#[tokio::test]
async fn a_first_sign_in_from_a_device_is_mailed_and_the_next_is_not() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), false).await;
    h.account("ada@example.com", HASH).await;

    h.login("ada@example.com", HASH).await;
    let sent = mailbox.notices();
    assert_eq!(sent.len(), 1);
    let Notice::NewDevice(notice) = &sent[0] else {
        panic!("not a new-device notice: {:?}", sent[0]);
    };
    assert_eq!(notice.to.as_str(), "ada@example.com");
    assert_eq!(notice.device_name, "Kemlock");
    assert_eq!(notice.device_kind, DeviceKind::KemlockAndroid);
    assert_eq!(notice.ip, truncate_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert_eq!(notice.at, h.env.time());

    // The same app again is not a new device.
    h.login("ada@example.com", HASH).await;
    assert_eq!(mailbox.notices().len(), 1);

    // Another app is.
    let mut fields = Harness::password_fields("ada@example.com", HASH);
    fields.retain(|(name, _)| *name != "deviceIdentifier");
    fields.push(("deviceIdentifier", "0d3f0c8a-1f64-4a55-9a52-6a7a9f1d2c33"));
    let (status, body) = h.token(&fields).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(mailbox.notices().len(), 2);
}

#[tokio::test]
async fn a_wrong_password_mails_nothing() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), false).await;
    h.account("ada@example.com", HASH).await;
    let (status, _) = h
        .token(&Harness::password_fields("ada@example.com", "not-the-hash"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(mailbox.notices().is_empty());
}

#[tokio::test]
async fn without_mail_a_new_device_signs_in_unannounced() {
    // The default harness has no outbox: nothing to send and nothing to refuse.
    let h = Harness::new().await;
    h.account("ada@example.com", HASH).await;
    h.login("ada@example.com", HASH).await;
}

#[tokio::test]
async fn a_mail_that_fails_is_ignored_unless_the_device_email_is_required() {
    let mailbox = Arc::new(Mailbox {
        fail: true,
        ..Mailbox::default()
    });
    let h = Harness::with_mail(mailbox, false).await;
    h.account("ada@example.com", HASH).await;
    h.login("ada@example.com", HASH).await;
}

#[tokio::test]
async fn a_required_device_email_that_cannot_be_sent_refuses_the_sign_in() {
    let mailbox = Arc::new(Mailbox {
        fail: true,
        ..Mailbox::default()
    });
    let h = Harness::with_mail(mailbox, true).await;
    h.account("ada@example.com", HASH).await;
    let (status, body) = h
        .token(&Harness::password_fields("ada@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains(
            "Could not send login notification email. Please contact your administrator."
        ),
        "{body}"
    );
}

#[tokio::test]
async fn a_required_device_email_that_is_sent_lets_the_sign_in_through() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), true).await;
    h.account("ada@example.com", HASH).await;
    h.login("ada@example.com", HASH).await;
    assert_eq!(mailbox.notices().len(), 1);
}
