//! Registration with `SIGNUPS_VERIFY` on: the token goes only to the address, and an account is
//! made only with it.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, HASH, Harness, USER_KEY, keys};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Keeps what it is asked to mail.
#[derive(Default)]
struct Mailbox(Mutex<Vec<Notice>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("lock").push(notice);
        })
    }
}

impl Mailbox {
    /// The tokens mailed so far, with the address each went to.
    fn tokens(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .filter_map(|notice| match notice {
                Notice::RegisterVerify(n) => Some((n.to.as_str().to_owned(), n.token.clone())),
                _ => None,
            })
            .collect()
    }
}

async fn ask(h: &Harness, email: &str) -> (StatusCode, Vec<u8>) {
    let (status, _, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[("content-type", "application/json")],
            Body::from(json!({"email": email, "name": "New"}).to_string()),
        )
        .await;
    (status, bytes)
}

async fn finish(h: &Harness, email: &str, token: &str) -> (StatusCode, Value) {
    h.json(
        "POST",
        "/identity/accounts/register/finish",
        None,
        Some(json!({
            "email": email,
            "masterPasswordHash": HASH,
            "kdf": 0, "kdfIterations": 600_000,
            "userSymmetricKey": USER_KEY,
            "keys": {"encryptedPrivateKey": "2.priv|key|mac", "publicKey": "MIIBIjAN"},
            "emailVerificationToken": token
        })),
    )
    .await
}

/// A token for `email` as the server signs it, verified or not.
fn token_for(h: &Harness, email: &str, verified: bool) -> String {
    let now = h.env.time().unix_timestamp();
    keys()
        .encode(&json!({
            "nbf": now,
            "exp": now + 1800,
            "iss": format!("{DOMAIN}|register_verify"),
            "sub": email,
            "name": null,
            "verified": verified,
        }))
        .expect("a token")
}

#[tokio::test]
async fn the_token_goes_to_the_address_and_not_to_whoever_asks() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail_set(mailbox.clone(), |s| s.signups_verify = true).await;

    let (status, body) = ask(&h, "victim@example.com").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty(), "the asker gets no token");
    let mailed = mailbox.tokens();
    assert_eq!(mailed.len(), 1);
    assert_eq!(mailed[0].0, "victim@example.com");

    // A token that was not mailed, made by someone who had none, does not register the address.
    let (status, body) = finish(
        &h,
        "victim@example.com",
        &token_for(&h, "victim@example.com", false),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["message"],
        "Email verification is required: open the link mailed to the address to finish registering"
    );
    let (status, _) = h
        .token(&Harness::password_fields("victim@example.com", HASH))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no account was made");

    // The mailed one does.
    let (status, body) = finish(&h, "victim@example.com", &mailed[0].1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.login("victim@example.com", HASH).await;

    // And the link of the mail is accepted by the clicked check.
    let (status, body) = ask(&h, "other@example.com").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body:?}");
    let other = mailbox.tokens()[1].1.clone();
    let (status, body) = h
        .json(
            "POST",
            "/identity/accounts/register/verification-email-clicked",
            None,
            Some(json!({"email": "other@example.com", "emailVerificationToken": other})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn with_verification_off_the_token_comes_back_as_vaultwarden_does() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail_set(mailbox.clone(), |_| {}).await;
    let (status, bytes) = ask(&h, "new@example.com").await;
    assert_eq!(status, StatusCode::OK);
    let token = String::from_utf8(bytes).expect("a token");
    assert!(mailbox.tokens().is_empty(), "nothing is mailed");
    let (status, body) = finish(&h, "new@example.com", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_server_that_can_not_mail_does_not_ask_for_what_it_can_not_send() {
    // SIGNUPS_VERIFY on, no mailer: nobody could ever register, so it behaves as with it off.
    let h = Harness::with(|s| s.signups_verify = true).await;
    let (status, bytes) = ask(&h, "new@example.com").await;
    assert_eq!(status, StatusCode::OK);
    let token = String::from_utf8(bytes).expect("a token");
    let (status, body) = finish(&h, "new@example.com", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn one_address_is_mailed_a_link_once_in_a_while_and_answers_alike() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail_set(mailbox.clone(), |s| s.signups_verify = true).await;
    for _ in 0..3 {
        let (status, body) = ask(&h, "victim@example.com").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
    }
    assert_eq!(mailbox.tokens().len(), 1, "the address was mailed once");
    // After five minutes it may be mailed again, whatever the case it is written in.
    h.env.advance(time::Duration::minutes(5));
    let (status, _) = ask(&h, "Victim@Example.com").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(mailbox.tokens().len(), 2);
}

#[tokio::test]
async fn one_client_may_ask_for_only_a_few_mails() {
    let mailbox = Arc::new(Mailbox::default());
    let h = Harness::with_mail_set(mailbox.clone(), |s| s.signups_verify = true).await;
    for n in 0..5 {
        let (status, _) = ask(&h, &format!("person{n}@example.com")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, bytes) = ask(&h, "person5@example.com").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        String::from_utf8_lossy(&bytes).contains("Too many requests"),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(mailbox.tokens().len(), 5);
    // A token is given back every five minutes.
    h.env.advance(time::Duration::minutes(5));
    let (status, _) = ask(&h, "person5@example.com").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(mailbox.tokens().len(), 6);
}
