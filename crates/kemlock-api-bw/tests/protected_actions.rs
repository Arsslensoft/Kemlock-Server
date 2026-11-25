//! Protected actions on the Bitwarden API: `POST /api/accounts/request-otp` mails a one-time code,
//! and the calls that take `masterPasswordHash` take that code as `otp`, with Vaultwarden 1.37.5's
//! expiry, attempts and messages.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_api_bw::TwoStepParts;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::two_step::{NoDuo, NoYubico, TwoStepSettings};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use time::Duration;

const EMAIL: &str = "ada@example.com";
const NOT_FOUND: &str =
    "Protected action token not found, try sending the code again or restart the process";

/// The protected-action codes the mail sender was asked to send: address and code.
#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<(String, String)>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::ProtectedAction(code) = notice {
                self.0
                    .lock()
                    .expect("the mailbox lock")
                    .push((code.to.as_str().to_owned(), code.code.clone()));
            }
        })
    }
}

impl Mailbox {
    fn count(&self) -> usize {
        self.0.lock().expect("the mailbox lock").len()
    }

    fn last(&self) -> (String, String) {
        self.0
            .lock()
            .expect("the mailbox lock")
            .last()
            .cloned()
            .expect("a code was mailed")
    }
}

async fn harness(mail: bool) -> (Harness, Mailbox) {
    let mailbox = Mailbox::default();
    let h = Harness::with_two_step(
        TwoStepParts {
            settings: TwoStepSettings {
                email_enabled: mail,
                ..TwoStepSettings::default()
            },
            notices: Notices::with_outbox(Arc::new(mailbox.clone())),
            yubico: Arc::new(NoYubico),
            duo: Arc::new(NoDuo),
        },
        false,
    )
    .await;
    (h, mailbox)
}

async fn post(h: &Harness, token: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    h.json("POST", path, Some(token), body).await
}

#[tokio::test]
async fn a_server_that_cannot_mail_refuses_to_send_a_code() {
    let (h, mailbox) = harness(false).await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (status, body) = post(&h, &token, "/api/accounts/request-otp", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Email is disabled for this server. Either enable email or login using your master password instead of login via device."
    );
    assert_eq!(mailbox.count(), 0);
    // And no code can have been asked for: Vaultwarden's answer to an `otp` with none.
    let (_, body) = post(
        &h,
        &token,
        "/api/two-factor/get-authenticator",
        Some(json!({"otp": "123456"})),
    )
    .await;
    assert_eq!(body["message"], NOT_FOUND);
    // No bearer token, no code.
    let (status, _) = h
        .json("POST", "/api/accounts/request-otp", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_mailed_code_stands_in_for_the_password_and_the_api_key_uses_it_up() {
    let (h, mailbox) = harness(true).await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (status, _) = post(&h, &token, "/api/accounts/request-otp", None).await;
    assert_eq!(status, StatusCode::OK);
    let (to, code) = mailbox.last();
    assert_eq!(to, EMAIL);
    assert_eq!(code.len(), 6);

    // The get-* calls leave the code good for the next call of the process.
    for path in ["get-authenticator", "get-email", "get-duo"] {
        let (status, body) = post(
            &h,
            &token,
            &format!("/api/two-factor/{path}"),
            Some(json!({"otp": code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert!(body["userVerificationToken"].is_string(), "{path}");
    }
    // Both proofs, or neither, is no proof.
    let (_, body) = post(
        &h,
        &token,
        "/api/two-factor/get-email",
        Some(json!({"otp": code, "masterPasswordHash": HASH})),
    )
    .await;
    assert_eq!(body["message"], "No validation provided");
    let (_, body) = post(&h, &token, "/api/two-factor/get-email", Some(json!({}))).await;
    assert_eq!(body["message"], "No validation provided");

    // The API key acts, so it uses the code up.
    let (status, body) = post(
        &h,
        &token,
        "/api/accounts/api-key",
        Some(json!({"otp": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "apiKey");
    let (_, body) = post(
        &h,
        &token,
        "/api/accounts/api-key",
        Some(json!({"otp": code})),
    )
    .await;
    assert_eq!(body["message"], NOT_FOUND);
}

#[tokio::test]
async fn verify_otp_checks_the_code_once() {
    let (h, mailbox) = harness(true).await;
    let (token, _) = h.signed_in(EMAIL).await;
    let (_, body) = post(
        &h,
        &token,
        "/api/accounts/verify-otp",
        Some(json!({"OTP": "1"})),
    )
    .await;
    assert_eq!(body["message"], NOT_FOUND);

    post(&h, &token, "/api/accounts/request-otp", None).await;
    let (_, code) = mailbox.last();
    let (_, body) = post(
        &h,
        &token,
        "/api/accounts/verify-otp",
        Some(json!({"OTP": "wrong!"})),
    )
    .await;
    assert_eq!(body["message"], "Token is invalid");
    // The key is `OTP` in the web vault and `otp` in other clients.
    let (status, _) = post(
        &h,
        &token,
        "/api/accounts/verify-otp",
        Some(json!({"otp": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = post(
        &h,
        &token,
        "/api/accounts/verify-otp",
        Some(json!({"OTP": code})),
    )
    .await;
    assert_eq!(body["message"], NOT_FOUND, "the code was used up");
}

#[tokio::test]
async fn a_code_has_attempts_and_a_lifetime_and_is_not_resent_within_thirty_seconds() {
    let (h, mailbox) = harness(true).await;
    let (token, _) = h.signed_in(EMAIL).await;
    post(&h, &token, "/api/accounts/request-otp", None).await;
    let (_, code) = mailbox.last();

    // Asking again at once is refused, and sends nothing.
    h.env.advance(Duration::seconds(12));
    let (status, body) = post(&h, &token, "/api/accounts/request-otp", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Please wait 18 seconds before requesting another code."
    );
    assert_eq!(mailbox.count(), 1);

    // Three wrong entries use the code's attempts up; the right one is then refused too.
    for _ in 0..3 {
        let (_, body) = post(
            &h,
            &token,
            "/api/two-factor/get-email",
            Some(json!({"otp": "wrong!"})),
        )
        .await;
        assert_eq!(body["message"], "Token is invalid");
    }
    let (_, body) = post(
        &h,
        &token,
        "/api/two-factor/get-email",
        Some(json!({"otp": code})),
    )
    .await;
    assert_eq!(body["message"], "Token has expired");

    // After thirty seconds a new code replaces it, and that one expires with time.
    h.env.advance(Duration::seconds(18));
    let (status, _) = post(&h, &token, "/api/accounts/request-otp", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mailbox.count(), 2);
    let (_, fresh) = mailbox.last();
    h.env.advance(Duration::seconds(601));
    let (_, body) = post(
        &h,
        &token,
        "/api/two-factor/get-email",
        Some(json!({"otp": fresh})),
    )
    .await;
    assert_eq!(body["message"], "Token has expired");
    let (_, body) = post(
        &h,
        &token,
        "/api/two-factor/get-email",
        Some(json!({"otp": fresh})),
    )
    .await;
    assert_eq!(body["message"], NOT_FOUND, "an expired code is deleted");
}

#[tokio::test]
async fn a_mailed_code_deletes_the_account_and_is_used_up() {
    let (h, mailbox) = harness(true).await;
    let (token, user) = h.signed_in(EMAIL).await;
    let (status, _) = post(&h, &token, "/api/accounts/request-otp", None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, code) = mailbox.last();

    // A wrong code deletes nothing.
    let (status, body) = h
        .json("DELETE", "/api/accounts", Some(&token), Some(json!({"otp": "000000"})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        kemlock_app::ports::UserRepo::by_id(&h.store, user)
            .await
            .expect("the store")
            .is_some(),
        "the account is still there"
    );

    let (status, body) = h
        .json("DELETE", "/api/accounts", Some(&token), Some(json!({"otp": code})))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        kemlock_app::ports::UserRepo::by_id(&h.store, user)
            .await
            .expect("the store")
            .is_none(),
        "the account is erased"
    );
}
