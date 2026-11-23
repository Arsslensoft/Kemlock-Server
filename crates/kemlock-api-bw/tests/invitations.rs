//! Registration on the Bitwarden routes with sign-ups closed: a server invitation token lets its
//! address in, once, and the live sign-ups switch applies to the next request.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{HASH, Harness, USER_KEY};
use kemlock_app::AppError;
use kemlock_app::admin::{InviteGate, InviteTicket, Live};
use kemlock_app::notices::BoxFuture;
use kemlock_domain::Email;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

const REFUSED: &str = "Registration not allowed or user already exists";

/// One invitation: `token` for `email`, good until consumed.
struct OneInvite {
    token: &'static str,
    email: &'static str,
    used: AtomicBool,
}

impl InviteGate for OneInvite {
    fn accept<'a>(
        &'a self,
        token: &'a str,
        email: &'a Email,
    ) -> BoxFuture<'a, Result<InviteTicket, AppError>> {
        let good = token == self.token
            && email.as_str() == self.email
            && !self.used.load(Ordering::SeqCst);
        Box::pin(async move {
            if good {
                Ok(InviteTicket {
                    invite: Uuid::from_u128(1),
                })
            } else {
                Err(AppError::Forbidden)
            }
        })
    }

    fn consume<'a>(&'a self, _ticket: &'a InviteTicket) -> BoxFuture<'a, Result<(), AppError>> {
        self.used.store(true, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

/// A server with sign-ups closed and one invitation: `good-token` for ada.
async fn closed_with_invitation() -> (Harness, Live, Arc<OneInvite>) {
    let live = Live::new(false);
    let gate = Arc::new(OneInvite {
        token: "good-token",
        email: "ada@example.org",
        used: AtomicBool::new(false),
    });
    live.set_invites(gate.clone());
    let shared = live.clone();
    let h = Harness::with(move |s| {
        s.signups_allowed = false;
        s.live = Some(shared);
    })
    .await;
    (h, live, gate)
}

async fn verification(h: &Harness, email: &str, invite: Option<&str>) -> (StatusCode, Value) {
    let mut body = json!({"email": email});
    if let Some(token) = invite {
        body["inviteToken"] = json!(token);
    }
    // Asking for JSON gets the verification token as a JSON string, not as plain text.
    let (status, _, bytes) = h
        .send(
            "POST",
            "/identity/accounts/register/send-verification-email",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            Body::from(body.to_string()),
        )
        .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn finish(
    h: &Harness,
    email: &str,
    token: &str,
    invite: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({
        "email": email,
        "masterPasswordHash": HASH,
        "kdf": 0, "kdfIterations": 600_000,
        "userSymmetricKey": USER_KEY,
        "emailVerificationToken": token
    });
    if let Some(token) = invite {
        body["inviteToken"] = json!(token);
    }
    h.json(
        "POST",
        "/identity/accounts/register/finish",
        None,
        Some(body),
    )
    .await
}

#[tokio::test]
async fn an_invited_address_registers_with_its_token_and_the_token_is_used_up() {
    let (h, _live, gate) = closed_with_invitation().await;
    let (status, token) = verification(&h, "ada@example.org", Some("good-token")).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    let token = token.as_str().expect("a verification token").to_owned();

    let (status, body) = finish(&h, "ada@example.org", &token, Some("good-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        gate.used.load(Ordering::SeqCst),
        "the invitation was consumed"
    );
    // The account can sign in.
    let answer = h.login("ada@example.org", HASH).await;
    assert_eq!(answer["token_type"], "Bearer");

    // The token is spent.
    let (status, body) = verification(&h, "ada@example.org", Some("good-token")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], REFUSED);
}

#[tokio::test]
async fn without_the_token_or_with_a_wrong_one_the_address_is_refused() {
    let (h, _live, gate) = closed_with_invitation().await;
    for (email, invite) in [
        ("ada@example.org", None),
        ("ada@example.org", Some("wrong-token")),
        ("bob@example.org", Some("good-token")),
    ] {
        let (status, body) = verification(&h, email, invite).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{email} with {invite:?}");
        assert_eq!(body["message"], REFUSED);
    }
    assert!(!gate.used.load(Ordering::SeqCst));

    // A verification token alone doesn't finish it: the invitation is checked again.
    let (status, token) = verification(&h, "ada@example.org", Some("good-token")).await;
    assert_eq!(status, StatusCode::OK);
    let token = token.as_str().expect("a verification token").to_owned();
    let (status, body) = finish(&h, "ada@example.org", &token, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], REFUSED);
}

#[tokio::test]
async fn invitations_switched_off_refuse_a_good_token() {
    let (h, live, _gate) = closed_with_invitation().await;
    live.set_invitations_allowed(false);
    let (status, body) = verification(&h, "ada@example.org", Some("good-token")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], REFUSED);
}

#[tokio::test]
async fn the_signups_switch_applies_to_the_next_request() {
    let (h, live, _gate) = closed_with_invitation().await;
    let (status, _) = verification(&h, "sam@example.org", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    live.set_signups_allowed(true);
    let (status, _) = verification(&h, "sam@example.org", None).await;
    assert_eq!(status, StatusCode::OK);

    live.set_signups_allowed(false);
    let (status, _) = verification(&h, "sam@example.org", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
