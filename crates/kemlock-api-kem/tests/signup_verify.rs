//! "Verify the email of a new account" through the router: a new account is held until the link
//! mailed to its address is opened, and nothing changes while the setting is off.

mod common;

use axum::http::StatusCode;
use common::{App, Client, Reply, Req, register, register_and_sign_in, sign_in_reply, test_device};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_app::ports::{Clock, UserRepo};
use kemlock_domain::UserId;
use serde_json::json;
use std::sync::{Arc, Mutex};
use time::Duration;

const EMAIL: &str = "sam@example.org";

/// The mail the server sent.
#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<Notice>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("the lock").push(notice);
        })
    }
}

impl Mailbox {
    /// The tokens of the links mailed to `to`, oldest first.
    fn tokens(&self, to: &str) -> Vec<String> {
        self.0
            .lock()
            .expect("the lock")
            .iter()
            .filter_map(|notice| match notice {
                Notice::SignupVerify(n) if n.to.as_str() == to => Some(n.token.clone()),
                _ => None,
            })
            .collect()
    }
}

fn app(verify: bool) -> (App, Mailbox) {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    app.api.live.set_signups_verify(verify);
    (app, mailbox)
}

fn link(token: &str) -> String {
    format!("/kem/v1/accounts/confirm-email?token={token}")
}

/// Presses the button of the page the link opens: the token, as the form posts it.
async fn confirm(client: &Client, token: &str) -> Reply {
    client
        .send(
            "POST",
            "/kem/v1/accounts/confirm-email",
            Req {
                raw_body: Some(format!("token={token}").into_bytes()),
                headers: vec![(
                    "content-type",
                    "application/x-www-form-urlencoded".to_owned(),
                )],
                ..Req::default()
            },
        )
        .await
}

#[tokio::test]
async fn an_account_made_while_verifying_signs_in_only_after_its_link_is_opened() {
    let (app, mailbox) = app(true);
    let client = app.client();

    let (made, _user) = register(&client, EMAIL, None).await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    assert_eq!(made.json()["emailConfirmationRequired"], true);
    let tokens = mailbox.tokens(EMAIL);
    assert_eq!(tokens.len(), 1, "one link was mailed");

    // The right password isn't enough until the address is confirmed.
    let refused = sign_in_reply(&client, EMAIL, test_device()).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json());
    assert_eq!(refused.problem(), "email-not-confirmed");

    // A link that isn't ours opens nothing.
    let bad = confirm(&client, "not-a-token").await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        sign_in_reply(&client, EMAIL, test_device()).await.status,
        StatusCode::FORBIDDEN
    );

    // The link confirms the address, once.
    let opened = confirm(&client, &tokens[0]).await;
    assert_eq!(opened.status, StatusCode::OK);
    assert_eq!(opened.header("referrer-policy"), Some("no-referrer"));
    assert!(
        opened
            .header("content-type")
            .is_some_and(|t| t.starts_with("text/html"))
    );
    let again = confirm(&client, &tokens[0]).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);

    let signed = sign_in_reply(&client, EMAIL, test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    assert_eq!(signed.json()["status"], "signed_in");
}

#[tokio::test]
async fn nothing_changes_while_the_setting_is_off() {
    let (app, mailbox) = app(false);
    let client = app.client();
    let (made, _user) = register(&client, EMAIL, None).await;
    assert_eq!(made.status, StatusCode::CREATED);
    // Not even a field the answer didn't have before.
    let json = made.json();
    assert_eq!(json.as_object().map(|o| o.len()), Some(2), "{json}");
    assert!(mailbox.tokens(EMAIL).is_empty());
    let signed = sign_in_reply(&client, EMAIL, test_device()).await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}

#[tokio::test]
async fn a_token_of_an_account_held_after_signing_in_stops_working() {
    let (app, _mailbox) = app(false);
    let client = app.client();
    let session = register_and_sign_in(&client, EMAIL).await;
    let ok = client
        .get_authed("/kem/v1/devices", &session.access_token)
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());

    let user = UserId(session.user_id.parse().expect("a user id"));
    let now = app.crypto.now();
    app.store
        .hold_unconfirmed(user, [5; 32], now, now + Duration::hours(1))
        .await
        .expect("held");
    // With the setting off a hold does nothing; turned on, it refuses the token.
    let released = client
        .get_authed("/kem/v1/devices", &session.access_token)
        .await;
    assert_eq!(released.status, StatusCode::OK, "{:?}", released.json());
    app.api.live.set_signups_verify(true);
    let held = client
        .get_authed("/kem/v1/devices", &session.access_token)
        .await;
    assert_eq!(held.status, StatusCode::FORBIDDEN, "{:?}", held.json());
    assert_eq!(held.problem(), "email-not-confirmed");
    app.api.live.set_signups_verify(false);
    let freed = client
        .get_authed("/kem/v1/devices", &session.access_token)
        .await;
    assert_eq!(freed.status, StatusCode::OK, "{:?}", freed.json());
}

#[tokio::test]
async fn a_new_link_is_mailed_on_asking_and_only_when_one_is_due() {
    let (app, mailbox) = app(true);
    let client = app.client();
    let (made, _user) = register(&client, EMAIL, None).await;
    assert_eq!(made.status, StatusCode::CREATED);
    assert_eq!(mailbox.tokens(EMAIL).len(), 1);

    let ask = |email: &'static str| client.post("/kem/v1/accounts/confirm-email/resend", json!({"email": email}));
    // Too soon: the answer is the same, and nothing is sent.
    assert_eq!(ask(EMAIL).await.status, StatusCode::ACCEPTED);
    assert_eq!(mailbox.tokens(EMAIL).len(), 1);
    // An address with no account gets the same answer and no mail.
    assert_eq!(ask("nobody@example.org").await.status, StatusCode::ACCEPTED);
    assert!(mailbox.tokens("nobody@example.org").is_empty());

    app.clock.advance(Duration::minutes(6));
    assert_eq!(ask(EMAIL).await.status, StatusCode::ACCEPTED);
    let tokens = mailbox.tokens(EMAIL);
    assert_eq!(tokens.len(), 2);

    // The new link replaced the old one.
    assert_eq!(
        confirm(&client, &tokens[0]).await.status,
        StatusCode::BAD_REQUEST
    );

    // A sign-in with the right password, once another link is due, mails one too.
    app.clock.advance(Duration::minutes(6));
    let refused = sign_in_reply(&client, EMAIL, test_device()).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json());
    let tokens = mailbox.tokens(EMAIL);
    assert_eq!(tokens.len(), 3);
    assert_eq!(confirm(&client, &tokens[2]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_link_runs_out_after_a_day() {
    let (app, mailbox) = app(true);
    let client = app.client();
    let (made, _user) = register(&client, EMAIL, None).await;
    assert_eq!(made.status, StatusCode::CREATED);
    let token = mailbox.tokens(EMAIL).remove(0);
    app.clock.advance(Duration::hours(25));
    assert_eq!(confirm(&client, &token).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn opening_the_link_changes_nothing_until_the_button_is_pressed() {
    let (app, mailbox) = app(true);
    let client = app.client();
    let (made, _user) = register(&client, EMAIL, None).await;
    assert_eq!(made.status, StatusCode::CREATED);
    let token = mailbox.tokens(EMAIL).remove(0);

    // A mail scanner or a link preview fetches the link, more than once: it gets the page and
    // spends nothing.
    for _ in 0..3 {
        let page = client.get(&link(&token)).await;
        assert_eq!(page.status, StatusCode::OK);
        let text = String::from_utf8_lossy(&page.body).into_owned();
        assert!(text.contains("method=\"post\""), "{text}");
        assert!(text.contains(&token), "the button carries the token");
        assert!(
            page.header("content-security-policy")
                .is_some_and(|csp| csp.contains("form-action 'self'"))
        );
    }
    assert_eq!(
        sign_in_reply(&client, EMAIL, test_device()).await.status,
        StatusCode::FORBIDDEN,
        "still held"
    );

    // Pressing the button confirms it, once.
    let pressed = confirm(&client, &token).await;
    assert_eq!(pressed.status, StatusCode::OK);
    assert!(
        pressed
            .header("content-security-policy")
            .is_some_and(|csp| csp.contains("form-action 'none'"))
    );
    assert_eq!(confirm(&client, &token).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        sign_in_reply(&client, EMAIL, test_device()).await.status,
        StatusCode::OK
    );

    // A token that is no token never reaches the page's markup.
    let odd = client
        .get("/kem/v1/accounts/confirm-email?token=%22%3E%3Cscript%3E")
        .await;
    assert_eq!(odd.status, StatusCode::BAD_REQUEST);
}
