//! Registration with sign-ups closed: an invited address gets in with its token, once, and the
//! console's live settings (the switch, the domain whitelist, the invitation switch) apply to the
//! next request without a restart.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_app::AppError;
use kemlock_app::admin::{InviteGate, InviteTicket};
use kemlock_app::notices::BoxFuture;
use kemlock_app::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_domain::{Email, UserId};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

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

fn gate() -> Arc<OneInvite> {
    Arc::new(OneInvite {
        token: "good-token",
        email: "ada@example.org",
        used: AtomicBool::new(false),
    })
}

/// [`register`] carrying an invitation token in both requests.
async fn register_invited(client: &Client, email: &str, token: &str) -> Reply {
    let (state, request) = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client registration start");
    let started = client
        .post(
            "/kem/v1/accounts/register/start",
            json!({"email": email, "request": b64(&request), "inviteToken": token}),
        )
        .await;
    if started.status != StatusCode::OK {
        return started;
    }
    let response = unb64(started.json()["response"].as_str().expect("response"));
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client registration finish");
    let user = UserId::random();
    client
        .post(
            "/kem/v1/accounts/register/finish",
            json!({
                "userId": user.to_string(),
                "email": email,
                "name": "Ada",
                "upload": b64(&upload),
                "kdf": {"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": b64(&[4u8; 16])},
                "publicBundle": b64(&fakes::bundle(user)),
                "bundleSignature": b64(&fakes::bundle_signature(user)),
                "sealedPrivateKeys": b64(&[0x22u8; 64]),
                "wrappedRootKey": b64(&[0x33u8; WRAPPED_ROOT_KEY_LEN]),
                "inviteToken": token,
            }),
        )
        .await
}

#[tokio::test]
async fn an_invited_address_registers_with_signups_closed_and_the_token_is_used_up() {
    let app = App::new(false);
    app.api.live.set_invites(gate());
    let client = app.client();

    let reply = register_invited(&client, "Ada@Example.org", "good-token").await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // The token is spent: it opens nothing a second time.
    let again = register_invited(&client, "ada@example.org", "good-token").await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert_eq!(again.problem(), "forbidden");
}

#[tokio::test]
async fn a_wrong_token_or_another_address_is_refused() {
    let app = App::new(false);
    app.api.live.set_invites(gate());
    let client = app.client();
    for (email, token) in [
        ("ada@example.org", "wrong-token"),
        ("bob@example.org", "good-token"),
        ("ada@example.org", ""),
    ] {
        let reply = register_invited(&client, email, token).await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "{email} with {token:?}"
        );
    }
    // None of those spent it.
    let reply = register_invited(&client, "ada@example.org", "good-token").await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

#[tokio::test]
async fn invitations_switched_off_refuse_even_a_good_token() {
    let app = App::new(false);
    app.api.live.set_invites(gate());
    app.api.live.set_invitations_allowed(false);
    let reply = register_invited(&app.client(), "ada@example.org", "good-token").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_token_is_not_needed_while_signups_are_open_and_a_bad_one_does_no_harm() {
    let app = App::new(true);
    app.api.live.set_invites(gate());
    let reply = register_invited(&app.client(), "bob@example.org", "stale-token").await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

#[tokio::test]
async fn the_signups_switch_applies_to_the_next_request() {
    let app = App::new(false);
    let client = app.client();
    let (closed, _) = register(&client, "sam@example.org", None).await;
    assert_eq!(closed.status, StatusCode::FORBIDDEN);
    assert_eq!(
        client.get("/kem/v1/config").await.json()["signupsAllowed"],
        false
    );

    app.api.live.set_signups_allowed(true);
    assert_eq!(
        client.get("/kem/v1/config").await.json()["signupsAllowed"],
        true
    );
    let (open, _) = register(&client, "sam@example.org", None).await;
    assert_eq!(open.status, StatusCode::CREATED, "{:?}", open.json());

    app.api.live.set_signups_allowed(false);
    let (closed, _) = register(&client, "kim@example.org", None).await;
    assert_eq!(closed.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_domain_whitelist_opens_its_domains_and_closes_the_rest() {
    let app = App::new(false);
    app.api.live.set_signup_domains(["example.org"]);
    let client = app.client();
    let (inside, _) = register(&client, "sam@example.org", None).await;
    assert_eq!(inside.status, StatusCode::CREATED, "{:?}", inside.json());
    let (outside, _) = register(&client, "eve@elsewhere.test", None).await;
    assert_eq!(outside.status, StatusCode::FORBIDDEN);

    // With sign-ups on as well, the whitelist still keeps other domains out.
    app.api.live.set_signups_allowed(true);
    let (outside, _) = register(&client, "eve@elsewhere.test", None).await;
    assert_eq!(outside.status, StatusCode::FORBIDDEN);
}
