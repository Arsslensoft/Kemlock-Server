//! Every sign-in attempt on the Kemlock API writes a sign-in log row through the privacy port,
//! with the client's address (the store cuts it to its /24 or /48 on write; the fake does the
//! same), success or failure, and the account and device when the attempt names them.

mod common;

use axum::http::StatusCode;
use common::*;
use kemlock_domain::privacy::SignInOutcome;
use serde_json::json;
use std::net::SocketAddr;

/// Both OPAQUE login messages for `email` with `password`, from `peer`; the reply to the finish.
async fn sign_in_from(client: &Client, email: &str, password: &[u8], peer: SocketAddr) -> Reply {
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(password).expect("client login start");
    let started = client
        .send(
            "POST",
            "/kem/v1/auth/opaque/start",
            Req {
                body: Some(json!({"email": email, "request": b64(&request)})),
                peer: Some(peer),
                ..Req::default()
            },
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let started = started.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let finalization = match kemlock_crypto::opaque::client_login_finish(state, password, &response)
    {
        Ok((finalization, _, _)) => finalization,
        // A wrong password can fail on the client side already; send garbage then.
        Err(_) => vec![7u8; 64],
    };
    client
        .send(
            "POST",
            "/kem/v1/auth/opaque/finish",
            Req {
                body: Some(json!({
                    "email": email,
                    "loginState": started["loginState"],
                    "finalization": b64(&finalization),
                    "device": test_device(),
                })),
                peer: Some(peer),
                ..Req::default()
            },
        )
        .await
}

fn from(address: &str) -> SocketAddr {
    SocketAddr::new(address.parse().expect("an address"), 40_000)
}

#[tokio::test]
async fn a_password_sign_in_is_logged_with_its_account_device_and_truncated_address() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;

    let reply = sign_in_from(&client, "sam@example.org", &PASSWORD, from("203.0.113.77")).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let session = Session::from_tokens(&reply.json()["tokens"]);

    let rows = app.store.sign_ins();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.method, "password");
    assert_eq!(row.outcome, SignInOutcome::Success);
    assert_eq!(row.user.map(|u| u.to_string()), Some(session.user_id));
    assert_eq!(row.device.map(|d| d.to_string()), Some(session.device_id));
    assert_eq!(row.ip.as_deref(), Some("203.0.113.0/24"));
}

#[tokio::test]
async fn an_ipv6_client_is_logged_at_its_48() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;

    let reply = sign_in_from(
        &client,
        "sam@example.org",
        &PASSWORD,
        from("2001:db8:1:2::7"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());

    let rows = app.store.sign_ins();
    assert_eq!(rows[0].ip.as_deref(), Some("2001:db8:1::/48"));
}

#[tokio::test]
async fn a_wrong_password_is_logged_as_a_failure_without_an_account() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;

    let reply = sign_in_from(&client, "sam@example.org", &[9u8; 32], from("198.51.100.4")).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{:?}", reply.json());

    let rows = app.store.sign_ins();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].method, "password");
    assert_eq!(rows[0].outcome, SignInOutcome::Failure);
    assert_eq!(
        rows[0].user, None,
        "a failed password proves nothing about who"
    );
    assert_eq!(rows[0].device, None);
    assert_eq!(rows[0].ip.as_deref(), Some("198.51.100.0/24"));
}

#[tokio::test]
async fn a_refresh_is_logged_and_so_is_a_refused_one() {
    let app = App::new(true);
    let client = app.client();
    let first = register_and_sign_in(&client, "sam@example.org").await;
    let before = app.store.sign_ins().len();

    let ok = client
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": first.refresh_token}),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    // The first token is spent: using it again is a reuse, which ends the session.
    let again = client
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": first.refresh_token}),
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{:?}", again.json());

    let rows = app.store.sign_ins();
    let refreshes: Vec<_> = rows[before..].iter().collect();
    assert_eq!(refreshes.len(), 2, "{rows:?}");
    assert!(refreshes.iter().all(|r| r.method == "refresh"));
    assert_eq!(refreshes[0].outcome, SignInOutcome::Success);
    assert_eq!(refreshes[1].outcome, SignInOutcome::Failure);
}

#[tokio::test]
async fn a_malformed_request_is_not_an_attempt() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;

    let reply = client
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "not-a-grant", "refreshToken": "x"}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());
    assert!(app.store.sign_ins().is_empty());
}

#[tokio::test]
async fn sign_in_answers_that_the_account_is_being_deleted_while_its_erasure_is_pending() {
    let app = App::new(true);
    let client = app.client();
    register(&client, "sam@example.org", None).await;
    let sam = app
        .store
        .user_by_email("sam@example.org")
        .expect("the account exists")
        .id;
    app.store.set_erasure_pending(sam, true);

    let reply = sign_in_from(&client, "sam@example.org", &PASSWORD, from("203.0.113.5")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{:?}", reply.json());
    assert_eq!(reply.problem(), "account-being-deleted");
    let rows = app.store.sign_ins();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].outcome, SignInOutcome::Failure);

    // A wrong password is told nothing about it.
    let wrong = sign_in_from(&client, "sam@example.org", &[9u8; 32], from("203.0.113.5")).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());

    // Once an admin cancels the deletion the account signs in again.
    app.store.set_erasure_pending(sam, false);
    let again = sign_in_from(&client, "sam@example.org", &PASSWORD, from("203.0.113.5")).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
}
