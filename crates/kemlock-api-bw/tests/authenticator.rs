//! Authenticator apps as Bitwarden's second step (provider 0): the web vault's three routes, the
//! verification token between them, and the token endpoint taking the code afterwards. The rules
//! are Vaultwarden 1.37.5's `api/core/two_factor/authenticator.rs` and `auth/two_factor.rs`.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_crypto::totp;
use serde_json::{Value, json};
use time::Duration;

const EMAIL: &str = "ada@example.com";
const ENABLE: &str = "/api/two-factor/authenticator";
const GET: &str = "/api/two-factor/get-authenticator";

fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {text}"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).expect("a byte"));
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

fn unix(h: &Harness) -> u64 {
    u64::try_from(h.env.time().unix_timestamp()).expect("a time")
}

async fn call(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    h.json(method, path, Some(token), Some(body)).await
}

/// `get-authenticator` with the password: the answer.
async fn get_authenticator(h: &Harness, token: &str) -> Value {
    let (status, body) = call(h, "POST", GET, token, json!({"masterPasswordHash": HASH})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn enable_body(key: &str, code: Value, verification: &Value) -> Value {
    json!({"key": key, "token": code, "userVerificationToken": verification})
}

fn disable_body(key: &str, verification: &Value) -> Value {
    json!({"key": key, "userVerificationToken": verification})
}

#[tokio::test]
async fn the_authenticator_is_turned_on_with_a_code_and_then_asked_for_at_sign_in() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;

    let offered = get_authenticator(&h, &token).await;
    assert_eq!(offered["authenticator"]["enabled"], false);
    let key = offered["authenticator"]["key"]
        .as_str()
        .expect("a key")
        .to_owned();
    assert_eq!(key.len(), 32, "20 bytes in base32: {key}");
    let verification = offered["userVerificationToken"].clone();
    assert!(verification.is_string(), "{offered}");
    // Nothing is stored until a code proves the key was kept.
    let second = get_authenticator(&h, &token).await;
    assert_eq!(second["authenticator"]["enabled"], false);

    let secret = base32_decode(&key);
    let code = totp::code_at(&secret, unix(&h));

    // A wrong code is the server's own message, with its time and the peer.
    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!("000000"), &verification),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["message"].as_str().expect("a message");
    assert!(
        message.starts_with("Invalid TOTP code! Server time: 2026-11-21 12:00:00 UTC IP: "),
        "{body}"
    );
    // A key the token wasn't made for is refused before the key is read at all.
    for other in ["MZXW6YTBOI======", "not base32"] {
        let (status, body) = call(
            &h,
            "PUT",
            ENABLE,
            &token,
            enable_body(other, json!(code), &verification),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["message"], "Invalid verification token: Invalid key");
    }

    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!(code), &verification),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"authenticator": {"enabled": true, "key": key}})
    );
    let on = get_authenticator(&h, &token).await;
    assert_eq!(on["authenticator"], json!({"enabled": true, "key": key}));
    // The token from before it was on says the method was off, so it can't enable it twice, and
    // POST is PUT.
    let (_, body) = call(
        &h,
        "POST",
        ENABLE,
        &token,
        enable_body(&key, json!(code), &verification),
    )
    .await;
    assert_eq!(body["message"], "Invalid verification token: Invalid state");

    // The token endpoint now asks for the second step. The code that turned it on is spent in
    // Vaultwarden, and the next period's is taken.
    let (status, body) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    h.env.advance(Duration::seconds(30));
    let next = totp::code_at(&secret, unix(&h));
    let mut fields = Harness::password_fields(EMAIL, HASH);
    fields.push(("twoFactorProvider", "0"));
    fields.push(("twoFactorToken", next.as_str()));
    let (status, body) = h.token(&fields).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn turning_it_off_takes_the_key_and_a_token_that_says_it_is_on() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let offered = get_authenticator(&h, &token).await;
    let key = offered["authenticator"]["key"]
        .as_str()
        .expect("a key")
        .to_owned();
    let secret = base32_decode(&key);
    // The code goes in as a number, as the web vault's field sends it, so one with a leading zero
    // (which a number can't hold) waits for the next period's.
    let mut code = totp::code_at(&secret, unix(&h));
    while code.starts_with('0') {
        h.env.advance(Duration::seconds(30));
        code = totp::code_at(&secret, unix(&h));
    }
    let number = code.parse::<u64>().expect("digits");
    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!(number), &offered["userVerificationToken"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let on = get_authenticator(&h, &token).await;
    // The token from before it was on is the wrong state.
    let (_, body) = call(
        &h,
        "DELETE",
        ENABLE,
        &token,
        disable_body(&key, &offered["userVerificationToken"]),
    )
    .await;
    assert_eq!(body["message"], "Invalid verification token: Invalid state");
    // Another key is refused before anything is read.
    let (_, body) = call(
        &h,
        "DELETE",
        ENABLE,
        &token,
        disable_body("MZXW6YTBOI======", &on["userVerificationToken"]),
    )
    .await;
    assert_eq!(body["message"], "Invalid verification token: Invalid key");

    let (status, body) = call(
        &h,
        "DELETE",
        ENABLE,
        &token,
        disable_body(&key, &on["userVerificationToken"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let off = get_authenticator(&h, &token).await;
    assert_eq!(off["authenticator"]["enabled"], false);
    let (status, body) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(status, StatusCode::OK, "no second step any more: {body}");
}

#[tokio::test]
async fn the_password_is_the_only_proof_and_a_missing_one_is_named() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let cases = [
        (json!({"masterPasswordHash": "wrong"}), "Invalid password"),
        (json!({}), "No validation provided"),
        (
            json!({"masterPasswordHash": HASH, "otp": "123456"}),
            "No validation provided",
        ),
        (
            json!({"otp": "123456"}),
            "Protected action token not found, try sending the code again or restart the process",
        ),
    ];
    for (body, message) in cases {
        let (status, reply) = call(&h, "POST", GET, &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
        assert_eq!(reply["message"], message);
    }
    // Capitalised, as the older clients send it.
    let (status, reply) = call(&h, "POST", GET, &token, json!({"MasterPasswordHash": HASH})).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    // No bearer token, no answer.
    let body = Some(json!({"masterPasswordHash": HASH}));
    let (status, _) = h.json("POST", GET, None, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_spent_code_at_enable_time_is_refused_and_leaves_the_method_on() {
    // Vaultwarden's `validate_totp_code` checks `last_used` at enable time as at sign-in, and a
    // refusal changes nothing: an account that is on stays on, with its key.
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;
    let offered = get_authenticator(&h, &token).await;
    let key = offered["authenticator"]["key"]
        .as_str()
        .expect("a key")
        .to_owned();
    let secret = base32_decode(&key);
    let code = totp::code_at(&secret, unix(&h));
    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!(code), &offered["userVerificationToken"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The method is on now, so a fresh token says so, and the same code is the same time step.
    let on = get_authenticator(&h, &token).await;
    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!(code), &on["userVerificationToken"]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .starts_with("Invalid TOTP code! Server time: 2026-11-21 12:00:00 UTC IP: "),
        "{body}"
    );
    let still = get_authenticator(&h, &token).await;
    assert_eq!(
        still["authenticator"],
        json!({"enabled": true, "key": key}),
        "a refused code doesn't turn the method off"
    );

    // The next period's code is taken.
    h.env.advance(Duration::seconds(30));
    let next = totp::code_at(&secret, unix(&h));
    let (status, body) = call(
        &h,
        "PUT",
        ENABLE,
        &token,
        enable_body(&key, json!(next), &still["userVerificationToken"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
