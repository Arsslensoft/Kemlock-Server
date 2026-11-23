//! The two-step recovery code on the Bitwarden API, as Vaultwarden 1.37.5 has it: made when an
//! account first turns a method on, shown by `POST /api/two-factor/get-recover`, and entered as
//! provider 8 at sign-in, which switches every method off.

mod common;

use axum::http::StatusCode;
use common::{HASH, Harness};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_crypto::totp;
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";

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

/// Turns the authenticator on through the web vault's two calls, and returns its secret.
async fn turn_on_authenticator(h: &Harness, token: &str) -> Vec<u8> {
    let (_, offered) = h
        .json(
            "POST",
            "/api/two-factor/get-authenticator",
            Some(token),
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    let key = offered["authenticator"]["key"]
        .as_str()
        .expect("a key")
        .to_owned();
    let secret = base32_decode(&key);
    let code = totp::code_at(
        &secret,
        u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
    );
    let (status, body) = h
        .json(
            "PUT",
            "/api/two-factor/authenticator",
            Some(token),
            Some(json!({
                "key": key,
                "token": code,
                "userVerificationToken": offered["userVerificationToken"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    secret
}

async fn get_recover(h: &Harness, token: &str, body: Value) -> (StatusCode, Value) {
    h.json(
        "POST",
        "/api/two-factor/get-recover",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn the_first_second_step_makes_a_recovery_code_the_password_shows() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;

    // No second step yet, so no code.
    let (status, body) = get_recover(&h, &token, json!({"masterPasswordHash": HASH})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"code": null, "object": "twoFactorRecover"}));
    let (status, body) = get_recover(&h, &token, json!({"masterPasswordHash": "wrong"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (_, body) = get_recover(&h, &token, json!({})).await;
    assert_eq!(body["message"], "No validation provided");

    turn_on_authenticator(&h, &token).await;
    let (status, body) = get_recover(&h, &token, json!({"MasterPasswordHash": HASH})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "twoFactorRecover");
    let code = body["code"].as_str().expect("a code").to_owned();
    assert_eq!(code.len(), 32, "20 bytes in base32: {code}");
    assert!(
        code.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "{code}"
    );
    // Asking again shows the same code.
    let (_, again) = get_recover(&h, &token, json!({"masterPasswordHash": HASH})).await;
    assert_eq!(again["code"], code.as_str());
}

#[tokio::test]
async fn the_recovery_code_signs_in_switches_every_method_off_and_is_spent() {
    let h = Harness::new().await;
    let (token, _) = h.signed_in(EMAIL).await;
    turn_on_authenticator(&h, &token).await;
    let (_, shown) = get_recover(&h, &token, json!({"masterPasswordHash": HASH})).await;
    let code = shown["code"].as_str().expect("a code").to_owned();

    let with = |provider: &'static str, token: String| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields(EMAIL, HASH);
            f.push(("twoFactorProvider", provider));
            f.push(("twoFactorToken", token.as_str()));
            h.token(&f).await
        }
    };
    // The password alone is asked for a second step; a wrong recovery code changes nothing.
    let (status, body) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    let (status, body) = with("8", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Two-step token is invalid. Try again.");
    let (_, listed) = h.json("GET", "/api/two-factor", Some(&token), None).await;
    assert_eq!(listed["data"].as_array().map(Vec::len), Some(1));

    // Spaces and case don't matter.
    let typed = format!("{} {}", code[..10].to_lowercase(), &code[10..]);
    let (status, body) = with("8", typed).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let recovered = body["access_token"].as_str().expect("a token").to_owned();
    let (_, listed) = h
        .json("GET", "/api/two-factor", Some(&recovered), None)
        .await;
    assert_eq!(listed["data"], json!([]), "every method is off");
    let (_, profile) = h
        .json("GET", "/api/accounts/profile", Some(&recovered), None)
        .await;
    assert_eq!(profile["twoFactorEnabled"], false);

    // The code is spent: there is none to show, and the password alone signs in.
    let (_, gone) = get_recover(&h, &recovered, json!({"masterPasswordHash": HASH})).await;
    assert_eq!(gone["code"], Value::Null);
    let (status, _) = h.token(&Harness::password_fields(EMAIL, HASH)).await;
    assert_eq!(status, StatusCode::OK);

    // The next method the account turns on makes a new code.
    h.env.advance(time::Duration::seconds(60));
    turn_on_authenticator(&h, &recovered).await;
    let (_, fresh) = get_recover(&h, &recovered, json!({"masterPasswordHash": HASH})).await;
    let fresh = fresh["code"].as_str().expect("a new code");
    assert_ne!(fresh, code);
}

/// Keeps what it is asked to mail.
#[derive(Default)]
struct Mailbox(std::sync::Mutex<Vec<Notice>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("lock").push(notice);
        })
    }
}

#[tokio::test]
async fn the_recovery_code_ends_remembered_devices_and_mails_the_owner() {
    let mailbox = std::sync::Arc::new(Mailbox::default());
    let h = Harness::with_mail(mailbox.clone(), false).await;
    let (token, _) = h.signed_in(EMAIL).await;
    let secret = turn_on_authenticator(&h, &token).await;
    let (_, shown) = get_recover(&h, &token, json!({"masterPasswordHash": HASH})).await;
    let code = shown["code"].as_str().expect("a code").to_owned();

    // The authenticator's code, with "remember this device".
    h.env.advance(time::Duration::seconds(60));
    let with = |provider: &'static str, token: String, remember: &'static str| {
        let h = &h;
        async move {
            let mut f = Harness::password_fields(EMAIL, HASH);
            f.push(("twoFactorProvider", provider));
            f.push(("twoFactorToken", token.as_str()));
            f.push(("twoFactorRemember", remember));
            h.token(&f).await
        }
    };
    let now = u64::try_from(h.env.time().unix_timestamp()).expect("a time");
    let (status, body) = with("0", totp::code_at(&secret, now), "1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let remember = body["TwoFactorToken"]
        .as_str()
        .expect("a remember token")
        .to_owned();
    let recoveries = || {
        mailbox
            .0
            .lock()
            .expect("lock")
            .iter()
            .filter(|n| matches!(n, Notice::TwoStepRecovered(_)))
            .count()
    };
    assert_eq!(recoveries(), 0);

    // Recovering switches the methods off and tells the owner.
    let (status, body) = with("8", code, "0").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(recoveries(), 1);
    let notice = mailbox
        .0
        .lock()
        .expect("lock")
        .iter()
        .find_map(|n| match n {
            Notice::TwoStepRecovered(r) => Some(r.clone()),
            _ => None,
        })
        .expect("a recovery notice");
    assert_eq!(notice.to.as_str(), EMAIL);
    assert_eq!(notice.at, h.env.time());

    // The account turns two-step login on again: the token from before the recovery is no good.
    let recovered = body["access_token"].as_str().expect("a token").to_owned();
    h.env.advance(time::Duration::seconds(60));
    turn_on_authenticator(&h, &recovered).await;
    let (status, body) = with("5", remember, "0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
}
