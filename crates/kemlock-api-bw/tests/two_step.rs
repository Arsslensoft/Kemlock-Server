//! Emailed codes, Duo and YubiKeys on the Bitwarden API: the setup routes the web vault calls, the
//! second step's 400 and the answers to it, with a pretend mail sender, Yubico and Duo.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{HASH, Harness, SERVER_KEY};
use kemlock_api_bw::TwoStepParts;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    Duo, DuoError, DuoKeys, DuoPrompt, PURPOSE_DUO, PURPOSE_EMAIL, PURPOSE_YUBIKEY,
    TwoStepSettings, Yubico, YubicoError,
};
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::UserId;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const EMAIL: &str = "ada@example.com";
const OTP: &str = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";
const DEVICE: &str = "6a3c5f2e-9d1b-4c7e-8a40-0f9e7d6c5b4a";
const NOTE: &str = "<To use the global Duo keys, please leave these fields untouched>";

#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<(String, String)>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::TwoStepCode(code) = notice {
                self.0
                    .lock()
                    .expect("the mailbox lock")
                    .push((code.to.as_str().to_owned(), code.code.clone()));
            }
        })
    }
}

impl Mailbox {
    fn last(&self) -> (String, String) {
        self.0
            .lock()
            .expect("the mailbox lock")
            .last()
            .cloned()
            .expect("a code was mailed")
    }

    fn count(&self) -> usize {
        self.0.lock().expect("the mailbox lock").len()
    }
}

#[derive(Clone, Default)]
struct FakeYubico(Arc<Mutex<Vec<String>>>);

impl Yubico for FakeYubico {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(async move {
            if self.0.lock().expect("the lock").iter().any(|o| o == otp) {
                Ok(())
            } else {
                Err(YubicoError::Rejected)
            }
        })
    }
}

/// A prompt as Duo was asked to start it: the username, the device, the state and the host.
type Started = (String, String, String, String);

#[derive(Clone, Default)]
struct FakeDuo(Arc<Mutex<Vec<Started>>>);

impl FakeDuo {
    fn last(&self) -> Started {
        self.0
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a prompt was started")
    }
}

impl Duo for FakeDuo {
    fn check_keys<'a>(&'a self, keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async move {
            if keys.host.contains("bad") {
                Err(DuoError::Rejected)
            } else {
                Ok(())
            }
        })
    }

    fn auth_url<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
    ) -> BoxFuture<'a, Result<String, DuoError>> {
        Box::pin(async move {
            self.0.lock().expect("the lock").push((
                prompt.username.to_owned(),
                prompt.device.to_owned(),
                prompt.state.to_owned(),
                prompt.keys.host.clone(),
            ));
            Ok(format!(
                "https://{}/oauth/v1/authorize?state={}",
                prompt.keys.host, prompt.state
            ))
        })
    }

    fn verify<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
        code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async move {
            let known = self
                .0
                .lock()
                .expect("the lock")
                .iter()
                .any(|p| p.0 == prompt.username && p.1 == prompt.device && p.2 == prompt.state);
            if known && code == "duo-says-yes" {
                Ok(())
            } else {
                Err(DuoError::Rejected)
            }
        })
    }
}

fn global_duo() -> DuoKeys {
    DuoKeys {
        host: "api-global.duosecurity.com".to_owned(),
        ik: "DIGLOBALGLOBALGLOBAL".to_owned(),
        sk: "global-secret-key".to_owned(),
    }
}

struct Fx {
    h: Harness,
    mailbox: Mailbox,
    yubico: FakeYubico,
    duo: FakeDuo,
}

impl Fx {
    async fn with(settings: TwoStepSettings) -> Self {
        let mailbox = Mailbox::default();
        let yubico = FakeYubico::default();
        let duo = FakeDuo::default();
        let h = Harness::with_two_step(
            TwoStepParts {
                settings,
                notices: Notices::with_outbox(Arc::new(mailbox.clone())),
                yubico: Arc::new(yubico.clone()),
                duo: Arc::new(duo.clone()),
            },
            false,
        )
        .await;
        Fx {
            h,
            mailbox,
            yubico,
            duo,
        }
    }

    /// A server with every method on.
    async fn new() -> Self {
        Fx::with(TwoStepSettings {
            email_enabled: true,
            yubico_enabled: true,
            duo_global: Some(global_duo()),
            ..TwoStepSettings::default()
        })
        .await
    }

    /// A row as the move from Vaultwarden writes it: its JSON, sealed.
    async fn imported(&self, user: UserId, method: TwoFactorMethod, purpose: &str, json: &str) {
        TwoFactorRepo::put(
            &self.h.store,
            &TwoFactor {
                user,
                method,
                sealed_secret: ServerSeal::new(&SERVER_KEY).seal(purpose, json.as_bytes()),
                enabled: true,
                created_at: self.h.env.time(),
            },
        )
        .await
        .expect("the row is stored");
    }

    async fn post(&self, token: &str, path: &str, body: Value) -> (StatusCode, Value) {
        self.h
            .json(
                "POST",
                &format!("/api/two-factor/{path}"),
                Some(token),
                Some(body),
            )
            .await
    }

    /// The password sign-in a client makes before it has a code.
    async fn first_step(&self) -> (StatusCode, Value) {
        self.h.token(&Harness::password_fields(EMAIL, HASH)).await
    }

    /// The sign-in with a provider's answer.
    async fn second_step(&self, provider: &str, code: &str) -> (StatusCode, Value) {
        let mut fields = Harness::password_fields(EMAIL, HASH);
        fields.push(("twoFactorProvider", provider));
        fields.push(("twoFactorToken", code));
        self.h.token(&fields).await
    }
}

// ---------------------------------------------------------------------------------------------
// Email.

#[tokio::test]
async fn email_is_set_up_with_the_web_vaults_calls_and_answers_the_second_step() {
    let fx = Fx::new().await;
    let (token, _) = fx.h.signed_in(EMAIL).await;

    let (status, body) = fx
        .post(&token, "get-email", json!({"masterPasswordHash": "wrong"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid password");
    let (status, body) = fx
        .post(&token, "get-email", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email"], json!({"enabled": false, "email": null}));
    let verification = body["userVerificationToken"]
        .as_str()
        .expect("a token")
        .to_owned();

    // A code goes to the address; a wrong one is refused, the right one turns the method on.
    let (status, body) = fx
        .post(
            &token,
            "send-email",
            json!({"email": "mfa@example.com", "userVerificationToken": verification}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({}));
    let (to, code) = fx.mailbox.last();
    assert_eq!(to, "mfa@example.com");
    let (status, body) = fx
        .h
        .json(
            "PUT",
            "/api/two-factor/email",
            Some(&token),
            Some(json!({"email": "mfa@example.com", "token": "wrong!", "userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Token is invalid");
    let (status, body) = fx
        .h
        .json(
            "PUT",
            "/api/two-factor/email",
            Some(&token),
            Some(json!({"email": "mfa@example.com", "token": code, "userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The list and the method's own page show it.
    let (status, body) =
        fx.h.json("GET", "/api/two-factor", Some(&token), None)
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "data": [{"enabled": true, "type": 1, "object": "twoFactorProvider"}],
            "object": "list",
            "continuationToken": null,
        })
    );
    let (_, body) = fx
        .post(&token, "get-email", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(
        body["email"],
        json!({"enabled": true, "email": "mfa@example.com"})
    );

    // Signing in now asks for the code, with the address hidden.
    let (status, body) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "Two factor required.");
    assert_eq!(body["TwoFactorProviders"], json!(["1"]));
    assert_eq!(
        body["TwoFactorProviders2"],
        json!({"1": {"Email": "***@example.com"}})
    );
    let before = fx.mailbox.count();
    let (status, body) =
        fx.h.json(
            "POST",
            "/api/two-factor/send-email-login",
            None,
            Some(json!({"email": EMAIL, "masterPasswordHash": HASH, "deviceIdentifier": DEVICE})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.mailbox.count(), before + 1);
    let (to, code) = fx.mailbox.last();
    assert_eq!(to, "mfa@example.com");

    let (status, body) = fx.second_step("1", "wrong!").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .starts_with("Token is invalid! IP: "),
        "{body}"
    );
    let (status, body) = fx.second_step("1", &code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    // A code is good once.
    let (status, _) = fx.second_step("1", &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Taking the method off lets the password alone in again.
    let (status, _) =
        fx.h.json(
            "DELETE",
            "/api/two-factor/email",
            Some(&token),
            Some(json!({"userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = fx.first_step().await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_routes_that_change_a_method_need_the_token_the_password_check_hands_out() {
    let fx = Fx::new().await;
    let (token, _) = fx.h.signed_in(EMAIL).await;
    let (status, body) = fx
        .post(
            &token,
            "send-email",
            json!({"email": "mfa@example.com", "userVerificationToken": "not a token"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid user verification token");
    assert_eq!(fx.mailbox.count(), 0);
    let (status, _) =
        fx.h.json(
            "DELETE",
            "/api/two-factor/yubikey",
            Some(&token),
            Some(json!({"userVerificationToken": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // And a call with no bearer token is refused outright.
    let (status, _) =
        fx.h.json(
            "POST",
            "/api/two-factor/get-duo",
            None,
            Some(json!({"masterPasswordHash": HASH})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn send_email_login_follows_vaultwardens_checks() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    let ask = |hash: Value| {
        let fx = &fx;
        async move {
            fx.h.json(
                "POST",
                "/api/two-factor/send-email-login",
                None,
                Some(json!({"email": EMAIL, "masterPasswordHash": hash})),
            )
            .await
        }
    };
    // No email method yet.
    let (status, body) = ask(json!(HASH)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Two factor not found");
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old@example.com","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let (status, body) = ask(json!("wrong")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "Username or password is incorrect. Try again"
    );
    let (status, bytes) = {
        let (status, _, bytes) =
            fx.h.send(
                "POST",
                "/api/two-factor/send-email-login",
                &[("content-type", "application/json")],
                Body::from(json!({"email": EMAIL, "masterPasswordHash": HASH}).to_string()),
            )
            .await;
        (status, bytes)
    };
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    assert_eq!(fx.mailbox.last().0, "old@example.com");
}

#[tokio::test]
async fn a_server_that_cannot_mail_offers_no_email_codes() {
    let fx = Fx::with(TwoStepSettings::default()).await;
    let (token, user) = fx.h.signed_in(EMAIL).await;
    let (status, body) = fx
        .post(&token, "get-email", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let verification = body["userVerificationToken"].as_str().expect("a token");
    let (status, body) = fx
        .post(
            &token,
            "send-email",
            json!({"email": "mfa@example.com", "userVerificationToken": verification}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "email codes are not enabled on this server"
    );
    // An account moved from Vaultwarden with an email method can't be let in without it, nor
    // asked for a code that could never arrive.
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old@example.com","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let (status, body) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "No enabled and usable two factor providers are available for this account"
    );
}

// ---------------------------------------------------------------------------------------------
// YubiKey.

#[tokio::test]
async fn a_yubikey_is_registered_and_answers_the_second_step() {
    let fx = Fx::new().await;
    fx.yubico.0.lock().expect("the lock").push(OTP.to_owned());
    let (token, _) = fx.h.signed_in(EMAIL).await;

    let (status, body) = fx
        .post(&token, "get-yubikey", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["yubiKey"], json!({"enabled": false}));
    let verification = body["userVerificationToken"]
        .as_str()
        .expect("a token")
        .to_owned();

    // An OTP Yubico doesn't know, then the real one.
    let (status, body) = fx
        .post(
            &token,
            "yubikey",
            json!({"key1": "eeeeeeeeeeeekhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv", "key2": "", "nfc": false, "userVerificationToken": verification}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid Yubikey OTP provided");
    let (status, body) = fx
        .h
        .json(
            "PUT",
            "/api/two-factor/yubikey",
            Some(&token),
            Some(json!({"key1": OTP, "key2": "ffffffffffff", "nfc": true, "userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"yubiKey": {"Key1": "cccccccccccc", "Key2": "ffffffffffff", "enabled": true, "nfc": true}})
    );
    let (_, body) = fx
        .post(&token, "get-yubikey", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(body["yubiKey"]["Key1"], "cccccccccccc");
    assert_eq!(body["yubiKey"]["enabled"], true);

    let (status, body) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["3"]));
    assert_eq!(body["TwoFactorProviders2"], json!({"3": {"Nfc": true}}));
    // A key that isn't registered, a short OTP, the right one.
    let other = OTP.replacen("cccccccccccc", "dddddddddddd", 1);
    fx.yubico.0.lock().expect("the lock").push(other.clone());
    for wrong in [other.as_str(), "short"] {
        let (status, _) = fx.second_step("3", wrong).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{wrong}");
    }
    let (status, body) = fx.second_step("3", OTP).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _) =
        fx.h.json(
            "DELETE",
            "/api/two-factor/yubikey",
            Some(&token),
            Some(json!({"userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = fx.first_step().await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn yubikeys_need_yubico_set_up() {
    let fx = Fx::with(TwoStepSettings::default()).await;
    let (token, _) = fx.h.signed_in(EMAIL).await;
    let (status, body) = fx
        .post(&token, "get-yubikey", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Yubico support is disabled");
}

#[tokio::test]
async fn a_key_is_required_to_register_yubikeys() {
    let fx = Fx::new().await;
    let (token, _) = fx.h.signed_in(EMAIL).await;
    let (_, body) = fx
        .post(&token, "get-yubikey", json!({"masterPasswordHash": HASH}))
        .await;
    let verification = body["userVerificationToken"].as_str().expect("a token");
    let (status, body) = fx
        .post(
            &token,
            "yubikey",
            json!({"nfc": false, "userVerificationToken": verification}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "A key is required.");
}

// ---------------------------------------------------------------------------------------------
// Duo.

#[tokio::test]
async fn duo_uses_the_servers_keys_and_answers_the_second_step() {
    let fx = Fx::new().await;
    let (token, _) = fx.h.signed_in(EMAIL).await;

    let (status, body) = fx
        .post(&token, "get-duo", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["duo"],
        json!({"enabled": false, "host": NOTE, "clientSecret": NOTE, "clientId": NOTE})
    );
    let verification = body["userVerificationToken"]
        .as_str()
        .expect("a token")
        .to_owned();

    // The fields left alone mean the global integration.
    let (status, body) = fx
        .post(
            &token,
            "duo",
            json!({"host": NOTE, "clientSecret": NOTE, "clientId": NOTE, "userVerificationToken": verification}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"duo": {"enabled": true, "host": "<global_secret>", "clientSecret": "<global_secret>", "clientId": "<global_secret>"}})
    );

    // Signing in asks for a prompt: the 400 carries Duo's address.
    let (status, body) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["2"]));
    let (username, device, state, host) = fx.duo.last();
    assert_eq!(username, EMAIL);
    assert_eq!(device, DEVICE);
    assert_eq!(host, "api-global.duosecurity.com");
    assert_eq!(
        body["TwoFactorProviders2"],
        json!({"2": {"AuthUrl": format!("https://api-global.duosecurity.com/oauth/v1/authorize?state={state}")}})
    );
    // Duo's answer is `<code>|<state>`.
    let (status, body) = fx.second_step("2", "duo-says-yes|another-state").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Error validating duo authentication");
    // That used the prompt up: the 400 above did not start another, so ask again.
    let (status, _) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, _, state, _) = fx.duo.last();
    let (status, body) = fx.second_step("2", &format!("duo-says-yes|{state}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_account_saves_its_own_duo_keys_after_duo_checks_them() {
    let fx = Fx::new().await;
    let (token, _) = fx.h.signed_in(EMAIL).await;
    let (_, body) = fx
        .post(&token, "get-duo", json!({"masterPasswordHash": HASH}))
        .await;
    let verification = body["userVerificationToken"]
        .as_str()
        .expect("a token")
        .to_owned();
    let own = |host: &str| json!({"host": host, "clientSecret": "own-secret-key", "clientId": "DIOWNOWNOWNOWNOWNOWN", "userVerificationToken": verification});
    let (status, body) = fx.post(&token, "duo", own("api-bad.duosecurity.com")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Failed to validate Duo credentials");
    let (status, body) =
        fx.h.json(
            "PUT",
            "/api/two-factor/duo",
            Some(&token),
            Some(own("api-own.duosecurity.com")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"duo": {"enabled": true, "host": "api-************", "clientSecret": "own-************", "clientId": "DIOW************"}})
    );
    let (_, body) = fx
        .post(&token, "get-duo", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(body["duo"]["enabled"], true);
    assert_eq!(body["duo"]["host"], "api-************");

    let (status, _) =
        fx.h.json(
            "DELETE",
            "/api/two-factor/duo",
            Some(&token),
            Some(json!({"userVerificationToken": verification})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = fx
        .post(&token, "get-duo", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(body["duo"]["enabled"], false);
}

#[tokio::test]
async fn duo_without_keys_anywhere_shows_nothing() {
    let fx = Fx::with(TwoStepSettings::default()).await;
    let (token, _) = fx.h.signed_in(EMAIL).await;
    let (status, body) = fx
        .post(&token, "get-duo", json!({"masterPasswordHash": HASH}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["duo"],
        json!({"enabled": false, "host": null, "clientSecret": null, "clientId": null})
    );
}

// ---------------------------------------------------------------------------------------------
// Accounts moved from Vaultwarden, and the providers together.

#[tokio::test]
async fn an_account_moved_with_every_method_lists_them_all_and_signs_in_with_each() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    fx.yubico.0.lock().expect("the lock").push(OTP.to_owned());
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old.address@example.com","last_token":null,"token_sent":1700000000,"attempts":0}"#,
    )
    .await;
    fx.imported(
        user,
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    // Vaultwarden keeps an empty string for an account on the global Duo integration.
    fx.imported(user, TwoFactorMethod::Duo, PURPOSE_DUO, "")
        .await;

    let (status, body) = fx.first_step().await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["1", "2", "3"]));
    let options = &body["TwoFactorProviders2"];
    assert_eq!(options["1"], json!({"Email": "ol*********@example.com"}));
    assert_eq!(options["3"], json!({"Nfc": false}));
    assert!(
        options["2"]["AuthUrl"]
            .as_str()
            .expect("an address")
            .starts_with("https://api-global.duosecurity.com/")
    );

    // The old YubiKey, then the old email address, then Duo: each answers.
    let (status, body) = fx.second_step("3", OTP).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    fx.h.json(
        "POST",
        "/api/two-factor/send-email-login",
        None,
        Some(json!({"email": EMAIL, "masterPasswordHash": HASH})),
    )
    .await;
    let (to, code) = fx.mailbox.last();
    assert_eq!(to, "old.address@example.com");
    let (status, body) = fx.second_step("1", &code).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, _) = fx.first_step().await;
    let (_, _, state, _) = fx.duo.last();
    let (status, body) = fx.second_step("2", &format!("duo-says-yes|{state}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The list the web vault shows has all three, in Bitwarden's order.
    let (status, answer) = fx.second_step("3", OTP).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let token = answer["access_token"].as_str().expect("a token").to_owned();
    let (_, body) =
        fx.h.json("GET", "/api/two-factor", Some(&token), None)
            .await;
    assert_eq!(
        body["data"],
        json!([
            {"enabled": true, "type": 1, "object": "twoFactorProvider"},
            {"enabled": true, "type": 2, "object": "twoFactorProvider"},
            {"enabled": true, "type": 3, "object": "twoFactorProvider"},
        ])
    );
}

#[tokio::test]
async fn a_provider_the_account_does_not_have_is_answered_with_the_choices() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    fx.imported(
        user,
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    let (status, body) = fx.second_step("1", "123456").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "Two factor required.");
    assert_eq!(body["TwoFactorProviders"], json!(["3"]));
    // Remember (5) and recovery (8) are special: they are looked at, not offered. A provider that
    // is not one of those and not on the account is simply asked again.
    let (status, body) = fx.second_step("2", "x|y").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["TwoFactorProviders"], json!(["3"]));
}

#[tokio::test]
async fn send_email_login_answers_alike_for_no_account_no_hash_and_a_wrong_hash() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old@example.com","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let ask = |email: &'static str, body: Value| {
        let fx = &fx;
        async move {
            let mut full = json!({"email": email});
            full.as_object_mut()
                .expect("an object")
                .extend(body.as_object().expect("an object").clone());
            fx.h.json("POST", "/api/two-factor/send-email-login", None, Some(full))
                .await
        }
    };
    let answers = [
        ask("nobody@example.com", json!({"masterPasswordHash": HASH})).await,
        ask(EMAIL, json!({})).await,
        ask(EMAIL, json!({"masterPasswordHash": "wrong"})).await,
    ];
    for (status, body) in &answers {
        assert_eq!(*status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["message"],
            "Username or password is incorrect. Try again"
        );
    }
    assert_eq!(fx.mailbox.count(), 0, "nothing was mailed");
}

#[tokio::test]
async fn an_account_may_ask_for_five_emailed_codes_in_a_window() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old@example.com","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let ask = || async {
        fx.h.json(
            "POST",
            "/api/two-factor/send-email-login",
            None,
            Some(json!({"email": EMAIL, "masterPasswordHash": HASH})),
        )
        .await
    };
    for _ in 0..5 {
        let (status, body) = ask().await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = ask().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["message"], "Too many login requests");
    // The window runs out.
    fx.h.env.advance(time::Duration::minutes(16));
    let (status, body) = ask().await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_stranger_asking_for_emailed_codes_with_a_wrong_hash_does_not_use_up_the_owners_mails() {
    let fx = Fx::new().await;
    let user = fx.h.account(EMAIL, HASH).await;
    fx.imported(
        user,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old@example.com","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let ask = |hash: &'static str| {
        let fx = &fx;
        async move {
            fx.h.json(
                "POST",
                "/api/two-factor/send-email-login",
                None,
                Some(json!({"email": EMAIL, "masterPasswordHash": hash})),
            )
            .await
        }
    };
    for _ in 0..8 {
        let (status, body) = ask("wrong").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["message"],
            "Username or password is incorrect. Try again"
        );
    }
    let (status, body) = ask(HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
