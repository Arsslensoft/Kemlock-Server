//! The emailed-code, YubiKey and Duo second steps through the router, in-process, with a real DPoP
//! client and a pretend mail sender, Yubico and Duo. The setups are rows written the way the move
//! from Vaultwarden writes them (its JSON, sealed).

mod common;
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, register_and_sign_in, sign_in_reply, test_device};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{TwoStepApiDoc, TwoStepRuntime, two_step_router};
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    Duo, DuoError, DuoKeys, DuoPrompt, PURPOSE_DUO, PURPOSE_EMAIL, PURPOSE_YUBIKEY,
    RecoveryCodeRepo, TwoStepSettings, Yubico, YubicoError,
};
use kemlock_domain::UserId;
use passkey_fakes::FakePasskeys;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use utoipa::OpenApi;

const EMAIL: &str = "sam@example.org";
const OTP: &str = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";

#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<(String, String)>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::TwoStepCode(code) = notice {
                self.0
                    .lock()
                    .expect("the lock")
                    .push((code.to.as_str().to_owned(), code.code.clone()));
            }
        })
    }
}

impl Mailbox {
    fn last(&self) -> (String, String) {
        self.0
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a code was mailed")
    }

    fn count(&self) -> usize {
        self.0.lock().expect("the lock").len()
    }
}

struct FakeYubico;

impl Yubico for FakeYubico {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(async move {
            if otp == OTP {
                Ok(())
            } else {
                Err(YubicoError::Rejected)
            }
        })
    }
}

/// `(username, device, state)` of the prompts started.
type Started = (String, String, String);

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
    fn check_keys<'a>(&'a self, _keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async { Ok(()) })
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
            ));
            Ok(format!(
                "https://{}/oauth/v1/authorize?state={}&client={}",
                prompt.keys.host, prompt.state, prompt.client
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

struct Rig {
    app: App,
    router: Router,
    mailbox: Mailbox,
    duo: FakeDuo,
    calls: AtomicUsize,
}

fn rig() -> Rig {
    let app = App::new(true);
    let mailbox = Mailbox::default();
    let duo = FakeDuo::default();
    let runtime = TwoStepRuntime {
        challenges: FakePasskeys::default(),
        notices: Notices::with_outbox(Arc::new(mailbox.clone())),
        yubico: Arc::new(FakeYubico),
        duo: Arc::new(duo.clone()),
        settings: TwoStepSettings {
            email_enabled: true,
            yubico_enabled: true,
            duo_global: Some(DuoKeys {
                host: "api-global.duosecurity.com".to_owned(),
                ik: "DIGLOBALGLOBALGLOBAL".to_owned(),
                sk: "global-secret-key".to_owned(),
            }),
            ..TwoStepSettings::default()
        },
    };
    let router = app
        .router
        .clone()
        .merge(two_step_router(app.api.clone(), runtime));
    Rig {
        app,
        router,
        mailbox,
        duo,
        calls: AtomicUsize::new(0),
    }
}

impl Rig {
    fn device(&self) -> Client {
        Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        )
    }

    /// One request from an address of its own, so the per-address limits of one test don't add up.
    async fn call(&self, client: &Client, uri: &str, body: Value) -> Reply {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        let peer = SocketAddr::from((
            [
                10,
                2,
                u8::try_from(n / 250).unwrap_or(0),
                u8::try_from(n % 250).unwrap_or(0) + 1,
            ],
            40_000,
        ));
        client
            .send(
                "POST",
                uri,
                Req {
                    body: Some(body),
                    peer: Some(peer),
                    ..Req::default()
                },
            )
            .await
    }

    /// The account, signed in on a first device, with the method set up as the move from
    /// Vaultwarden would have it.
    async fn account_with(&self, method: TwoFactorMethod, purpose: &str, json: &str) -> Session {
        let first = self.device();
        let session = register_and_sign_in(&first, EMAIL).await;
        let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
        self.app
            .store
            .put(&TwoFactor {
                user,
                method,
                sealed_secret: self.app.crypto.seal(purpose, json.as_bytes()),
                enabled: true,
                created_at: self.app.clock.now(),
            })
            .await
            .expect("the row is stored");
        session
    }

    /// A new device that signed in with the password and was asked for its second step: the
    /// device and the challenge.
    async fn asked(&self, methods: Value) -> (Client, Value) {
        let device = self.device();
        let first = sign_in_reply(&device, EMAIL, test_device()).await;
        assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
        let first = first.json();
        assert_eq!(first["status"], "two_factor_required");
        assert_eq!(first["methods"], methods);
        (device, first["challenge"].clone())
    }
}

#[tokio::test]
async fn an_emailed_code_answers_the_second_step() {
    let rig = rig();
    let first = rig
        .account_with(
            TwoFactorMethod::Email,
            PURPOSE_EMAIL,
            r#"{"email":"old.address@example.org","last_token":null,"token_sent":1700000000,"attempts":0}"#,
        )
        .await;
    let (device, challenge) = rig.asked(json!(["email"])).await;

    let sent = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/email/send",
            json!({"challenge": challenge}),
        )
        .await;
    assert_eq!(sent.status, StatusCode::NO_CONTENT);
    let (to, code) = rig.mailbox.last();
    assert_eq!(to, "old.address@example.org");

    // Another device key can't use the challenge, nor a made-up challenge anything.
    let thief = rig.device();
    let stolen = rig
        .call(
            &thief,
            "/kem/v1/auth/two-factor/email",
            json!({"challenge": challenge, "code": code}),
        )
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);

    let wrong = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/email",
            json!({"challenge": challenge, "code": "wrong!"}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());
    let signed = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/email",
            json!({"challenge": challenge, "code": code}),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let second = Session::from_tokens(&signed.json());
    assert_eq!(second.user_id, first.user_id);
    assert_ne!(second.device_id, first.device_id);
    // A code is good once.
    let replay = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/email",
            json!({"challenge": challenge, "code": code}),
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn codes_are_not_mailed_without_limit() {
    let rig = rig();
    rig.account_with(
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"a@b.example","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let (device, challenge) = rig.asked(json!(["email"])).await;
    let mut last = StatusCode::NO_CONTENT;
    for _ in 0..40 {
        last = rig
            .call(
                &device,
                "/kem/v1/auth/two-factor/email/send",
                json!({"challenge": challenge}),
            )
            .await
            .status;
        if last == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(rig.mailbox.count() < 40);
}

#[tokio::test]
async fn a_yubikey_otp_answers_the_second_step() {
    let rig = rig();
    rig.account_with(
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    let (device, challenge) = rig.asked(json!(["yubikey"])).await;
    let refused = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/yubikey",
            json!({"challenge": challenge, "code": OTP.replacen("cccccccccccc", "dddddddddddd", 1)}),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let signed = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/yubikey",
            json!({"challenge": challenge, "code": OTP}),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}

#[tokio::test]
async fn duo_answers_the_second_step_after_a_prompt() {
    let rig = rig();
    // An empty setup, as Vaultwarden keeps for an account on the global integration.
    rig.account_with(TwoFactorMethod::Duo, PURPOSE_DUO, "")
        .await;
    let (device, challenge) = rig.asked(json!(["duo"])).await;

    let bad_client = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/duo/start",
            json!({"challenge": challenge, "client": "evil"}),
        )
        .await;
    assert_eq!(bad_client.status, StatusCode::BAD_REQUEST);

    let started = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/duo/start",
            json!({"challenge": challenge, "client": "desktop"}),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
    let (username, _, state) = rig.duo.last();
    assert_eq!(username, EMAIL);
    assert_eq!(
        started.json()["authUrl"],
        format!(
            "https://api-global.duosecurity.com/oauth/v1/authorize?state={state}&client=desktop"
        )
    );

    let wrong = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/duo",
            json!({"challenge": challenge, "code": "duo-says-yes|another-state", "client": "desktop"}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    // That used the prompt up: start another and answer it.
    rig.call(
        &device,
        "/kem/v1/auth/two-factor/duo/start",
        json!({"challenge": challenge, "client": "desktop"}),
    )
    .await;
    let (_, _, state) = rig.duo.last();
    let signed = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/duo",
            json!({"challenge": challenge, "code": format!("duo-says-yes|{state}"), "client": "desktop"}),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
}

#[tokio::test]
async fn wrong_answers_count_against_the_account_and_slow_it_down() {
    let rig = rig();
    rig.account_with(
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    let (device, challenge) = rig.asked(json!(["yubikey"])).await;
    let wrong = OTP.replacen("cccccccccccc", "dddddddddddd", 1);
    for _ in 0..5 {
        let reply = rig
            .call(
                &device,
                "/kem/v1/auth/two-factor/yubikey",
                json!({"challenge": challenge, "code": wrong}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    // The sixth is turned away before it is looked at, even with the right OTP.
    let blocked = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/yubikey",
            json!({"challenge": challenge, "code": OTP}),
        )
        .await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
}

const LIST: &str = "/kem/v1/account/two-step";

#[tokio::test]
async fn the_account_lists_its_own_second_steps() {
    let rig = rig();
    let device = rig.device();
    let session = register_and_sign_in(&device, EMAIL).await;
    let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));

    // No bearer token, no answer; with one, an account without a second step lists none.
    assert_eq!(device.get(LIST).await.status, StatusCode::UNAUTHORIZED);
    let none = device.get_authed(LIST, &session.access_token).await;
    assert_eq!(none.status, StatusCode::OK, "{:?}", none.json());
    assert_eq!(none.json(), json!({"methods": [], "recoveryCodes": false}));

    // An email step that is on, and a YubiKey that was set up but is off.
    for (method, purpose, enabled, row) in [
        (
            TwoFactorMethod::Email,
            PURPOSE_EMAIL,
            true,
            r#"{"email":"a@b.example","last_token":null,"token_sent":0,"attempts":0}"#,
        ),
        (
            TwoFactorMethod::YubiKey,
            PURPOSE_YUBIKEY,
            false,
            r#"{"keys":["cccccccccccc"],"nfc":false}"#,
        ),
    ] {
        rig.app
            .store
            .put(&TwoFactor {
                user,
                method,
                sealed_secret: rig.app.crypto.seal(purpose, row.as_bytes()),
                enabled,
                created_at: rig.app.clock.now(),
            })
            .await
            .expect("the row is stored");
    }
    let listed = device.get_authed(LIST, &session.access_token).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.json());
    assert_eq!(
        listed.json(),
        json!({
            "methods": [
                {"method": "email", "enabled": true},
                {"method": "yubikey", "enabled": false},
            ],
            "recoveryCodes": false,
        })
    );
    let body = String::from_utf8_lossy(&listed.body).into_owned();
    assert!(!body.contains("a@b.example"), "no secret is listed");

    // The recovery code shows as held, not as its text.
    rig.app
        .store
        .put_recovery_code_if_absent(user, b"sealed", rig.app.clock.now())
        .await
        .expect("the code is stored");
    let held = device.get_authed(LIST, &session.access_token).await;
    assert_eq!(held.json()["recoveryCodes"], true);

    // Another account sees only its own.
    let other_device = rig.device();
    let other = register_and_sign_in(&other_device, "other@example.org").await;
    let theirs = other_device.get_authed(LIST, &other.access_token).await;
    assert_eq!(
        theirs.json(),
        json!({"methods": [], "recoveryCodes": false})
    );
}

#[tokio::test]
async fn the_routes_are_in_the_openapi_document() {
    let doc = serde_json::to_value(TwoStepApiDoc::openapi()).expect("serialises");
    for path in [
        "/kem/v1/auth/two-factor/email/send",
        "/kem/v1/auth/two-factor/duo/start",
        "/kem/v1/auth/two-factor/email",
        "/kem/v1/auth/two-factor/yubikey",
        "/kem/v1/auth/two-factor/duo",
    ] {
        assert!(doc["paths"][path]["post"].is_object(), "{path}");
    }
    assert!(doc["paths"]["/kem/v1/account/two-step"]["get"].is_object());
}
