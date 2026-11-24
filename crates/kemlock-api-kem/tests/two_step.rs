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

/// What was mailed: setup and sign-in codes, proofs for turning a step off, and the notices that a
/// step changed (method, on).
#[derive(Clone, Default)]
struct Mailbox(
    Arc<Mutex<Vec<(String, String)>>>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<(&'static str, bool)>>>,
);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            match notice {
                Notice::TwoStepCode(code) => self
                    .0
                    .lock()
                    .expect("the lock")
                    .push((code.to.as_str().to_owned(), code.code.clone())),
                Notice::ProtectedAction(p) => self.1.lock().expect("the lock").push(p.code.clone()),
                Notice::TwoStepChanged(c) => {
                    self.2.lock().expect("the lock").push((c.method, c.on));
                }
                _ => {}
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

    fn last_proof(&self) -> String {
        self.1
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a proof was mailed")
    }

    fn changes(&self) -> Vec<(&'static str, bool)> {
        self.2.lock().expect("the lock").clone()
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
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
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

// ---------------------------------------------------------------------------------------------
// Setting a second step up, and turning it off, from a signed-in device.

const FACTOR: &str = "/kem/v1/account/two-factor";
const SETUP: &str = "/kem/v1/account/two-step/setup";

impl Rig {
    /// A signed-in call from an address of its own.
    async fn authed(
        &self,
        client: &Client,
        method: &str,
        uri: &str,
        token: &str,
        body: Option<Value>,
    ) -> Reply {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        let peer = SocketAddr::from((
            [
                10,
                3,
                u8::try_from(n / 250).unwrap_or(0),
                u8::try_from(n % 250).unwrap_or(0) + 1,
            ],
            40_000,
        ));
        client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(token),
                    body,
                    peer: Some(peer),
                    ..Req::default()
                },
            )
            .await
    }

    /// An account with no second step, signed in.
    async fn plain(&self) -> (Client, Session) {
        let device = self.device();
        let session = register_and_sign_in(&device, EMAIL).await;
        (device, session)
    }

    fn actions(&self) -> Vec<&'static str> {
        self.app.store.events().iter().map(|e| e.action).collect()
    }
}

#[tokio::test]
async fn the_setup_read_says_what_is_set_up_and_what_the_server_offers() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    assert_eq!(device.get(SETUP).await.status, StatusCode::UNAUTHORIZED);
    let shown = rig
        .authed(&device, "GET", SETUP, &session.access_token, None)
        .await;
    assert_eq!(shown.status, StatusCode::OK, "{:?}", shown.json());
    assert_eq!(
        shown.json(),
        json!({
            "email": null, "yubikey": null, "duo": null,
            "emailOffered": true, "yubikeyOffered": true, "duoServerKeys": true,
        })
    );
}

#[tokio::test]
async fn an_emailed_code_is_set_up_with_the_code_and_turned_off_only_with_a_proof() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let uri = format!("{FACTOR}/email");
    let confirm = format!("{uri}/confirm");

    // A wrong code does not turn it on.
    let begun = rig
        .authed(
            &device,
            "POST",
            &uri,
            token,
            Some(json!({"address": "mfa@example.org"})),
        )
        .await;
    assert_eq!(begun.status, StatusCode::NO_CONTENT);
    let wrong = rig
        .authed(
            &device,
            "POST",
            &confirm,
            token,
            Some(json!({"address": "mfa@example.org", "code": "nope"})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let (_, code) = rig.mailbox.last();
    let confirmed = rig
        .authed(
            &device,
            "POST",
            &confirm,
            token,
            Some(json!({"address": "mfa@example.org", "code": code})),
        )
        .await;
    assert_eq!(
        confirmed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        confirmed.json()
    );
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], "mfa@example.org");
    assert_eq!(rig.mailbox.changes(), vec![("email", true)]);
    assert!(rig.actions().contains(&"account.two_step_added"));

    // It can not be re-pointed while it is on, nor turned off with a session alone.
    let repoint = rig
        .authed(
            &device,
            "POST",
            &uri,
            token,
            Some(json!({"address": "thief@example.org"})),
        )
        .await;
    assert_eq!(repoint.status, StatusCode::CONFLICT);
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(
        shown.json()["email"],
        "mfa@example.org",
        "the live row is untouched"
    );
    let bare = rig.authed(&device, "DELETE", &uri, token, None).await;
    assert!(
        bare.status.is_client_error(),
        "no proof, no removal: {:?}",
        bare.status
    );
    let guess = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": "123456"})),
        )
        .await;
    assert_eq!(guess.status, StatusCode::BAD_REQUEST);
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], "mfa@example.org");

    // With the mailed code it goes, once.
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.json());
    let proof = rig.mailbox.last_proof();
    let off = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": proof})),
        )
        .await;
    assert_eq!(off.status, StatusCode::NO_CONTENT, "{:?}", off.json());
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], Value::Null);
    assert_eq!(
        rig.mailbox.changes(),
        vec![("email", true), ("email", false)]
    );
    assert!(rig.actions().contains(&"account.two_step_removed"));
    let again = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": proof})),
        )
        .await;
    assert_eq!(
        again.status,
        StatusCode::BAD_REQUEST,
        "a proof is good once"
    );
}

#[tokio::test]
async fn a_second_step_beside_another_needs_a_proof_and_a_method_is_not_replaced() {
    let rig = rig();
    rig.account_with(
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    // Another device of the same account: the password, then the YubiKey.
    let (device, challenge) = rig.asked(json!(["yubikey"])).await;
    let signed = rig
        .call(
            &device,
            "/kem/v1/auth/two-factor/yubikey",
            json!({"challenge": challenge, "code": OTP}),
        )
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let session = Session::from_tokens(&signed.json());
    let token = session.access_token.as_str();
    // Duo is a second method: without a proof it is refused; the YubiKey method is on, so
    // replacing it is refused (409) even with one.
    for (method, uri, body, status) in [
        (
            "PUT",
            format!("{FACTOR}/duo"),
            json!({}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "PUT",
            format!("{FACTOR}/yubikey"),
            json!({"otps": [OTP]}),
            StatusCode::CONFLICT,
        ),
    ] {
        let refused = rig.authed(&device, method, &uri, token, Some(body)).await;
        assert_eq!(
            refused.status,
            status,
            "{method} {uri}: {:?}",
            refused.json()
        );
    }
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(
        shown.json()["yubikey"]["keys"],
        json!(["cccccccccccc"]),
        "replacing was refused"
    );
    assert_eq!(shown.json()["duo"], Value::Null, "no Duo without a proof");
}

#[tokio::test]
async fn the_emailed_code_needs_a_proof_when_another_step_came_on_in_between() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let begun = rig
        .authed(
            &device,
            "POST",
            &format!("{FACTOR}/email"),
            token,
            Some(json!({"address": "mfa@example.org"})),
        )
        .await;
    assert_eq!(begun.status, StatusCode::NO_CONTENT);
    let (_, code) = rig.mailbox.last();
    let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
    rig.app
        .store
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::YubiKey,
            sealed_secret: rig
                .app
                .crypto
                .seal(PURPOSE_YUBIKEY, br#"{"keys":["cccccccccccc"],"nfc":false}"#),
            enabled: true,
            created_at: rig.app.clock.now(),
        })
        .await
        .expect("the row is stored");
    let confirmed = rig
        .authed(
            &device,
            "POST",
            &format!("{FACTOR}/email/confirm"),
            token,
            Some(json!({"address": "mfa@example.org", "code": code})),
        )
        .await;
    assert_eq!(
        confirmed.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        confirmed.json()
    );
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], Value::Null);
}

#[tokio::test]
async fn at_most_five_setup_codes_are_mailed_in_a_while() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let uri = format!("{FACTOR}/email");
    for n in 0..5 {
        let begun = rig
            .authed(
                &device,
                "POST",
                &uri,
                &session.access_token,
                Some(json!({"address": "mfa@example.org"})),
            )
            .await;
        assert_eq!(begun.status, StatusCode::NO_CONTENT, "code {n}");
    }
    let sixth = rig
        .authed(
            &device,
            "POST",
            &uri,
            &session.access_token,
            Some(json!({"address": "mfa@example.org"})),
        )
        .await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rig.mailbox.count(), 5);
}

#[tokio::test]
async fn yubikeys_are_checked_with_yubico_and_removed_only_with_a_proof() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let uri = format!("{FACTOR}/yubikey");

    let rejected = rig
        .authed(
            &device,
            "PUT",
            &uri,
            token,
            Some(json!({"otps": ["x".repeat(44)]})),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    let set = rig
        .authed(
            &device,
            "PUT",
            &uri,
            token,
            Some(json!({"otps": [OTP], "nfc": true})),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.json());
    assert_eq!(set.json(), json!({"keys": [&OTP[..12]], "nfc": true}));
    assert_eq!(rig.mailbox.changes(), vec![("yubikey", true)]);

    let bare = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": "000000"})),
        )
        .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST);
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT);
    let off = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": rig.mailbox.last_proof()})),
        )
        .await;
    assert_eq!(off.status, StatusCode::NO_CONTENT, "{:?}", off.json());
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["yubikey"], Value::Null);
}

#[tokio::test]
async fn duo_keys_must_be_on_duos_own_api_host_and_are_removed_only_with_a_proof() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let uri = format!("{FACTOR}/duo");

    for host in [
        "evil.example",
        "api-x.duosecurity.com.evil.example",
        "127.0.0.1",
        "api-.duosecurity.com",
    ] {
        let refused = rig
            .authed(
                &device,
                "PUT",
                &uri,
                token,
                Some(json!({"host": host, "clientId": "DIXX", "clientSecret": "sekret"})),
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{host}");
    }
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(
        shown.json()["duo"],
        Value::Null,
        "a refused host sets nothing up"
    );

    let own = rig
        .authed(
            &device,
            "PUT",
            &uri,
            token,
            Some(json!({
                "host": "api-1234abcd.duosecurity.com",
                "clientId": "DIXX",
                "clientSecret": "sekret",
            })),
        )
        .await;
    assert_eq!(own.status, StatusCode::OK, "{:?}", own.json());
    assert_eq!(
        own.json(),
        json!({"integration": "own", "host": "api-1234abcd.duosecurity.com"})
    );
    let body = String::from_utf8_lossy(&own.body).into_owned();
    assert!(!body.contains("sekret"), "the secret is not echoed");

    let bare = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": "000000"})),
        )
        .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST);
    rig.authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    let off = rig
        .authed(
            &device,
            "DELETE",
            &uri,
            token,
            Some(json!({"proof": rig.mailbox.last_proof()})),
        )
        .await;
    assert_eq!(off.status, StatusCode::NO_CONTENT, "{:?}", off.json());
    assert_eq!(rig.mailbox.changes(), vec![("duo", true), ("duo", false)]);
}

#[tokio::test]
async fn the_new_routes_are_in_the_openapi_document() {
    let doc = serde_json::to_value(TwoStepApiDoc::openapi()).expect("serialises");
    for (path, method) in [
        ("/kem/v1/account/two-step/setup", "get"),
        ("/kem/v1/account/two-factor/proof", "post"),
        ("/kem/v1/account/two-factor/email", "post"),
        ("/kem/v1/account/two-factor/email", "delete"),
        ("/kem/v1/account/two-factor/email/confirm", "post"),
        ("/kem/v1/account/two-factor/yubikey", "put"),
        ("/kem/v1/account/two-factor/yubikey", "delete"),
        ("/kem/v1/account/two-factor/duo", "put"),
        ("/kem/v1/account/two-factor/duo", "delete"),
    ] {
        assert!(doc["paths"][path][method].is_object(), "{method} {path}");
    }
}

#[tokio::test]
async fn a_second_step_is_added_beside_another_after_a_fresh_proof_that_works_once() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
    // A YubiKey is on already.
    rig.app
        .store
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::YubiKey,
            sealed_secret: rig
                .app
                .crypto
                .seal(PURPOSE_YUBIKEY, br#"{"keys":["cccccccccccc"],"nfc":false}"#),
            enabled: true,
            created_at: rig.app.clock.now(),
        })
        .await
        .expect("the row is stored");

    // Mailing the first code turns nothing on, so it needs no proof.
    let begun = rig
        .authed(
            &device,
            "POST",
            &format!("{FACTOR}/email"),
            token,
            Some(json!({"address": "mfa@example.org"})),
        )
        .await;
    assert_eq!(begun.status, StatusCode::NO_CONTENT, "{:?}", begun.json());
    let (_, code) = rig.mailbox.last();
    let confirm = format!("{FACTOR}/email/confirm");
    let body = |proof: Option<&str>| match proof {
        Some(proof) => json!({"address": "mfa@example.org", "code": code, "proof": proof}),
        None => json!({"address": "mfa@example.org", "code": code}),
    };

    // No proof, and a wrong one: refused, and nothing is on.
    let bare = rig
        .authed(&device, "POST", &confirm, token, Some(body(None)))
        .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST, "{:?}", bare.json());
    let wrong = rig
        .authed(&device, "POST", &confirm, token, Some(body(Some("000000"))))
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{:?}", wrong.json());
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], Value::Null);
    assert!(rig.mailbox.changes().is_empty());

    // The mailed proof adds it.
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.json());
    let proof = rig.mailbox.last_proof();
    let added = rig
        .authed(&device, "POST", &confirm, token, Some(body(Some(&proof))))
        .await;
    assert_eq!(added.status, StatusCode::NO_CONTENT, "{:?}", added.json());
    let shown = rig.authed(&device, "GET", SETUP, token, None).await;
    assert_eq!(shown.json()["email"], "mfa@example.org");
    assert_eq!(shown.json()["yubikey"]["keys"], json!(["cccccccccccc"]));
    assert_eq!(rig.mailbox.changes(), vec![("email", true)]);
    assert!(rig.actions().contains(&"account.two_step_added"));

    // The proof is spent: it adds nothing else (Duo here), and a missing one is refused too.
    let duo = format!("{FACTOR}/duo");
    let replayed = rig
        .authed(&device, "PUT", &duo, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        replayed.json()
    );
    // A fresh one adds Duo (the server's keys) beside both.
    rig.app.clock.advance(time::Duration::seconds(31));
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT);
    let added = rig
        .authed(
            &device,
            "PUT",
            &duo,
            token,
            Some(json!({"proof": rig.mailbox.last_proof()})),
        )
        .await;
    assert_eq!(added.status, StatusCode::OK, "{:?}", added.json());
    assert_eq!(rig.mailbox.changes(), vec![("email", true), ("duo", true)]);

    // A method that is on is not replaced, proof or not: remove it first.
    rig.app.clock.advance(time::Duration::seconds(31));
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT);
    let replaced = rig
        .authed(
            &device,
            "PUT",
            &format!("{FACTOR}/yubikey"),
            token,
            Some(json!({"otps": [OTP], "proof": rig.mailbox.last_proof()})),
        )
        .await;
    assert_eq!(
        replaced.status,
        StatusCode::CONFLICT,
        "{:?}",
        replaced.json()
    );
}

#[tokio::test]
async fn a_request_that_fails_its_own_checks_does_not_spend_the_proof() {
    let rig = rig();
    let (device, session) = rig.plain().await;
    let token = session.access_token.as_str();
    let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
    rig.app
        .store
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::YubiKey,
            sealed_secret: rig
                .app
                .crypto
                .seal(PURPOSE_YUBIKEY, br#"{"keys":["cccccccccccc"],"nfc":false}"#),
            enabled: true,
            created_at: rig.app.clock.now(),
        })
        .await
        .expect("the row is stored");
    let asked = rig
        .authed(&device, "POST", &format!("{FACTOR}/proof"), token, None)
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT);
    let proof = rig.mailbox.last_proof();

    // Duo keys off Duo's own host fail before the proof is looked at; so does a wrong setup code.
    let duo = format!("{FACTOR}/duo");
    let bad = rig
        .authed(
            &device,
            "PUT",
            &duo,
            token,
            Some(json!({
                "host": "evil.example", "clientId": "DIX", "clientSecret": "s", "proof": proof
            })),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{:?}", bad.json());
    let begun = rig
        .authed(
            &device,
            "POST",
            &format!("{FACTOR}/email"),
            token,
            Some(json!({"address": "mfa@example.org"})),
        )
        .await;
    assert_eq!(begun.status, StatusCode::NO_CONTENT);
    let (_, code) = rig.mailbox.last();
    let confirm = format!("{FACTOR}/email/confirm");
    let wrong = rig
        .authed(
            &device,
            "POST",
            &confirm,
            token,
            Some(json!({"address": "mfa@example.org", "code": "nope", "proof": proof})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());

    // The proof is still good, once, for the request that is right.
    let added = rig
        .authed(
            &device,
            "POST",
            &confirm,
            token,
            Some(json!({"address": "mfa@example.org", "code": code, "proof": proof})),
        )
        .await;
    assert_eq!(added.status, StatusCode::NO_CONTENT, "{:?}", added.json());
}
