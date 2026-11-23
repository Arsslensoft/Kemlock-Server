//! The two-step recovery code on the Kemlock API: made when the authenticator is confirmed, shown
//! to a signed-in device, and entered as the second step, which switches every method off.

mod common;
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{
    App, Client, Reply, Req, Session, register_and_sign_in, sign_in_reply, test_device, totp_now,
};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{TwoStepRuntime, two_step_router};
use kemlock_app::notices::Notices;
use kemlock_app::two_step::{NoDuo, NoYubico, TwoStepSettings};
use kemlock_domain::UserId;
use passkey_fakes::FakePasskeys;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const EMAIL: &str = "sam@example.org";
const CODE: &str = "/kem/v1/account/two-factor/recovery-code";
const RECOVER: &str = "/kem/v1/auth/two-factor/recovery";

struct Rig {
    app: App,
    router: Router,
    devices: AtomicUsize,
}

fn rig() -> Rig {
    let app = App::new(true);
    let runtime = TwoStepRuntime {
        challenges: FakePasskeys::default(),
        notices: Notices::logging(),
        yubico: Arc::new(NoYubico),
        duo: Arc::new(NoDuo),
        settings: TwoStepSettings::default(),
    };
    let router = app
        .router
        .clone()
        .merge(two_step_router(app.api.clone(), runtime));
    Rig {
        app,
        router,
        devices: AtomicUsize::new(0),
    }
}

impl Rig {
    /// A device with an address of its own, so the per-address limits of one test don't add up.
    fn device(&self) -> Client {
        let n = self.devices.fetch_add(1, Ordering::Relaxed);
        let mut client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        client.peer = Some(SocketAddr::from((
            [10, 3, 0, u8::try_from(n % 250).unwrap_or(0) + 1],
            40_000,
        )));
        client
    }

    /// An account with an authenticator app turned on through the API's own two calls: its first
    /// device, that device's session and the app's secret.
    async fn account_with_authenticator(&self) -> (Client, Session, String) {
        let first = self.device();
        let session = register_and_sign_in(&first, EMAIL).await;
        let enrol = first
            .send(
                "POST",
                "/kem/v1/account/two-factor/totp",
                Req {
                    access_token: Some(&session.access_token),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(enrol.status, StatusCode::OK, "{:?}", enrol.json());
        let secret = enrol.json()["secret"]
            .as_str()
            .expect("a secret")
            .to_owned();
        let confirmed = first
            .post_authed(
                "/kem/v1/account/two-factor/totp/confirm",
                &session.access_token,
                json!({"code": totp_now(&self.app, &secret)}),
            )
            .await;
        assert_eq!(confirmed.status, StatusCode::NO_CONTENT);
        (first, session, secret)
    }

    /// A new device that signed in with the password and was asked for its second step.
    async fn asked(&self) -> (Client, Value) {
        let device = self.device();
        let first = sign_in_reply(&device, EMAIL, test_device()).await;
        assert_eq!(first.status, StatusCode::OK, "{:?}", first.json());
        let first = first.json();
        assert_eq!(first["status"], "two_factor_required");
        (device, first["challenge"].clone())
    }
}

async fn recovery_code(client: &Client, session: &Session) -> Reply {
    client.get_authed(CODE, &session.access_token).await
}

#[tokio::test]
async fn confirming_the_authenticator_makes_a_recovery_code_a_signed_in_device_can_read() {
    let rig = rig();
    let first = rig.device();
    let session = register_and_sign_in(&first, EMAIL).await;
    // No second step yet, so no code; and no bearer token, no answer.
    let none = recovery_code(&first, &session).await;
    assert_eq!(none.status, StatusCode::OK, "{:?}", none.json());
    assert_eq!(none.json(), json!({"code": null}));
    assert_eq!(first.get(CODE).await.status, StatusCode::UNAUTHORIZED);

    // Enrolling alone makes none: the code comes when the app proves it was set up.
    let enrol = first
        .send(
            "POST",
            "/kem/v1/account/two-factor/totp",
            Req {
                access_token: Some(&session.access_token),
                ..Req::default()
            },
        )
        .await;
    let secret = enrol.json()["secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    assert_eq!(
        recovery_code(&first, &session).await.json(),
        json!({"code": null})
    );
    first
        .post_authed(
            "/kem/v1/account/two-factor/totp/confirm",
            &session.access_token,
            json!({"code": totp_now(&rig.app, &secret)}),
        )
        .await;

    let shown = recovery_code(&first, &session).await.json();
    let code = shown["code"].as_str().expect("a code");
    assert_eq!(code.len(), 32, "{code}");
    assert!(
        code.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "{code}"
    );
}

#[tokio::test]
async fn the_recovery_code_answers_the_second_step_switches_the_methods_off_and_is_spent() {
    let rig = rig();
    let (first, session, _secret) = rig.account_with_authenticator().await;
    let code = recovery_code(&first, &session).await.json()["code"]
        .as_str()
        .expect("a code")
        .to_owned();
    let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
    assert_eq!(rig.app.store.two_factor_of(user).len(), 1);

    let (device, challenge) = rig.asked().await;
    // Another device key can't use the challenge; a wrong code changes nothing.
    let thief = rig.device();
    let stolen = thief
        .post(RECOVER, json!({"challenge": challenge, "code": code}))
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
    let wrong = device
        .post(
            RECOVER,
            json!({"challenge": challenge, "code": "A".repeat(32)}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());
    assert_eq!(rig.app.store.two_factor_of(user).len(), 1);

    // Spaces and case don't matter.
    let typed = format!("{} {}", code[..12].to_lowercase(), &code[12..]);
    let signed = device
        .post(RECOVER, json!({"challenge": challenge, "code": typed}))
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
    let second = Session::from_tokens(&signed.json());
    assert_eq!(second.user_id, session.user_id);
    assert!(rig.app.store.two_factor_of(user).is_empty());

    // The code is spent, and the password alone signs in now.
    let replay = device
        .post(RECOVER, json!({"challenge": challenge, "code": code}))
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        recovery_code(&device, &second).await.json(),
        json!({"code": null})
    );
    let again = sign_in_reply(&rig.device(), EMAIL, test_device()).await;
    assert_eq!(again.json()["status"], "signed_in");
}
