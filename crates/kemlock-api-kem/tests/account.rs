//! `GET /kem/v1/account/export` and `DELETE /kem/v1/account`, in-process: a device signs in with
//! real OPAQUE and DPoP, then asks for its data or its erasure against the in-memory fakes.

mod common;
/// `privacy_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/privacy_fakes/mod.rs"]
mod privacy_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, PASSWORD, Req, Session, b64, register_and_sign_in, unb64};
use kemlock_api_kem::account_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_domain::UserId;
use privacy_fakes::{FakePrivacy, FakeSends};
use serde_json::{Value, json};

struct Rig {
    app: App,
    privacy: FakePrivacy,
    sends: FakeSends,
    router: Router,
}

impl Rig {
    fn new() -> Rig {
        let app = App::new(true);
        let privacy = FakePrivacy::new(&app.store);
        let sends = FakeSends::default();
        let router = app.router.clone().merge(account_router(
            app.api.clone(),
            privacy.clone(),
            sends.clone(),
            privacy.clone(),
        ));
        Rig {
            app,
            privacy,
            sends,
            router,
        }
    }

    async fn person(&self, email: &str) -> Person {
        let client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in(&client, email).await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        Person {
            client,
            session,
            id,
            email: email.to_owned(),
        }
    }
}

struct Person {
    client: Client,
    session: Session,
    id: UserId,
    email: String,
}

impl Person {
    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> common::Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    body,
                    ..Req::default()
                },
            )
            .await
    }

    /// The two OPAQUE messages of a fresh login with the account's password, as the web vault
    /// sends them to re-authenticate: `POST /auth/opaque/start`, then the client's last message.
    async fn reauth_body(&self) -> Value {
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
        let started = self
            .client
            .post(
                "/kem/v1/auth/opaque/start",
                json!({"email": self.email, "request": b64(&request)}),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        let (finalization, _session_key, _export_key) =
            kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &response)
                .expect("client login finish");
        json!({
            "loginState": started["loginState"],
            "finalization": b64(&finalization),
        })
    }
}

#[tokio::test]
async fn the_export_is_the_record_and_the_vault_as_a_download() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;

    let reply = sam.call("GET", "/kem/v1/account/export", None).await;

    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert!(
        reply
            .header("content-disposition")
            .is_some_and(|d| d.starts_with("attachment; filename=\"kemlock-account-")),
        "{:?}",
        reply.header("content-disposition")
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(
        reply.header("dpop-nonce").is_some(),
        "the nonce rides along"
    );
    let doc = reply.json();
    assert_eq!(doc["format"], "kemlock-account-export/1");
    assert_eq!(doc["account"]["email"], "sam@example.org");
    assert!(doc["vault"]["items"].is_array());
    // The export is in the event log, as the person's own.
    let logged = rig
        .privacy
        .events()
        .into_iter()
        .any(|e| e.action == "account.export" && e.actor == Some(sam.id));
    assert!(logged);
}

#[tokio::test]
async fn the_export_needs_a_signed_in_device_and_is_rate_limited() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    // Through the rig's router: the plain app's has no account routes.
    let anonymous = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    )
    .send("GET", "/kem/v1/account/export", Req::default())
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    for _ in 0..5 {
        let ok = sam.call("GET", "/kem/v1/account/export", None).await;
        assert_eq!(ok.status, StatusCode::OK);
    }
    let sixth = sam.call("GET", "/kem/v1/account/export", None).await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(sixth.header("retry-after").is_some());
}

#[tokio::test]
async fn erasing_after_re_authenticating_removes_the_account() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let body = sam.reauth_body().await;

    let reply = sam
        .call("DELETE", "/kem/v1/account", Some(body.clone()))
        .await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{:?}", reply.body);
    assert_eq!(rig.privacy.lock().erased, vec![sam.id]);
    assert_eq!(rig.sends.0.lock().expect("lock").clone(), vec![sam.id]);

    // The same proof can't be used twice.
    let again = sam.call("DELETE", "/kem/v1/account", Some(body)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{:?}", again.json());
    assert_eq!(rig.privacy.lock().erased.len(), 1);
}

#[tokio::test]
async fn a_token_alone_cannot_erase_an_account() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let body = sam.reauth_body().await;
    let garbage = json!({
        "loginState": body["loginState"],
        "finalization": b64(&[9u8; 64]),
    });

    let wrong = sam.call("DELETE", "/kem/v1/account", Some(garbage)).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json());

    let missing = sam.call("DELETE", "/kem/v1/account", Some(json!({}))).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);

    let forged = sam
        .call(
            "DELETE",
            "/kem/v1/account",
            Some(json!({"loginState": b64(b"forged"), "finalization": b64(b"x")})),
        )
        .await;
    assert_eq!(forged.status, StatusCode::BAD_REQUEST);

    assert!(rig.privacy.lock().erased.is_empty(), "nothing was erased");
}

#[tokio::test]
async fn a_login_started_by_another_device_key_does_not_count() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    // Another device (another DPoP key) starts the login; Sam's token can't finish it.
    let other = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
    let started = other
        .post(
            "/kem/v1/auth/opaque/start",
            json!({"email": sam.email, "request": b64(&request)}),
        )
        .await;
    let started = started.json();
    let response = unb64(started["response"].as_str().expect("response"));
    let (finalization, _s, _e) =
        kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &response)
            .expect("client login finish");

    let reply = sam
        .call(
            "DELETE",
            "/kem/v1/account",
            Some(json!({
                "loginState": started["loginState"],
                "finalization": b64(&finalization),
            })),
        )
        .await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{:?}", reply.json());
    assert!(rig.privacy.lock().erased.is_empty());
}

#[tokio::test]
async fn a_grace_period_answers_202_with_the_due_date() {
    let rig = Rig::new();
    rig.privacy.lock().retention.deleted_account_grace_days = 7;
    let sam = rig.person("sam@example.org").await;
    let body = sam.reauth_body().await;

    let reply = sam.call("DELETE", "/kem/v1/account", Some(body)).await;

    assert_eq!(reply.status, StatusCode::ACCEPTED, "{:?}", reply.body);
    let json = reply.json();
    assert_eq!(json["status"], "scheduled");
    assert!(json["dueAt"].as_str().is_some_and(|d| d.contains('T')));
    assert!(rig.privacy.lock().erased.is_empty(), "not yet");
}
