//! The profile routes through the router, in-process, with a real DPoP client and real OPAQUE: the
//! name, the master password and the sign-in address, from the browser's side.
//!
//! The browser's key worker makes the new master key, the new OPAQUE record and the new wrap of the
//! root key. Here the client's half of OPAQUE is `kemlock-crypto`'s, and the wrap is a filler of the
//! right length, since the server never opens it.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{
    App, Client, PASSWORD, Reply, Req, Session, b64, register, register_and_sign_in, test_device,
    unb64,
};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{ProfileApiDoc, profile_router};
use kemlock_app::notices::{BoxFuture, Notice, Outbox};
use kemlock_app::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_domain::{AccountMode, User, UserId};
use serde_json::{Value, json};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::Duration;
use utoipa::OpenApi;

use common::fakes::profile::FakeProfile;

const EMAIL: &str = "sam@example.org";
const NEW_EMAIL: &str = "sam@example.com";
/// The master key of the password a person changes to.
const NEW_PASSWORD: [u8; 32] = [6u8; 32];

/// An address no other request of this run comes from: the limits that count tries per address
/// (a few sign-ins a minute) then never stop a test that signs in many times.
fn next_peer() -> SocketAddr {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    SocketAddr::from(([10, 1, (n >> 8) as u8, (n & 0xff) as u8], 5000))
}

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
    /// The token of the last link mailed to `to`.
    fn link_token(&self, to: &str) -> String {
        self.0
            .lock()
            .expect("the lock")
            .iter()
            .rev()
            .find_map(|notice| match notice {
                Notice::EmailChange(n) if n.to.as_str() == to => Some(n.token.clone()),
                _ => None,
            })
            .expect("a link was mailed")
    }

    fn told_old_address(&self, old: &str, new: &str) -> bool {
        self.0.lock().expect("the lock").iter().any(|notice| {
            matches!(notice, Notice::EmailChangeRequested(n)
                if n.to.as_str() == old && n.new_address.as_str() == new)
        })
    }
}

struct Rig {
    app: App,
    router: Router,
    repo: FakeProfile,
    mailbox: Mailbox,
}

fn rig() -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    let repo = FakeProfile::default();
    let router = app
        .router
        .clone()
        .merge(profile_router(app.api.clone(), repo.clone()));
    Rig {
        app,
        router,
        repo,
        mailbox,
    }
}

struct Person {
    client: Client,
    session: Session,
    id: UserId,
    email: String,
    /// The master key of the account's password now.
    password: Cell<[u8; 32]>,
}

impl Rig {
    fn client(&self) -> Client {
        let mut client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        client.peer = Some(next_peer());
        client
    }

    async fn person(&self, email: &str) -> Person {
        let client = self.client();
        let session = register_and_sign_in(&client, email).await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        Person {
            client,
            session,
            id,
            email: email.to_owned(),
            password: Cell::new(PASSWORD),
        }
    }

    /// Both OPAQUE login messages over HTTP for `email` with `password`, as a new device. `None`
    /// when the client can't finish the exchange, which is what a wrong password usually does.
    async fn try_sign_in(&self, email: &str, password: &[u8]) -> Option<Reply> {
        let client = self.client();
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(password).expect("client login start");
        let started = client
            .post(
                "/kem/v1/auth/opaque/start",
                json!({"email": email, "request": b64(&request)}),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        let (finalization, _session_key, _export_key) =
            kemlock_crypto::opaque::client_login_finish(state, password, &response).ok()?;
        Some(
            client
                .post(
                    "/kem/v1/auth/opaque/finish",
                    json!({
                        "email": email,
                        "loginState": started["loginState"],
                        "finalization": b64(&finalization),
                        "device": test_device(),
                    }),
                )
                .await,
        )
    }

    async fn signs_in(&self, email: &str, password: &[u8]) -> bool {
        match self.try_sign_in(email, password).await {
            Some(reply) => reply.status == StatusCode::OK,
            None => false,
        }
    }
}

impl Person {
    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    body,
                    peer: Some(next_peer()),
                    ..Req::default()
                },
            )
            .await
    }

    /// The two OPAQUE messages of a fresh login with the account's password, as the web vault
    /// sends them to re-authenticate.
    async fn reauth_body(&self) -> Value {
        let password = self.password.get();
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(&password).expect("client login start");
        let started = self
            .client
            .send(
                "POST",
                "/kem/v1/auth/opaque/start",
                Req {
                    body: Some(json!({"email": self.email, "request": b64(&request)})),
                    peer: Some(next_peer()),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        let (finalization, _session_key, _export_key) =
            kemlock_crypto::opaque::client_login_finish(state, &password, &response)
                .expect("client login finish");
        json!({"loginState": started["loginState"], "finalization": b64(&finalization)})
    }

    /// The `upload` of a registration of `NEW_PASSWORD`, made through the server's first message
    /// for the account's own address, or for `email`.
    async fn registration(&self, email: Option<&str>) -> String {
        let (state, request) = kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD)
            .expect("client registration start");
        let mut body = json!({"request": b64(&request)});
        if let Some(email) = email {
            body["email"] = json!(email);
        }
        let reply = self
            .call("POST", "/kem/v1/account/credentials/start", Some(body))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        let response = unb64(reply.json()["response"].as_str().expect("response"));
        let (upload, _export_key) =
            kemlock_crypto::opaque::client_registration_finish(state, &NEW_PASSWORD, &response)
                .expect("client registration finish");
        b64(&upload)
    }

    /// The body of `PUT /account/password`, re-authenticated.
    async fn password_body(&self, sign_out_others: bool) -> Value {
        let mut body = self.reauth_body().await;
        body["upload"] = json!(self.registration(None).await);
        body["kdf"] = kdf();
        body["wrappedRootKey"] = json!(b64(&[0x44u8; WRAPPED_ROOT_KEY_LEN]));
        body["signOutOthers"] = json!(sign_out_others);
        body
    }

    /// The body of `POST /account/email`, re-authenticated.
    async fn email_body(&self, email: &str) -> Value {
        let mut body = self.reauth_body().await;
        body["email"] = json!(email);
        body["upload"] = json!(self.registration(Some(email)).await);
        body["kdf"] = kdf();
        body["wrappedRootKey"] = json!(b64(&[0x44u8; WRAPPED_ROOT_KEY_LEN]));
        body
    }
}

fn kdf() -> Value {
    json!({"memoryKib": 65536, "iterations": 3, "parallelism": 4, "salt": b64(&[8u8; 16])})
}

fn actions(rig: &Rig) -> Vec<&'static str> {
    rig.app.store.events().iter().map(|e| e.action).collect()
}

// ---- the profile and the name ----

#[tokio::test]
async fn the_profile_is_shown_and_the_name_changes() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;

    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.status, StatusCode::OK, "{:?}", shown.json());
    assert!(shown.header("dpop-nonce").is_some());
    let profile = shown.json();
    assert_eq!(profile["userId"], sam.session.user_id);
    assert_eq!(profile["email"], EMAIL);
    assert_eq!(profile["name"], "Sam");
    assert_eq!(profile["sso"], false);
    assert_eq!(profile["hasPassword"], true);
    assert_eq!(profile["compatible"], false);
    assert!(profile["pendingEmail"].is_null());

    let renamed = sam
        .call(
            "PATCH",
            "/kem/v1/account/profile",
            Some(json!({"name": "  Sam Rivera "})),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.json());
    assert_eq!(renamed.json()["name"], "Sam Rivera");
    let again = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(again.json()["name"], "Sam Rivera");

    let cleared = sam
        .call("PATCH", "/kem/v1/account/profile", Some(json!({"name": ""})))
        .await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(cleared.json()["name"].is_null());
    assert!(actions(&rig).contains(&"account.name_changed"));
}

#[tokio::test]
async fn a_name_that_is_too_long_is_refused_and_a_stranger_is_turned_away() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;

    let long = sam
        .call(
            "PATCH",
            "/kem/v1/account/profile",
            Some(json!({"name": "x".repeat(101)})),
        )
        .await;
    assert_eq!(long.status, StatusCode::BAD_REQUEST);
    assert_eq!(long.problem(), "invalid-request");
    let unknown = sam
        .call(
            "PATCH",
            "/kem/v1/account/profile",
            Some(json!({"name": "Sam", "email": "x@example.org"})),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);

    let anonymous = rig
        .client()
        .send("GET", "/kem/v1/account/profile", Req::default())
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_single_sign_on_account_keeps_its_name_and_address_and_may_change_its_password() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    rig.repo.link_sso(sam.id);

    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.json()["sso"], true);
    let renamed = sam
        .call(
            "PATCH",
            "/kem/v1/account/profile",
            Some(json!({"name": "Someone Else"})),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::FORBIDDEN);
    assert_eq!(renamed.problem(), "sso-managed");

    let (_state, request) =
        kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD).expect("start");
    let address = sam
        .call(
            "POST",
            "/kem/v1/account/credentials/start",
            Some(json!({"request": b64(&request), "email": NEW_EMAIL})),
        )
        .await;
    assert_eq!(address.status, StatusCode::FORBIDDEN);
    assert_eq!(address.problem(), "sso-managed");
    let email = sam
        .call("POST", "/kem/v1/account/email", Some(sam.email_body_unchecked()))
        .await;
    assert_eq!(email.status, StatusCode::FORBIDDEN);
    assert_eq!(email.problem(), "sso-managed");

    // The password stays the account's own to change.
    let body = sam.password_body(false).await;
    let changed = sam.call("PUT", "/kem/v1/account/password", Some(body)).await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT, "{:?}", changed.body);
}

impl Person {
    /// An email body that fails before anything is checked: for a route that must refuse first.
    fn email_body_unchecked(&self) -> Value {
        json!({
            "email": NEW_EMAIL,
            "loginState": "AAAA",
            "finalization": "AAAA",
            "upload": "AAAA",
            "kdf": kdf(),
            "wrappedRootKey": b64(&[0x44u8; WRAPPED_ROOT_KEY_LEN]),
        })
    }
}

// ---- the master password ----

#[tokio::test]
async fn a_new_password_signs_in_and_the_old_one_does_not() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let body = sam.password_body(false).await;

    let changed = sam
        .call("PUT", "/kem/v1/account/password", Some(body.clone()))
        .await;

    assert_eq!(changed.status, StatusCode::NO_CONTENT, "{:?}", changed.body);
    assert!(rig.signs_in(EMAIL, &NEW_PASSWORD).await);
    assert!(
        !rig.signs_in(EMAIL, &PASSWORD).await,
        "the old password is over"
    );
    // The session that asked goes on, and the account's stamp is the same.
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.status, StatusCode::OK);
    assert!(actions(&rig).contains(&"account.password_changed"));
    // The same proof can't be used twice.
    let again = sam.call("PUT", "/kem/v1/account/password", Some(body)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{:?}", again.json());
}

#[tokio::test]
async fn the_password_stays_when_the_old_one_is_wrong_or_the_records_are_bad() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;

    let mut wrong = sam.password_body(false).await;
    wrong["finalization"] = json!(b64(&[9u8; 64]));
    let refused = sam.call("PUT", "/kem/v1/account/password", Some(wrong)).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{:?}", refused.json());

    let mut odd_kdf = sam.password_body(false).await;
    odd_kdf["kdf"]["iterations"] = json!(4);
    let bad = sam
        .call("PUT", "/kem/v1/account/password", Some(odd_kdf))
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let mut short_wrap = sam.password_body(false).await;
    short_wrap["wrappedRootKey"] = json!(b64(&[1u8; 10]));
    let bad = sam
        .call("PUT", "/kem/v1/account/password", Some(short_wrap))
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let missing = sam
        .call("PUT", "/kem/v1/account/password", Some(json!({})))
        .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);

    assert!(rig.signs_in(EMAIL, &PASSWORD).await);
    assert!(!rig.signs_in(EMAIL, &NEW_PASSWORD).await);
}

#[tokio::test]
async fn signing_the_other_devices_out_keeps_the_device_that_asked() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let other = rig.client();
    let other_session = {
        let signed = common::sign_in_reply(&other, EMAIL, test_device()).await;
        assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
        Session::from_tokens(&signed.json()["tokens"])
    };

    // Without the box ticked every device goes on.
    let kept = sam.password_body(false).await;
    let changed = sam.call("PUT", "/kem/v1/account/password", Some(kept)).await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT, "{:?}", changed.body);
    let refresh = |client: &Client, token: &str| {
        client.post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": token}),
        )
    };
    let still = refresh(&other, &other_session.refresh_token).await;
    assert_eq!(still.status, StatusCode::OK, "{:?}", still.json());
    let other_session = Session::from_tokens(&still.json());

    // With it ticked the other device is signed out, and this one is not.
    sam.password.set(NEW_PASSWORD);
    let ticked = sam.password_body(true).await;
    let changed = sam.call("PUT", "/kem/v1/account/password", Some(ticked)).await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT, "{:?}", changed.body);
    let gone = refresh(&other, &other_session.refresh_token).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.status, StatusCode::OK, "{:?}", shown.json());
    let mine = refresh(&sam.client, &sam.session.refresh_token).await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.json());
}

#[tokio::test]
async fn an_account_shared_with_bitwarden_apps_or_with_no_password_is_refused() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let account = rig.app.store.user(sam.id).expect("the account");
    let (_state, request) =
        kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD).expect("start");
    let start = || {
        sam.call(
            "POST",
            "/kem/v1/account/credentials/start",
            Some(json!({"request": b64(&request)})),
        )
    };

    rig.app.store.put_user(User {
        mode: AccountMode::Compatible,
        ..account.clone()
    });
    let compatible = start().await;
    assert_eq!(compatible.status, StatusCode::FORBIDDEN);
    assert_eq!(compatible.problem(), "compatible-account");
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.json()["compatible"], true);

    rig.app.store.put_user(User {
        opaque_record: None,
        wrapped_root_key: Vec::new(),
        ..account
    });
    let none = start().await;
    assert_eq!(none.status, StatusCode::FORBIDDEN);
    assert_eq!(none.problem(), "no-password");
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.json()["hasPassword"], false);
}

// ---- the sign-in address ----

#[tokio::test]
async fn an_address_changes_when_its_link_is_opened_and_every_session_ends() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let body = sam.email_body(NEW_EMAIL).await;

    let asked = sam
        .call("POST", "/kem/v1/account/email", Some(body))
        .await;

    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.json());
    assert_eq!(asked.json()["pendingEmail"], NEW_EMAIL);
    assert!(asked.json()["expiresAt"].as_str().is_some());
    // Nothing has changed yet: the old address and password still sign in, and the profile says
    // what waits.
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert_eq!(shown.json()["email"], EMAIL);
    assert_eq!(shown.json()["pendingEmail"], NEW_EMAIL);
    assert!(rig.signs_in(EMAIL, &PASSWORD).await);
    assert!(rig.mailbox.told_old_address(EMAIL, NEW_EMAIL));
    let token = rig.mailbox.link_token(NEW_EMAIL);

    // Opening the link needs no session: it is opened from the mail client.
    let opened = rig
        .client()
        .post("/kem/v1/account/email/confirm", json!({"token": token}))
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.json());
    assert_eq!(opened.json()["email"], NEW_EMAIL);

    assert!(rig.signs_in(NEW_EMAIL, &NEW_PASSWORD).await);
    assert!(!rig.signs_in(EMAIL, &PASSWORD).await, "the old address is over");
    assert!(!rig.signs_in(NEW_EMAIL, &PASSWORD).await);
    // Every session ended.
    let refreshed = sam
        .client
        .post(
            "/kem/v1/auth/token",
            json!({"grantType": "refresh_token", "refreshToken": sam.session.refresh_token}),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);
    let events = actions(&rig);
    assert!(events.contains(&"account.email_change_requested"));
    assert!(events.contains(&"account.email_changed"));
    // The mail and the events carry no address of the account in their targets.
    assert!(
        rig.app
            .store
            .events()
            .iter()
            .all(|e| !e.target.as_deref().is_some_and(|t| t.contains('@')))
    );
}

#[tokio::test]
async fn a_link_is_good_once_and_runs_out() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let body = sam.email_body(NEW_EMAIL).await;
    let asked = sam.call("POST", "/kem/v1/account/email", Some(body)).await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.json());
    let token = rig.mailbox.link_token(NEW_EMAIL);
    let anyone = rig.client();

    let wrong = anyone
        .post("/kem/v1/account/email/confirm", json!({"token": "nope"}))
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.problem(), "email-change-invalid");

    // A day later the link no longer opens, and the profile no longer shows the ask.
    rig.app.clock.advance(Duration::hours(25));
    let late = anyone
        .post("/kem/v1/account/email/confirm", json!({"token": token}))
        .await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST);
    assert_eq!(late.problem(), "email-change-invalid");

    // A fresh ask, opened once: the second opening is as good as an unknown token.
    let sam = rig.person_signing_in_again(&sam).await;
    let body = sam.email_body(NEW_EMAIL).await;
    let asked = sam.call("POST", "/kem/v1/account/email", Some(body)).await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.json());
    let token = rig.mailbox.link_token(NEW_EMAIL);
    let opened = anyone
        .post("/kem/v1/account/email/confirm", json!({"token": token}))
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.json());
    let twice = anyone
        .post("/kem/v1/account/email/confirm", json!({"token": token}))
        .await;
    assert_eq!(twice.status, StatusCode::BAD_REQUEST);
    assert_eq!(twice.problem(), "email-change-invalid");
}

impl Rig {
    /// The same account on a new device, after a day has gone by and the old tokens ran out.
    async fn person_signing_in_again(&self, was: &Person) -> Person {
        let client = self.client();
        let signed = common::sign_in_reply(&client, &was.email, test_device()).await;
        assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.json());
        Person {
            client,
            session: Session::from_tokens(&signed.json()["tokens"]),
            id: was.id,
            email: was.email.clone(),
            password: Cell::new(PASSWORD),
        }
    }
}

#[tokio::test]
async fn an_address_someone_has_is_refused_and_an_ask_can_be_taken_back() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let other = rig.client();
    let (reply, _id) = register(&other, "kim@example.org", None).await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let (_state, request) =
        kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD).expect("start");
    let taken = sam
        .call(
            "POST",
            "/kem/v1/account/credentials/start",
            Some(json!({"request": b64(&request), "email": "kim@example.org"})),
        )
        .await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.problem(), "email-taken");
    let own = sam
        .call(
            "POST",
            "/kem/v1/account/credentials/start",
            Some(json!({"request": b64(&request), "email": EMAIL})),
        )
        .await;
    assert_eq!(own.status, StatusCode::BAD_REQUEST);

    // An ask taken back leaves a link that opens nothing; asking nothing is fine too.
    let body = sam.email_body(NEW_EMAIL).await;
    let asked = sam.call("POST", "/kem/v1/account/email", Some(body)).await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.json());
    let token = rig.mailbox.link_token(NEW_EMAIL);
    let cancelled = sam.call("DELETE", "/kem/v1/account/email", None).await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    let again = sam.call("DELETE", "/kem/v1/account/email", None).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    assert!(rig.repo.pending(sam.id).is_none());
    let opened = rig
        .client()
        .post("/kem/v1/account/email/confirm", json!({"token": token}))
        .await;
    assert_eq!(opened.status, StatusCode::BAD_REQUEST);
    let shown = sam.call("GET", "/kem/v1/account/profile", None).await;
    assert!(shown.json()["pendingEmail"].is_null());
}

#[tokio::test]
async fn a_wrong_password_changes_no_address() {
    let rig = rig();
    let sam = rig.person(EMAIL).await;
    let mut body = sam.email_body(NEW_EMAIL).await;
    body["finalization"] = json!(b64(&[9u8; 64]));

    let refused = sam.call("POST", "/kem/v1/account/email", Some(body)).await;

    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{:?}", refused.json());
    assert!(rig.repo.pending(sam.id).is_none());
    assert!(rig.signs_in(EMAIL, &PASSWORD).await);
}

// ---- the document ----

#[tokio::test]
async fn the_openapi_document_names_the_profile_routes() {
    let rig = rig();
    let own = serde_json::to_value(ProfileApiDoc::openapi()).expect("a document");
    let served = rig.app.client().get("/kem/v1/openapi.json").await.json();
    for (path, method) in [
        ("/kem/v1/account/profile", "get"),
        ("/kem/v1/account/profile", "patch"),
        ("/kem/v1/account/credentials/start", "post"),
        ("/kem/v1/account/password", "put"),
        ("/kem/v1/account/email", "post"),
        ("/kem/v1/account/email", "delete"),
        ("/kem/v1/account/email/confirm", "post"),
    ] {
        assert!(own["paths"][path][method].is_object(), "{method} {path}");
        assert!(
            served["paths"][path][method].is_object(),
            "{method} {path} is in the one document"
        );
    }
}
