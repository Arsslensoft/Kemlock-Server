//! The API key routes and the proof erasing an account takes beside the password, in-process with a real DPoP client:
//! what the key shows, what replaces it, and the fresh proof both the key and the erasure take.

mod common;
/// `privacy_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;
#[path = "../../kemlock-app/tests/privacy_fakes/mod.rs"]
mod privacy_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, PASSWORD, Reply, Req, Session, b64, register_and_sign_in, unb64};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{
    ApiKeyApiDoc, TwoStepRuntime, account_router, api_key_router, two_step_router,
};
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::ports::StoreError;
use kemlock_app::two_step::{NoDuo, NoYubico, TwoStepSettings};
use kemlock_domain::UserId;
use passkey_fakes::FakePasskeys;
use privacy_fakes::{FakePrivacy, FakeSends};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use utoipa::OpenApi;

const EMAIL: &str = "sam@example.org";
const KEY: &str = "/kem/v1/account/api-key";
const ROTATE: &str = "/kem/v1/account/api-key/rotate";
const ACCOUNT: &str = "/kem/v1/account";
const PROOF: &str = "/kem/v1/account/two-factor/proof";

/// The mailed proofs.
#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<String>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::ProtectedAction(p) = notice {
                self.0.lock().expect("the lock").push(p.code.clone());
            }
        })
    }
}

/// The Bitwarden account records, in a map.
#[derive(Clone, Default)]
struct Accounts(Arc<Mutex<HashMap<UserId, BwAccount>>>);

impl BwAccountRepo for Accounts {
    async fn get(&self, user: UserId) -> Result<Option<BwAccount>, StoreError> {
        Ok(self.0.lock().expect("the lock").get(&user).cloned())
    }

    async fn insert(&self, account: &BwAccount) -> Result<(), StoreError> {
        self.0
            .lock()
            .expect("the lock")
            .insert(account.user, account.clone());
        Ok(())
    }

    async fn update(&self, account: &BwAccount) -> Result<(), StoreError> {
        let mut map = self.0.lock().expect("the lock");
        let row = map.get_mut(&account.user).ok_or(StoreError::NotFound)?;
        let revision = row.revision_ms;
        *row = account.clone();
        row.revision_ms = revision;
        Ok(())
    }

    async fn touch(&self, user: UserId, now_ms: i64) -> Result<i64, StoreError> {
        let mut map = self.0.lock().expect("the lock");
        let row = map.get_mut(&user).ok_or(StoreError::NotFound)?;
        row.revision_ms = now_ms.max(row.revision_ms + 1);
        Ok(row.revision_ms)
    }
}

fn account_of(user: UserId) -> BwAccount {
    BwAccount {
        user,
        password_hash: Vec::new(),
        salt: vec![1; 64],
        password_iterations: 1,
        kdf_type: 0,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        akey: "2.a|b|c".to_owned(),
        private_key: None,
        public_key: None,
        password_hint: None,
        api_key: None,
        avatar_color: None,
        revision_ms: 1_000,
    }
}

struct Rig {
    app: App,
    router: Router,
    mailbox: Mailbox,
    accounts: Accounts,
    privacy: FakePrivacy,
    calls: AtomicUsize,
}

fn rig() -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    let runtime = TwoStepRuntime {
        challenges: FakePasskeys::default(),
        notices: Notices::with_outbox(Arc::new(mailbox.clone())),
        yubico: Arc::new(NoYubico),
        duo: Arc::new(NoDuo),
        settings: TwoStepSettings::default(),
    };
    let accounts = Accounts::default();
    let privacy = FakePrivacy::new(&app.store);
    let router = app
        .router
        .clone()
        .merge(two_step_router(app.api.clone(), runtime))
        .merge(api_key_router(app.api.clone(), accounts.clone()))
        .merge(account_router(
            app.api.clone(),
            privacy.clone(),
            FakeSends::default(),
            privacy.clone(),
        ));
    Rig {
        app,
        router,
        mailbox,
        accounts,
        privacy,
        calls: AtomicUsize::new(0),
    }
}

impl Rig {
    /// A signed-in account; `compatible` gives it the Bitwarden record the key lives in.
    async fn person(&self, compatible: bool) -> (Client, Session, UserId) {
        let device = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in(&device, EMAIL).await;
        let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
        if compatible {
            self.accounts
                .insert(&account_of(user))
                .await
                .expect("the record is kept");
        }
        (device, session, user)
    }

    async fn call(
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
                5,
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

    async fn proof(&self, device: &Client, token: &str) -> String {
        let asked = self.call(device, "POST", PROOF, token, None).await;
        assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.json());
        self.mailbox
            .0
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a proof was mailed")
    }

    fn actions(&self) -> Vec<&'static str> {
        self.app.store.events().iter().map(|e| e.action).collect()
    }
}

#[tokio::test]
async fn the_secret_is_shown_and_replaced_only_with_a_proof() {
    let rig = rig();
    let (device, session, user) = rig.person(true).await;
    let token = session.access_token.as_str();

    // Before any key: the client id, no secret.
    let info = rig.call(&device, "GET", KEY, token, None).await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.json());
    assert_eq!(info.json()["clientId"], format!("user.{}", user.0));
    assert_eq!(info.json()["set"], false);
    assert!(info.json().get("clientSecret").is_none());

    // No proof, a wrong proof: nothing is made.
    let bare = rig
        .call(&device, "POST", KEY, token, Some(json!({})))
        .await;
    assert!(bare.status.is_client_error(), "{:?}", bare.status);
    let guess = rig
        .call(&device, "POST", KEY, token, Some(json!({"proof": "123456"})))
        .await;
    assert_eq!(guess.status, StatusCode::BAD_REQUEST);
    assert!(
        rig.accounts.get(user).await.expect("the store").expect("the record").api_key.is_none(),
        "nothing was made"
    );

    // The first ask makes it.
    let proof = rig.proof(&device, token).await;
    let made = rig
        .call(&device, "POST", KEY, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.json());
    let made = made.json();
    let secret = made["clientSecret"].as_str().expect("a secret").to_owned();
    assert_eq!(secret.len(), 30);
    assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(made["clientId"], format!("user.{}", user.0));
    assert!(made["revisionDate"].is_string());
    assert_eq!(
        rig.accounts.get(user).await.expect("the store").expect("the record").api_key,
        Some(secret.clone()),
        "the key the Bitwarden grant compares is this one"
    );
    assert!(rig.actions().contains(&"account.api_key_created"));

    // A proof is good once.
    let spent = rig
        .call(&device, "POST", KEY, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(spent.status, StatusCode::BAD_REQUEST);

    // The same secret again, then a rotation that replaces it.
    let proof = rig.proof(&device, token).await;
    let again = rig
        .call(&device, "POST", KEY, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(again.json()["clientSecret"], secret.as_str());
    assert!(rig.actions().contains(&"account.api_key_viewed"));

    let proof = rig.proof(&device, token).await;
    let rotated = rig
        .call(&device, "POST", ROTATE, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.json());
    let fresh = rotated.json()["clientSecret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    assert_ne!(fresh, secret, "the old secret is out");
    assert_eq!(
        rig.accounts.get(user).await.expect("the store").expect("the record").api_key,
        Some(fresh)
    );
    assert!(rig.actions().contains(&"account.api_key_rotated"));
    let info = rig.call(&device, "GET", KEY, token, None).await;
    assert_eq!(info.json()["set"], true);
}

#[tokio::test]
async fn an_account_with_no_bitwarden_record_has_no_key() {
    let rig = rig();
    let (device, session, _user) = rig.person(false).await;
    let token = session.access_token.as_str();

    let info = rig.call(&device, "GET", KEY, token, None).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND);
    // The refusal comes before the proof is spent.
    let proof = rig.proof(&device, token).await;
    let reveal = rig
        .call(&device, "POST", KEY, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(reveal.status, StatusCode::NOT_FOUND);
    let rotate = rig
        .call(&device, "POST", ROTATE, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(rotate.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_key_routes_need_a_session_and_are_in_the_openapi_document() {
    let rig = rig();
    let anonymous = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = anonymous.send("GET", KEY, Req::default()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let document = serde_json::to_value(ApiKeyApiDoc::openapi()).expect("a document");
    assert!(document["paths"][KEY]["get"].is_object());
    assert!(document["paths"][KEY]["post"].is_object());
    assert!(document["paths"][ROTATE]["post"].is_object());
}

impl Rig {
    /// The two OPAQUE messages of a fresh login with the account's password, as the web vault
    /// sends them to re-authenticate.
    async fn reauth(&self, device: &Client) -> Value {
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
        let started = device
            .post(
                "/kem/v1/auth/opaque/start",
                json!({"email": EMAIL, "request": b64(&request)}),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        let (finalization, _key, _export) =
            kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &response)
                .expect("client login finish");
        json!({"loginState": started["loginState"], "finalization": b64(&finalization)})
    }
}

fn with_proof(mut body: Value, proof: &str) -> Value {
    body["proof"] = json!(proof);
    body
}

#[tokio::test]
async fn a_proof_alone_never_erases_an_account() {
    let rig = rig();
    let (device, session, _user) = rig.person(false).await;
    let token = session.access_token.as_str();
    let proof = rig.proof(&device, token).await;

    let reply = rig
        .call(&device, "DELETE", ACCOUNT, token, Some(json!({"proof": proof})))
        .await;

    assert!(reply.status.is_client_error(), "{:?}", reply.status);
    assert!(rig.privacy.lock().erased.is_empty(), "nothing was erased");
}

#[tokio::test]
async fn the_password_erases_an_account_with_no_second_step() {
    let rig = rig();
    let (device, session, user) = rig.person(false).await;
    let token = session.access_token.as_str();
    let body = rig.reauth(&device).await;

    let erased = rig.call(&device, "DELETE", ACCOUNT, token, Some(body)).await;

    assert_eq!(erased.status, StatusCode::NO_CONTENT, "{:?}", erased.json());
    assert_eq!(rig.privacy.lock().erased, vec![user]);
}

#[tokio::test]
async fn with_a_second_step_on_the_password_needs_a_fresh_proof_beside_it() {
    use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
    let rig = rig();
    let (device, session, user) = rig.person(false).await;
    let token = session.access_token.as_str();
    rig.app
        .store
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: rig
                .app
                .crypto
                .seal(kemlock_app::sealed::PURPOSE_TOTP, b"12345678901234567890"),
            enabled: true,
            created_at: rig.app.clock.now(),
        })
        .await
        .expect("the row is stored");

    // The password alone is not enough.
    let body = rig.reauth(&device).await;
    let bare = rig.call(&device, "DELETE", ACCOUNT, token, Some(body)).await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST, "{:?}", bare.json());
    // Nor is a wrong proof beside it.
    let body = rig.reauth(&device).await;
    let guess = rig
        .call(&device, "DELETE", ACCOUNT, token, Some(with_proof(body, "123456")))
        .await;
    assert_eq!(guess.status, StatusCode::BAD_REQUEST, "{:?}", guess.json());
    assert!(rig.privacy.lock().erased.is_empty(), "nothing was erased");

    // Both together are.
    let proof = rig.proof(&device, token).await;
    let body = rig.reauth(&device).await;
    let erased = rig
        .call(&device, "DELETE", ACCOUNT, token, Some(with_proof(body, &proof)))
        .await;
    assert_eq!(erased.status, StatusCode::NO_CONTENT, "{:?}", erased.json());
    assert_eq!(rig.privacy.lock().erased, vec![user]);
}
