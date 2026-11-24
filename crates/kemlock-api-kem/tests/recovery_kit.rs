//! The Recovery Kit routes through the router, in-process, with a real DPoP client: the record the
//! server keeps, and the fresh proof replacing or removing it takes.

mod common;
#[path = "../../kemlock-app/tests/passkey_fakes/mod.rs"]
mod passkey_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, register_and_sign_in};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{RecoveryKitApiDoc, TwoStepRuntime, recovery_kit_router, two_step_router};
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::passkeys::{ChallengeKind, ChallengeRepo};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::recovery_kit::RecoveryKitRepo;
use kemlock_app::two_step::{NoDuo, NoYubico, TwoStepSettings};
use kemlock_crypto::recovery_kit::{WRAPPED_LEN, make_kit};
use kemlock_domain::{RecoveryKit, UserId};
use passkey_fakes::FakePasskeys;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use utoipa::OpenApi;

const EMAIL: &str = "sam@example.org";
const KIT: &str = "/kem/v1/account/recovery-kit";
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

impl Mailbox {
    fn last_proof(&self) -> String {
        self.0
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a proof was mailed")
    }
}

/// The challenge store of the passkey fakes, and the kits in a map.
#[derive(Clone, Default)]
struct Repos {
    challenges: FakePasskeys,
    kits: Arc<Mutex<HashMap<UserId, RecoveryKit>>>,
}

impl ChallengeRepo for Repos {
    async fn put_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        self.challenges
            .put_challenge(user, kind, state, expires_at)
            .await
    }

    async fn take_challenge(
        &self,
        user: UserId,
        kind: ChallengeKind,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.challenges.take_challenge(user, kind, now).await
    }

    async fn purge_challenges(&self, before: OffsetDateTime) -> Result<u64, StoreError> {
        self.challenges.purge_challenges(before).await
    }
}

impl RecoveryKitRepo for Repos {
    async fn recovery_kit(&self, user: UserId) -> Result<Option<RecoveryKit>, StoreError> {
        Ok(self.kits.lock().expect("the lock").get(&user).cloned())
    }

    async fn insert_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> Result<bool, StoreError> {
        let mut kits = self.kits.lock().expect("the lock");
        if kits.contains_key(&user) {
            return Ok(false);
        }
        kits.insert(user, kit.clone());
        Ok(true)
    }

    async fn replace_recovery_kit(
        &self,
        user: UserId,
        kit: &RecoveryKit,
    ) -> Result<bool, StoreError> {
        let mut kits = self.kits.lock().expect("the lock");
        Ok(kits.insert(user, kit.clone()).is_some())
    }

    async fn remove_recovery_kit(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self.kits.lock().expect("the lock").remove(&user).is_some())
    }
}

struct Rig {
    app: App,
    router: Router,
    mailbox: Mailbox,
    calls: AtomicUsize,
}

fn rig() -> Rig {
    rig_with(true)
}

/// The kit routes beside the second-step routes, which serve the proof the changes take.
fn rig_with(email_enabled: bool) -> Rig {
    let mailbox = Mailbox::default();
    let app = App::mailing(true, Arc::new(mailbox.clone()));
    // One challenge store for both routers, as the server gives them: the proof the second-step
    // routes mail is the one the kit routes take.
    let challenges = FakePasskeys::default();
    let runtime = TwoStepRuntime {
        challenges: challenges.clone(),
        notices: Notices::with_outbox(Arc::new(mailbox.clone())),
        yubico: Arc::new(NoYubico),
        duo: Arc::new(NoDuo),
        settings: TwoStepSettings {
            email_enabled,
            ..TwoStepSettings::default()
        },
    };
    let router = app
        .router
        .clone()
        .merge(two_step_router(app.api.clone(), runtime))
        .merge(recovery_kit_router(
            app.api.clone(),
            Repos {
                challenges,
                kits: Arc::default(),
            },
        ));
    Rig {
        app,
        router,
        mailbox,
        calls: AtomicUsize::new(0),
    }
}

impl Rig {
    async fn plain(&self) -> (Client, Session, UserId) {
        let device = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in(&device, EMAIL).await;
        let user = UserId(uuid::Uuid::parse_str(&session.user_id).expect("a UUID"));
        (device, session, user)
    }

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
                4,
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

    /// A kit the way the key worker makes one, but with a wrap of the right length that no one
    /// opens: the server never looks inside.
    async fn kit_body(&self, user: UserId) -> Value {
        let (kit_id, _, _) = make_kit(2, 3).expect("a kit");
        let account = self
            .app
            .store
            .by_id(user)
            .await
            .expect("the store")
            .expect("the account");
        json!({
            "kitId": kit_id,
            "keyVersion": account.key_version,
            "wrappedKey": kemlock_app::b64url::encode(&[7u8; WRAPPED_LEN]),
        })
    }

    async fn proof(&self, device: &Client, token: &str) -> String {
        let asked = self.authed(device, "POST", PROOF, token, None).await;
        assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.json());
        self.mailbox.last_proof()
    }

    fn actions(&self) -> Vec<&'static str> {
        self.app.store.events().iter().map(|e| e.action).collect()
    }
}

fn with(mut body: Value, key: &str, value: Value) -> Value {
    body[key] = value;
    body
}

#[tokio::test]
async fn a_kit_is_made_read_replaced_with_a_proof_and_removed_with_a_proof() {
    let rig = rig();
    let (device, session, user) = rig.plain().await;
    let token = session.access_token.as_str();

    let none = rig.authed(&device, "GET", KIT, token, None).await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);

    let first = rig.kit_body(user).await;
    let made = rig
        .authed(&device, "POST", KIT, token, Some(first.clone()))
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    let shown = rig.authed(&device, "GET", KIT, token, None).await;
    let shown = shown.json();
    assert_eq!(shown["kitId"], first["kitId"]);
    assert_eq!(shown["wrappedKey"], first["wrappedKey"]);
    assert_eq!(shown["threshold"], 2);
    assert_eq!(shown["shares"], 3);
    assert_eq!(shown["current"], true);
    assert!(shown["createdAt"].is_string());
    assert!(rig.actions().contains(&"account.recovery_kit_created"));

    let again = rig
        .authed(&device, "POST", KIT, token, Some(rig.kit_body(user).await))
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "one kit at a time");

    // Replacing needs a proof.
    let second = rig.kit_body(user).await;
    let bare = rig
        .authed(&device, "PUT", KIT, token, Some(second.clone()))
        .await;
    assert!(bare.status.is_client_error(), "no proof: {:?}", bare.status);
    let guess = rig
        .authed(
            &device,
            "PUT",
            KIT,
            token,
            Some(with(second.clone(), "proof", json!("123456"))),
        )
        .await;
    assert_eq!(guess.status, StatusCode::BAD_REQUEST);
    let shown = rig.authed(&device, "GET", KIT, token, None).await.json();
    assert_eq!(shown["kitId"], first["kitId"], "the old kit is untouched");

    let proof = rig.proof(&device, token).await;
    let replaced = rig
        .authed(
            &device,
            "PUT",
            KIT,
            token,
            Some(with(second.clone(), "proof", json!(proof))),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.json());
    let shown = rig.authed(&device, "GET", KIT, token, None).await.json();
    assert_eq!(shown["kitId"], second["kitId"], "the old pieces are out");
    assert!(rig.actions().contains(&"account.recovery_kit_regenerated"));

    // Removing needs one too, and a proof is good once.
    let bare = rig.authed(&device, "DELETE", KIT, token, None).await;
    assert!(bare.status.is_client_error(), "no proof: {:?}", bare.status);
    let spent = rig
        .authed(&device, "DELETE", KIT, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(
        spent.status,
        StatusCode::BAD_REQUEST,
        "a proof is good once"
    );
    let proof = rig.proof(&device, token).await;
    let removed = rig
        .authed(&device, "DELETE", KIT, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(
        removed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        removed.json()
    );
    let gone = rig.authed(&device, "GET", KIT, token, None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert!(rig.actions().contains(&"account.recovery_kit_removed"));
}

#[tokio::test]
async fn a_malformed_kit_is_refused_and_nothing_is_kept() {
    let rig = rig();
    let (device, session, user) = rig.plain().await;
    let token = session.access_token.as_str();
    let good = rig.kit_body(user).await;

    for (name, body) in [
        (
            "an id that is not base32",
            with(good.clone(), "kitId", json!("abc")),
        ),
        (
            "a short wrap",
            with(
                good.clone(),
                "wrappedKey",
                json!(kemlock_app::b64url::encode(&[1u8; 20])),
            ),
        ),
        (
            "another key version than the account's",
            with(good.clone(), "keyVersion", json!(99)),
        ),
    ] {
        let reply = rig.authed(&device, "POST", KIT, token, Some(body)).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{name}: {:?}",
            reply.json()
        );
    }
    let none = rig.authed(&device, "GET", KIT, token, None).await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_routes_need_a_session_and_are_in_the_openapi_document() {
    let rig = rig();
    let anonymous = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = anonymous.send("GET", KIT, Req::default()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let document = serde_json::to_value(RecoveryKitApiDoc::openapi()).expect("a document");
    let methods: Vec<&str> = document["paths"][KIT]
        .as_object()
        .expect("the path")
        .keys()
        .map(String::as_str)
        .collect();
    for method in ["get", "post", "put", "delete"] {
        assert!(methods.contains(&method), "{method} is documented");
    }
}

/// The account's authenticator app, set up the way the move from Vaultwarden writes it.
async fn turn_totp_on(rig: &Rig, user: UserId, secret: &[u8]) {
    use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
    rig.app
        .store
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: rig
                .app
                .crypto
                .seal(kemlock_app::sealed::PURPOSE_TOTP, secret),
            enabled: true,
            created_at: rig.app.clock.now(),
        })
        .await
        .expect("the row is stored");
}

#[tokio::test]
async fn an_authenticator_code_or_the_recovery_code_proves_the_owner_when_mail_is_off() {
    use kemlock_app::ports::SecretSeal;
    use kemlock_app::two_step::{PURPOSE_RECOVERY, RecoveryCodeRepo};
    // No mail at all: the proof request is refused, and revoking must still work.
    let rig = rig_with(false);
    let (device, session, user) = rig.plain().await;
    let token = session.access_token.as_str();
    let asked = rig.authed(&device, "POST", PROOF, token, None).await;
    assert!(asked.status.is_client_error(), "mail is off");

    let made = rig
        .authed(&device, "POST", KIT, token, Some(rig.kit_body(user).await))
        .await;
    assert_eq!(made.status, StatusCode::CREATED);

    // A wrong code of the app does nothing.
    let secret = b"12345678901234567890";
    turn_totp_on(&rig, user, secret).await;
    let wrong = rig
        .authed(
            &device,
            "DELETE",
            KIT,
            token,
            Some(json!({"proof": "000000"})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);

    // The recovery code proves it, and is kept: it is a proof here, not a recovery.
    let code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    rig.app
        .store
        .put_recovery_code_if_absent(
            user,
            &rig.app.crypto.seal(PURPOSE_RECOVERY, code.as_bytes()),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("a code");
    let spaced = "abcd efgh ijkl mnop qrst uvwx yz23 4567";
    let by_code = rig
        .authed(
            &device,
            "DELETE",
            KIT,
            token,
            Some(json!({"proof": spaced})),
        )
        .await;
    assert_eq!(
        by_code.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        by_code.json()
    );
    assert!(
        rig.app
            .store
            .recovery_code(user)
            .await
            .expect("read")
            .is_some(),
        "the recovery code is not spent"
    );

    // A current code of the authenticator app proves it too.
    let again = rig
        .authed(&device, "POST", KIT, token, Some(rig.kit_body(user).await))
        .await;
    assert_eq!(again.status, StatusCode::CREATED);
    let now = u64::try_from(rig.app.now()).expect("a time");
    let current = kemlock_crypto::totp::code_at(secret, now);
    let by_app = rig
        .authed(
            &device,
            "DELETE",
            KIT,
            token,
            Some(json!({"proof": current})),
        )
        .await;
    assert_eq!(by_app.status, StatusCode::NO_CONTENT, "{:?}", by_app.json());

    // The code works once: the same step is refused the second time (as at sign-in).
    let made = rig
        .authed(&device, "POST", KIT, token, Some(rig.kit_body(user).await))
        .await;
    assert_eq!(made.status, StatusCode::CREATED);
    let replayed = rig
        .authed(
            &device,
            "DELETE",
            KIT,
            token,
            Some(json!({"proof": current})),
        )
        .await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST, "{:?}", replayed.json());
}

#[tokio::test]
async fn a_bad_replacement_or_a_missing_kit_does_not_spend_the_proof() {
    let rig = rig();
    let (device, session, user) = rig.plain().await;
    let token = session.access_token.as_str();

    // No kit: removing and replacing say so, and the proof stays good.
    let proof = rig.proof(&device, token).await;
    let none = rig
        .authed(&device, "DELETE", KIT, token, Some(json!({"proof": proof})))
        .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
    let good = rig.kit_body(user).await;
    let none = rig
        .authed(
            &device,
            "PUT",
            KIT,
            token,
            Some(with(good.clone(), "proof", json!(proof))),
        )
        .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);

    let made = rig
        .authed(&device, "POST", KIT, token, Some(good.clone()))
        .await;
    assert_eq!(made.status, StatusCode::CREATED);

    // A malformed replacement is refused before the proof is looked at.
    let bad = with(rig.kit_body(user).await, "keyVersion", json!(99));
    let refused = rig
        .authed(
            &device,
            "PUT",
            KIT,
            token,
            Some(with(bad, "proof", json!(proof))),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    // The same proof still works for a good one.
    let next = rig.kit_body(user).await;
    let replaced = rig
        .authed(
            &device,
            "PUT",
            KIT,
            token,
            Some(with(next, "proof", json!(proof))),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.json());
}

#[tokio::test]
async fn reading_the_kit_is_not_held_to_the_sign_in_limit() {
    let rig = rig();
    let (device, session, user) = rig.plain().await;
    let token = session.access_token.as_str();
    let made = rig
        .authed(&device, "POST", KIT, token, Some(rig.kit_body(user).await))
        .await;
    assert_eq!(made.status, StatusCode::CREATED);
    // The unlock screen and the card read it from one address, far over 10 a minute.
    let peer = SocketAddr::from(([10, 9, 9, 9], 40_000));
    for n in 0..25 {
        let reply = device
            .send(
                "GET",
                KIT,
                Req {
                    access_token: Some(token),
                    peer: Some(peer),
                    ..Req::default()
                },
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "read {n}");
    }
}
