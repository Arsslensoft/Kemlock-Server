//! The admin API under test: the Kemlock API's router over its fakes with the admin router
//! merged in, people who sign in with real OPAQUE and DPoP, and the helpers to make one an admin.
#![allow(dead_code, unused_imports)]

use crate::common::fakes::{FakeEnv, FakeStore};
use crate::common::{App, Client, PASSWORD, Reply, Req, Session, b64, register_and_sign_in, unb64};
use crate::fake_admin::{FakeAdmin, FakeMailer};
use crate::passkey_fakes::{FakePasskeys, ScriptedWebAuthn};
use crate::space_fakes::FakeSpaces;
use crate::sso_fakes::{FakeDns, FakeSsoRepos};
use axum::Router;
use axum::http::StatusCode;
use kemlock_api_admin::{AdminRuntime, admin_router};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::admin::{
    AdminError, FnEnv, MigrationRecord, MigrationRequest, MigrationRunner, MigrationState,
    MigrationStatus, PasskeyStepUp, PushRelayControl,
};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::{Role, SpaceId, UserId};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use time::Duration;

pub(crate) const TOTP_SECRET: [u8; 20] = *b"12345678901234567890";

pub(crate) struct Rig {
    pub(crate) app: App,
    pub(crate) router: Router,
    pub(crate) admin: FakeAdmin,
    pub(crate) spaces: FakeSpaces<FakeStore>,
    pub(crate) sso: FakeSsoRepos,
    pub(crate) dns: FakeDns,
    pub(crate) mail: FakeMailer,
    /// How many times the server was told settings were saved.
    pub(crate) settings_saves: Arc<AtomicU32>,
    /// The passkeys the step-up checks against.
    pub(crate) passkeys: FakePasskeys,
    /// The runner the start route hands the move to.
    pub(crate) migration: FakeMigration,
}

impl Rig {
    pub(crate) fn new() -> Rig {
        Rig::with(true, &[])
    }

    /// `mail`: whether an SMTP server is set up; `env`: variables the settings screen sees.
    pub(crate) fn with(mail: bool, env: &[(&str, &str)]) -> Rig {
        Rig::build(mail, env, None)
    }

    /// A rig whose console can turn Kemlock's push relay on and off through `relay`.
    pub(crate) fn with_push_relay(relay: Arc<dyn PushRelayControl>) -> Rig {
        Rig::build(true, &[], Some(relay))
    }

    fn build(mail: bool, env: &[(&str, &str)], relay: Option<Arc<dyn PushRelayControl>>) -> Rig {
        let app = App::new(true);
        let spaces = FakeSpaces::new(app.store.clone());
        let admin = FakeAdmin::new(app.store.clone(), spaces.clone());
        let sso = FakeSsoRepos::default();
        let dns = FakeDns::default();
        let mail = FakeMailer::new(mail);
        let vars: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let settings_saves = Arc::new(AtomicU32::new(0));
        let saved = settings_saves.clone();
        let passkeys = FakePasskeys::default();
        let migration = FakeMigration {
            admin: admin.clone(),
            crypto: app.crypto.clone(),
            started: Arc::default(),
        };
        let stepper = PasskeyStepUp {
            passkeys: passkeys.clone(),
            webauthn: ScriptedWebAuthn::default(),
            seal: app.crypto.clone(),
            env: app.crypto.clone(),
            keys: (),
        };
        let mut runtime = AdminRuntime::new(
            admin.clone(),
            spaces.clone(),
            sso.clone(),
            dns.clone(),
            mail.clone(),
            FnEnv(move |name: &str| vars.get(name).cloned()),
        )
        .with_passkeys(Arc::new(stepper))
        .with_migration(Arc::new(migration.clone()))
        .with_account_erasure(Arc::new(admin.clone()))
        .on_settings_saved(move || {
            saved.fetch_add(1, Ordering::SeqCst);
        });
        if let Some(relay) = relay {
            runtime = runtime.with_push_relay(relay);
        }
        let router = app
            .router
            .clone()
            .merge(admin_router(app.api.clone(), runtime));
        Rig {
            app,
            router,
            admin,
            spaces,
            sso,
            dns,
            mail,
            settings_saves,
            passkeys,
            migration,
        }
    }

    pub(crate) fn client(&self) -> Client {
        Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        )
    }

    /// An ordinary account, signed in on a device of its own.
    pub(crate) async fn user(&self, email: &str) -> Person {
        let client = self.client();
        let session = register_and_sign_in(&client, email).await;
        let id = UserId::from_str(&session.user_id).expect("a user id");
        self.admin.track_user(id);
        Person {
            client,
            session,
            id,
            email: email.to_owned(),
        }
    }

    /// An account with the admin role and a confirmed authenticator app.
    pub(crate) async fn admin(&self, email: &str) -> Person {
        let person = self.user(email).await;
        self.promote(person.id);
        self.enrol_totp(person.id).await;
        person
    }

    pub(crate) fn promote(&self, id: UserId) {
        let mut user = self.app.store.user(id).expect("the account exists");
        user.role = Role::Admin;
        self.app.store.put_user(user);
    }

    pub(crate) async fn enrol_totp(&self, id: UserId) {
        let sealed = self.app.crypto.seal("totp", &TOTP_SECRET);
        TwoFactorRepo::put(
            &self.app.store,
            &TwoFactor {
                user: id,
                method: TwoFactorMethod::Totp,
                sealed_secret: sealed,
                enabled: true,
                created_at: self.app.clock.now(),
            },
        )
        .await
        .expect("two-step is stored");
    }

    /// A device of the same account: its own DPoP key and its own session.
    pub(crate) async fn second_device(&self, person: &Person) -> Person {
        let client = self.client();
        let reply =
            crate::common::sign_in_reply(&client, &person.email, crate::common::test_device())
                .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        let signed = reply.json();
        // An admin has a second step: finish it with the next code.
        let tokens = if signed["status"] == "two_factor_required" {
            self.next_step();
            let second = client
                .post(
                    "/kem/v1/auth/two-factor",
                    json!({"challenge": signed["challenge"], "method": "totp", "code": self.totp_code()}),
                )
                .await;
            assert_eq!(second.status, StatusCode::OK, "{:?}", second.json());
            second.json()
        } else {
            signed["tokens"].clone()
        };
        let session = Session::from_tokens(&tokens);
        Person {
            client,
            session,
            id: person.id,
            email: person.email.clone(),
        }
    }

    /// The code an authenticator app shows now.
    pub(crate) fn totp_code(&self) -> String {
        let now = u64::try_from(self.app.now()).expect("a positive time");
        kemlock_crypto::totp::code_at(&TOTP_SECRET, now)
    }

    /// Waits for the next 30-second step, so a code is never the one already used.
    pub(crate) fn next_step(&self) {
        self.app.clock.advance(Duration::seconds(30));
    }
}

/// A signed-in device.
pub(crate) struct Person {
    pub(crate) client: Client,
    pub(crate) session: Session,
    pub(crate) id: UserId,
    pub(crate) email: String,
}

impl Person {
    /// A request as this person sends it, with an optional step-up token.
    pub(crate) async fn send(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        step_up: Option<&str>,
    ) -> Reply {
        let headers = step_up
            .map(|t| vec![("step-up-token", t.to_owned())])
            .unwrap_or_default();
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    headers,
                    body,
                    ..Req::default()
                },
            )
            .await
    }

    pub(crate) async fn get(&self, uri: &str) -> Reply {
        self.send("GET", uri, None, None).await
    }

    pub(crate) async fn write(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        token: &str,
    ) -> Reply {
        self.send(method, uri, body, Some(token)).await
    }

    /// A step-up token from a TOTP code.
    pub(crate) async fn step_up(&self, rig: &Rig) -> String {
        rig.next_step();
        let reply = self
            .send(
                "POST",
                "/admin/v1/step-up/totp",
                Some(json!({"code": rig.totp_code()})),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        reply.json()["token"].as_str().expect("a token").to_owned()
    }

    /// A step-up token from a re-run password login.
    pub(crate) async fn step_up_with_password(&self, password: &[u8; 32]) -> Reply {
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(password).expect("client login start");
        let started = self
            .send(
                "POST",
                "/admin/v1/step-up/password/start",
                Some(json!({"request": b64(&request)})),
                None,
            )
            .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.json());
        let started = started.json();
        let response = unb64(started["response"].as_str().expect("response"));
        // A wrong password fails on the client first; the server is sent a message that can't
        // be a finalization, as a client that carried on would.
        let finalization = kemlock_crypto::opaque::client_login_finish(state, password, &response)
            .map_or_else(
                |_| vec![0u8; 64],
                |(finalization, _session_key, _export_key)| finalization,
            );
        self.send(
            "POST",
            "/admin/v1/step-up/password/finish",
            Some(json!({
                "loginState": started["loginState"],
                "finalization": b64(&finalization),
            })),
            None,
        )
        .await
    }
}

/// The problem's `type` slug.
pub(crate) fn slug(reply: &Reply) -> String {
    reply.problem()
}

/// Stands in for the server's import: it records what it was asked and the "running" status the
/// real one records, and a test plays the background job by calling the record itself.
#[derive(Clone)]
pub(crate) struct FakeMigration {
    admin: FakeAdmin,
    crypto: crate::common::TestCrypto,
    /// The moves that were started.
    pub(crate) started: Arc<Mutex<Vec<MigrationRequest>>>,
}

impl FakeMigration {
    /// The record the real job writes its stages and result to.
    pub(crate) fn record(&self) -> MigrationRecord<FakeAdmin, crate::common::TestCrypto> {
        MigrationRecord {
            repo: self.admin.clone(),
            clock: self.crypto.clone(),
        }
    }

    pub(crate) fn requests(&self) -> Vec<MigrationRequest> {
        self.started
            .lock()
            .expect("the lock isn't poisoned")
            .clone()
    }
}

impl MigrationRunner for FakeMigration {
    fn start<'a>(
        &'a self,
        request: MigrationRequest,
    ) -> BoxFuture<'a, Result<MigrationStatus, AdminError>> {
        Box::pin(async move {
            // A source the real runner couldn't even parse.
            if request.from.starts_with("bad:") {
                return Err(AdminError::Invalid(
                    "that isn't a Vaultwarden source".to_owned(),
                ));
            }
            let record = self.record();
            if record.status().await?.state == MigrationState::Running {
                return Err(AdminError::State("a move is already running"));
            }
            self.started
                .lock()
                .expect("the lock isn't poisoned")
                .push(request.clone());
            record.running(request.by, request.from).await
        })
    }
}
